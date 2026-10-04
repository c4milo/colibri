//! What `Endpoint` and the connection's other files call on a server QUIC connection, and no
//! program does (design §8 step 17f): the endpoint starts the connection from a client's first
//! Initial, passes it the datagrams its connection IDs name, sends what it writes, fires its
//! deadlines and frees it once it is over (decision 103, RFC 9000 §5.2). The module's root exports
//! none of these, so `QuicConnection` keeps as methods only the calls a program makes.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const constants = @import("../constants.zig");
const quic_connection = @import("quic_connection.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");
const quic_deadline = @import("quic_deadline.zig");
const quic_coding = @import("quic_coding.zig");
const coding_pool = @import("../coding/coding_pool.zig");

const QuicConnection = quic_connection.QuicConnection;
const Config = quic_connection.Config;
const Start = quic_connection.Start;
const StartError = quic_connection.StartError;
const Sent = quic_connection.Sent;
const PeerAddress = quic_connection.PeerAddress;
const ReceiveStorage = quic_connection.ReceiveStorage;
const Parameters = quic.transport_parameters.Parameters;

/// Has the connection write its QUIC and h3 events into `log`, whose header the caller wrote
/// (decision 102): once, after `start` and before any datagram. h3's events go into the same
/// log as the QUIC connection's, one trace for both (h3-events §1.1).
pub fn attach_log(connection: *QuicConnection, log: *quic.qlog.Log, now_ns: u64) void {
    assert(connection.transport.qlog.log == null and connection.h3.options.qlog == null);
    assert(!connection.started);
    quic.connection_qlog.init(&connection.transport, log, now_ns);
    connection.h3.options.qlog = log;
}

/// Starts the connection a client's first Initial asked for. `receive_pool` holds the client's
/// octets until h3 reads them (decision 61), and no other connection uses it while this one
/// runs. Every draw the handshake makes comes from `random`, and `now_seconds` is the instant
/// the server's tickets are issued at, or 0 for none.
pub fn start(connection: *QuicConnection, config: *const Config, receive_pool: ReceiveStorage, how: Start, random: tls.Random, now_seconds: u64, now_ns: u64) StartError!void {
    assert(receive_pool.capacity > 0 and how.original_destination.len > 0);
    assert((config.codings.len == 0) == (config.encoders == null));
    for (config.codings) |coding| assert(coding_pool.encodes(coding));
    try config.deadlines.validate();
    // Over QUIC a request's content arrives a packet at a time. The bound kept for a TLS record
    // and an h2 DATA frame covers a packet of up to `body_unit_len` octets, and one `Deadlines`
    // then suits a server's TCP and QUIC connections (decision 110 as amended).
    try config.deadlines.validate_units();
    connection.config = config;
    connection.deadlines = config.deadlines;
    connection.clock = .init(now_ns);
    connection.bodies.init();
    connection.sends.init();
    connection.requests.init();
    connection.owed = .{};
    connection.started = false;
    connection.shutting_down = false;
    connection.stopped = false;
    connection.failure_owed = false;
    connection.closed = false;
    connection.last_ns = now_ns;
    connection.peer_resets = 0;
    connection.peer_reset_period_start_ns = now_ns;
    connection.random = random;
    connection.spare_ids_issued = false;
    connection.transport.init(.{
        .role = .server,
        .version = how.version,
        .switch_to = config.switch_to,
        .local_parameters = parameters(config, receive_pool.capacity),
        .now_ns = now_ns,
        .identity = .{
            .local_initial_source = &how.local_id,
            .original_destination = how.original_destination,
            .peer_initial_source = how.peer_source,
            .retry_source = how.retry_source,
        },
        .receive = receive_pool,
        .ecn_reads = config.ecn,
        .ecn_marks = config.ecn,
        .peer_address = how.peer,
    });
    connection.send_scratch = .{};
    connection.h3.init(.{ .role = .server, .grease = how.grease });
    connection.session.start(config.tls, random, now_seconds, how.version);
    // Decision 111: a client that lists version 2 is switched to it (RFC 9368 §2.3).
    connection.session.set_version_chooser(quic.connection_version.chooser(&connection.transport));
    try hand_over_parameters(connection);
    const suite = connection.session.suite();
    const keys_destination = how.retry_source orelse how.original_destination;
    // RFC 9001 §5.2: the Initial keys derive from the client's first Destination Connection ID,
    // and RFC 9000 §17.2.5.2: after a Retry, from the Retry's Source Connection ID.
    suite.vtable.install_initial_keys(suite.context, .server, keys_destination) catch return error.TlsRefused;
}

/// RFC 9001 §8.2: the transport parameters travel in the handshake. `transport.init` wrote the
/// connection IDs into them (RFC 9000 §7.3).
fn hand_over_parameters(connection: *QuicConnection) StartError!void {
    var encoded: [constants.quic_transport_parameters_len_max]u8 = undefined;
    var writer = quic.core.Writer.init(&encoded);
    // RFC 9000 §18: the parameters are encoded before the handshake carries them.
    quic.transport_parameters.write(&writer, &connection.transport.local_parameters, .server) catch return error.TlsRefused;
    // RFC 9001 §8.2: chapulin carries them in its quic_transport_parameters extension.
    connection.session.provider().set_transport_params(writer.written()) catch return error.TlsRefused;
}

/// Takes a datagram whose connection ID names this connection, from `from`, which the suite
/// opens in place.
pub fn take(connection: *QuicConnection, datagram: []u8, ecn: quic.connection_receive.Datagram.Ecn, from: PeerAddress, now_ns: u64) void {
    if (connection.closed) return;
    connection.last_ns = now_ns;
    // Decision 110: a window that ended before `now_ns` is judged before this datagram's
    // acknowledgments count, so they count in the window they arrived in.
    quic_deadline.fire(connection, now_ns);
    const received = quic.connection_datagram.receive(
        &connection.transport,
        connection.session.suite(),
        connection.session.provider(),
        .{ .octets = datagram, .now_ns = now_ns, .ecn = ecn, .from = from },
        &connection.scratch,
    ) catch return fail(connection);
    // Decision 72: the client's address changed and colibri followed it, so it owes
    // PATH_CHALLENGE frames, whose data RFC 9000 §8.2.1 wants unpredictable.
    if (received.migrated) quic.connection_migration.challenge(&connection.transport, challenge_data(connection));
    after_change(connection, now_ns);
}

/// Writes the next datagram the connection owes into `output`, or null when it owes none.
pub fn send(connection: *QuicConnection, output: []u8, now_ns: u64) ?Sent {
    if (connection.closed) return null;
    const sent = quic.connection_send.send(
        &connection.transport,
        connection.session.suite(),
        connection.session.provider(),
        quic_connection_h3.provider(connection),
        &connection.send_scratch,
        output,
        now_ns,
    ) catch {
        fail(connection);
        return null;
    } orelse return null;
    assert(sent.len <= output.len);
    return .{ .octets = output[0..sent.len], .ecn = sent.ecn, .to = sent.to };
}

/// The instant the connection next wants `on_instant` at (design §4.2), or null for none: the
/// sooner of QUIC's timers and the connection's own deadlines (decision 110 as amended).
pub fn deadline_ns(connection: *QuicConnection) ?u64 {
    if (connection.closed) return null;
    const timer_at_ns = timer_ns(connection);
    const own_ns = quic_deadline.soonest(connection) orelse return timer_at_ns;
    return @min(timer_at_ns orelse own_ns, own_ns);
}

/// The instant QUIC's next timer is due at, or null.
fn timer_ns(connection: *QuicConnection) ?u64 {
    const timer = quic.connection_timer.next(&connection.transport) orelse return null;
    return timer.at_ns;
}

/// Fires whichever deadlines `now_ns` has reached: a loss, the idle timeout, the end of the
/// closing period (RFC 9002 §6.2, RFC 9000 §10), and the connection's own (decision 110 as
/// amended).
pub fn on_instant(connection: *QuicConnection, now_ns: u64) void {
    const at_ns = deadline_ns(connection) orelse return;
    if (now_ns < at_ns) return;
    connection.last_ns = now_ns;
    if (timer_ns(connection)) |timer_at_ns| {
        if (now_ns >= timer_at_ns) {
            _ = quic.connection_timer.on_instant(&connection.transport, connection.session.suite(), &connection.scratch.recovery, now_ns) catch {
                return fail(connection);
            };
        }
    }
    quic_deadline.fire(connection, now_ns);
    after_change(connection, now_ns);
}

/// Whether the connection is over: its closing or draining period ran, it timed out, or its
/// transport closed (RFC 9000 §10).
pub fn ended(connection: *const QuicConnection) bool {
    return connection.closed or connection.transport.termination.state == .closed;
}

/// Whether a datagram whose first packet names `dcid` belongs to this connection (RFC 9000
/// §5.2).
pub fn addressed_by(connection: *const QuicConnection, dcid: []const u8) bool {
    return !connection.closed and connection.transport.addressed_by(dcid);
}

/// The connection is over, so nothing more is read or written, and the session's secrets are
/// wiped. A second call changes nothing.
pub fn transport_closed(connection: *QuicConnection) void {
    if (connection.closed) return;
    connection.closed = true;
    connection.stopped = true;
    connection.owed.clear();
    quic_coding.give_back_all(connection);
    connection.session.close();
}

/// What a datagram or a deadline may have changed: the handshake completed, or the connection
/// stopped being active.
fn after_change(connection: *QuicConnection, now_ns: u64) void {
    if (!connection.started) start_h3(connection, now_ns);
    issue_spare_ids(connection);
    // A stream that closed frees its record before anything is sent, so the credit for a new
    // stream QUIC grants for it finds a record free (RFC 9000 §4.6).
    quic_connection_h3.settle(connection);
    // RFC 9000 §10: once the connection stops being active, no request is read or answered.
    // The peer closed it, or it went idle, and neither is a failure this side found: the
    // endpoint's `ended` reports it once its closing or draining period is over.
    if (connection.transport.termination.state != .active and !connection.stopped) stop(connection);
    quic_deadline.observe(connection, now_ns);
}

/// Issues spare connection IDs once the handshake is confirmed, as many as the peer's
/// active_connection_id_limit allows beside the one in use. RFC 9000 §5.1.1: an endpoint
/// "SHOULD ensure that its peer has a sufficient number of available and unused connection
/// IDs", which a client that moves to a new path needs (§9.5).
fn issue_spare_ids(connection: *QuicConnection) void {
    if (connection.spare_ids_issued or !connection.transport.handshake_confirmed) return;
    const peer = connection.transport.peer_parameters orelse return;
    connection.spare_ids_issued = true;
    const limit = @min(peer.active_connection_id_limit, quic.constants.connection_ids_max);
    // Bounded by `connection_ids_max`, a named limit.
    for (1..limit) |_| {
        var id: [constants.quic_id_len]u8 = undefined;
        var token: [quic.constants.stateless_reset_token_len]u8 = undefined;
        // RFC 9000 §5.1: an ID unlinkable to the others; §10.3: a token no one can guess.
        connection.random.bytes(&id);
        connection.random.bytes(&token);
        _ = quic.connection_id_frames.issue(&connection.transport, &id, &token) catch return;
    }
}

fn challenge_data(connection: *QuicConnection) quic.connection_migration.ChallengeData {
    var data: quic.connection_migration.ChallengeData = undefined;
    connection.random.bytes(std.mem.asBytes(&data));
    return data;
}

/// Starts h3 once the handshake completed (RFC 9114 §6.2.1). The server's ALPN list names "h3"
/// alone, so a completed handshake selected it (RFC 9001 §8.1).
fn start_h3(connection: *QuicConnection, now_ns: u64) void {
    if (!connection.transport.handshake_complete) return;
    connection.h3.start(&connection.transport, now_ns) catch return fail(connection);
    connection.started = true;
}

/// Stops the connection: no request is read or answered from here on, and no stream reads the
/// caller's octets again, because a connection that is not active sends none (RFC 9000
/// §10.2.1).
pub fn stop(connection: *QuicConnection) void {
    connection.stopped = true;
    connection.owed.clear();
    connection.bodies.init();
    connection.sends.init();
    quic_coding.give_back_all(connection);
    for (&connection.requests.records) |*record| record.in_use = false;
}

/// Ends the connection on a failure: it stops, QUIC's CONNECTION_CLOSE still goes out, and
/// the next `receive` fails once.
pub fn fail(connection: *QuicConnection) void {
    if (connection.stopped) return;
    stop(connection);
    connection.failure_owed = true;
    const transport = &connection.transport;
    // RFC 9000 §10.2: an active connection that ends owes its CONNECTION_CLOSE, unless h3 or
    // QUIC already owes one. RFC 9000 §20.1: with no more specific code, INTERNAL_ERROR.
    if (transport.termination.state == .active and !quic.connection_close.owes(transport)) {
        quic.connection_close.owe(transport, quic.connection_close.transport(quic.error_code.internal_error, null));
    }
}

/// What the server grants the client (RFC 9000 §18.2): its request streams, each with room for a
/// request's content, and h3's unidirectional streams (RFC 9114 §6.2).
fn parameters(config: *const Config, capacity: u64) Parameters {
    var held = Parameters.initial();
    // RFC 9000 §4.1: flow control keeps a sender within "a receiver's buffer capacity", and the
    // pool is all the server holds (decision 61), so no window grants more than it.
    held.initial_max_data = capacity;
    held.initial_max_stream_data_bidi_remote = @min(constants.quic_stream_window, capacity);
    held.initial_max_stream_data_uni = @min(constants.quic_stream_window, capacity);
    held.initial_max_streams_bidi = constants.quic_requests_max;
    held.initial_max_streams_uni = h3.constants.uni_streams_max;
    held.max_idle_timeout_ms = config.idle_timeout_ms;
    return held;
}
