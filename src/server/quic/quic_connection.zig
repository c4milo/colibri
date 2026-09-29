//! One connection of the server over QUIC (decision 103, design §8 step 17b): h3 (RFC 9114) over
//! `quic`, with the TLS handshake run through `tls.quic.Server`, reporting the same events and
//! answering with the same calls as the TCP `Connection`. `Endpoint` owns each one: it starts it
//! from a client's first Initial, passes it the datagrams its connection IDs name, and sends what
//! it writes (RFC 9000 §5.2).
//!
//! The caller loops over `receive`, as it does for a TCP connection, until it returns no event,
//! after each datagram the endpoint passed. It answers each request by its id, the stream's, with
//! `respond`, `write_body` and `write_trailers`. `write_body` copies nothing: QUIC reads the
//! caller's octets in place as often as it sends them, so they stay the caller's until the request
//! is `done`, once the peer has acknowledged every octet of the response (RFC 9000 §3.1), or
//! `cancelled` (decision 103). The frames around them are the connection's (decision 79).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("../connection/connection.zig");
const quic_request = @import("quic_request.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");
const quic_coding = @import("quic_coding.zig");
const coding_pool = @import("../coding/coding_pool.zig");
const http = @import("http");

pub const Id = event.Id;
pub const Received = event.Received;
pub const Field = connection_module.Field;
pub const Error = connection_module.Error;
pub const SendError = connection_module.SendError;
pub const PeerAddress = quic.peer_address.PeerAddress;
/// Where a QUIC connection's received octets wait until h3 reads them (decision 61): the storage
/// of a `quic.stream.stream_incoming.Pool` the caller places.
pub const ReceiveStorage = quic.stream.stream_incoming.Storage;
const Parameters = quic.transport_parameters.Parameters;

/// What every QUIC connection of an endpoint borrows. The caller keeps it alive while any
/// connection holds it.
pub const Config = struct {
    /// The TLS configuration, whose ALPN list names "h3" (RFC 9114 §3.1).
    tls: *const tls.quic.ServerConfig,
    /// Decision 68: whether the caller reads each datagram's ECN codepoint and sets the one `send`
    /// names.
    ecn: bool = false,
    /// The idle timeout the server advertises (RFC 9000 §10.1), in milliseconds.
    idle_timeout_ms: u64 = constants.quic_idle_timeout_ms_default,
    /// The content codings the server applies to a response the caller marks `codable`, in its
    /// order of preference, and the pool their encoders come from, which connections may share
    /// (decision 101). Both or neither.
    codings: []const http.content_coding.Coding = &.{},
    encoders: ?coding_pool.Encoders = null,
};

/// What a connection starts from, which the endpoint read off the client's first Initial or drew
/// from its caller's source (invariant 5).
pub const Start = struct {
    /// The connection ID the server chose (RFC 9000 §7.2).
    local_id: [constants.quic_id_len]u8,
    /// The client's first Destination and Source Connection IDs (RFC 9000 §7.3), and a Retry's
    /// Source Connection ID when the Initial returned a Retry token (RFC 9000 §17.2.5.1).
    original_destination: []const u8,
    peer_source: []const u8,
    retry_source: ?[]const u8 = null,
    /// The value h3's reserved setting and error codes are drawn from (RFC 9114 §7.2.4.1, §8.1).
    grease: u64,
    /// Where the client sent from, which the connection's datagrams go to (decision 72).
    peer: PeerAddress,
};

pub const StartError = error{
    /// chapulin would not take the transport parameters or the Initial keys.
    TlsRefused,
};

/// A datagram `send` wrote, the ECN codepoint for its IP header (decision 68), and the address it
/// goes to (decision 72).
pub const Sent = struct {
    octets: []const u8,
    ecn: quic.connection_send.Ecn,
    to: PeerAddress,
};

pub const QuicConnection = struct {
    config: *const Config,
    transport: quic.Connection,
    session: tls.quic.Server,
    send_scratch: quic.connection_send.DefaultScratch,
    scratch: quic.connection_datagram.Scratch,
    h3: h3.Connection,
    /// Where a response's field section is built, and where h3 copies a request's content.
    section: h3.http.FieldSection,
    body: [constants.quic_read_len]u8,
    requests: quic_request.Requests,
    owed: quic_request.Owed,
    /// Whether h3 runs: the handshake completed.
    started: bool,
    /// The caller asked the connection to end once its requests are answered.
    shutting_down: bool,
    /// The connection failed or is ending, so it reads no request, and the next `receive` says
    /// so once.
    stopped: bool,
    failure_owed: bool,
    /// The caller's transport is gone, so nothing more is read or written.
    closed: bool,
    /// The latest instant a call passed, which the qlog events of the writes that take none carry
    /// (decision 102).
    last_ns: u64,
    /// The caller's source, which the connection IDs it issues, their reset tokens and each
    /// PATH_CHALLENGE's data are drawn from (invariant 5).
    random: tls.Random,
    /// Whether the spare connection IDs went out (`issue_spare_ids`).
    spare_ids_issued: bool,

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
        connection.config = config;
        connection.requests.init();
        connection.owed = .{};
        connection.started = false;
        connection.shutting_down = false;
        connection.stopped = false;
        connection.failure_owed = false;
        connection.closed = false;
        connection.last_ns = now_ns;
        connection.random = random;
        connection.spare_ids_issued = false;
        connection.transport.init(.{
            .role = .server,
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
        connection.session.start(config.tls, random, now_seconds);
        try connection.hand_over_parameters();
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

    /// Reports the next event: a request's head, its content, its trailer section, its
    /// cancellation, or that its response is done. `consumed` is always 0: the endpoint passed the
    /// datagrams already. Every slice points into storage the connection holds until the next call.
    pub fn receive(connection: *QuicConnection, now_ns: u64) Error!Received {
        connection.last_ns = now_ns;
        if (connection.failure_owed) {
            connection.failure_owed = false;
            // RFC 9000 §10.2: a connection that failed reads nothing more from its peer.
            return error.ConnectionFailed;
        }
        quic_connection_h3.settle(connection);
        if (connection.owed.take()) |owed| return .{ .consumed = 0, .event = owed };
        if (!connection.started or connection.stopped) return .{ .consumed = 0, .event = null };
        return .{ .consumed = 0, .event = try quic_connection_h3.read_event(connection, now_ns) };
    }

    /// Writes the head of the response to request `id`: an interim one (1xx) or the final one.
    /// With `end`, the final response carries no content.
    pub fn respond(connection: *QuicConnection, id: Id, response: event.Response) SendError!void {
        return quic_connection_h3.respond(connection, id, response);
    }

    /// Takes `content.octets` whole as the next content of the response to request `id`, and ends
    /// the content with `end`. Nothing is copied: the octets stay the caller's until the request
    /// is `done` or `cancelled`. A coded response instead takes as many octets as its encoder's
    /// ring has room for, and returns them, coded, to the caller at once (decision 101).
    /// `error.Blocked` says the response holds as many runs, or its ring as many octets, as it can
    /// until the peer acknowledges some: `receive`, then call again.
    pub fn write_body(connection: *QuicConnection, id: Id, content: event.Content) SendError!usize {
        return quic_connection_h3.write_body(connection, id, content);
    }

    /// Ends the response to request `id` with a trailer section (RFC 9110 §6.5).
    pub fn write_trailers(connection: *QuicConnection, id: Id, fields: []const Field) SendError!void {
        return quic_connection_h3.write_trailers(connection, id, fields);
    }

    /// Ends request `id` before its response is whole: its stream is reset with
    /// H3_REQUEST_CANCELLED (RFC 9114 §4.1.1), after which nothing reads the caller's octets, and
    /// nothing more is reported of it.
    pub fn cancel(connection: *QuicConnection, id: Id) void {
        quic_connection_h3.cancel(connection, id);
    }

    /// Ends the connection once the requests it holds are answered: a GOAWAY refuses every later
    /// request (RFC 9114 §5.2), and QUIC closes with H3_NO_ERROR once the last is done.
    pub fn shutdown(connection: *QuicConnection, now_ns: u64) void {
        connection.last_ns = now_ns;
        connection.shutting_down = true;
        quic_connection_h3.shut_down(connection, now_ns);
    }

    /// h3 once the handshake completed, or null.
    pub fn protocol(connection: *const QuicConnection) ?event.Protocol {
        return if (connection.started) .h3 else null;
    }

    /// The server_name the client sent (RFC 9846 §9.2), or null.
    pub fn server_name(connection: *const QuicConnection) ?[]const u8 {
        return connection.session.sni();
    }

    /// The endpoint passes a datagram whose connection ID names this connection, from `from`,
    /// which the suite opens in place.
    pub fn take(connection: *QuicConnection, datagram: []u8, ecn: quic.connection_receive.Datagram.Ecn, from: PeerAddress, now_ns: u64) void {
        if (connection.closed) return;
        connection.last_ns = now_ns;
        const received = quic.connection_datagram.receive(
            &connection.transport,
            connection.session.suite(),
            connection.session.provider(),
            .{ .octets = datagram, .now_ns = now_ns, .ecn = ecn, .from = from },
            &connection.scratch,
        ) catch return connection.fail();
        // Decision 72: the client's address changed and colibri followed it, so it owes
        // PATH_CHALLENGE frames, whose data RFC 9000 §8.2.1 wants unpredictable.
        if (received.migrated) quic.connection_migration.challenge(&connection.transport, connection.challenge_data());
        connection.after_change(now_ns);
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
            connection.fail();
            return null;
        } orelse return null;
        assert(sent.len <= output.len);
        return .{ .octets = output[0..sent.len], .ecn = sent.ecn, .to = sent.to };
    }

    /// The instant the connection next wants `on_instant` at (design §4.2), or null for none.
    pub fn deadline_ns(connection: *QuicConnection) ?u64 {
        if (connection.closed) return null;
        const deadline = quic.connection_timer.next(&connection.transport) orelse return null;
        return deadline.at_ns;
    }

    /// Fires whichever deadlines `now_ns` has reached: a loss, the idle timeout, the end of the
    /// closing period (RFC 9002 §6.2, RFC 9000 §10).
    pub fn on_instant(connection: *QuicConnection, now_ns: u64) void {
        const at_ns = connection.deadline_ns() orelse return;
        if (now_ns < at_ns) return;
        connection.last_ns = now_ns;
        _ = quic.connection_timer.on_instant(&connection.transport, connection.session.suite(), &connection.scratch.recovery, now_ns) catch {
            return connection.fail();
        };
        connection.after_change(now_ns);
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
        if (!connection.started) connection.start_h3(now_ns);
        connection.issue_spare_ids();
        // A stream that closed frees its record before anything is sent, so the credit for a new
        // stream QUIC grants for it finds a record free (RFC 9000 §4.6).
        quic_connection_h3.settle(connection);
        // RFC 9000 §10: once the connection stops being active, no request is read or answered.
        // The peer closed it, or it went idle, and neither is a failure this side found: the
        // endpoint's `ended` reports it once its closing or draining period is over.
        if (connection.transport.termination.state != .active and !connection.stopped) connection.stop();
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
        connection.h3.start(&connection.transport, now_ns) catch return connection.fail();
        connection.started = true;
    }

    /// Stops the connection: no request is read or answered from here on, and no stream reads the
    /// caller's octets again, because a connection that is not active sends none (RFC 9000
    /// §10.2.1).
    fn stop(connection: *QuicConnection) void {
        connection.stopped = true;
        connection.owed.clear();
        quic_coding.give_back_all(connection);
        for (&connection.requests.records) |*record| record.in_use = false;
    }

    /// Ends the connection on a failure: it stops, QUIC's CONNECTION_CLOSE still goes out, and
    /// the next `receive` fails once.
    pub fn fail(connection: *QuicConnection) void {
        if (connection.stopped) return;
        connection.stop();
        connection.failure_owed = true;
        const transport = &connection.transport;
        // RFC 9000 §10.2: an active connection that ends owes its CONNECTION_CLOSE, unless h3 or
        // QUIC already owes one. RFC 9000 §20.1: with no more specific code, INTERNAL_ERROR.
        if (transport.termination.state == .active and !quic.connection_close.owes(transport)) {
            quic.connection_close.owe(transport, quic.connection_close.transport(quic.error_code.internal_error, null));
        }
    }
};

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
