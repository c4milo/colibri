//! One connection of the client over QUIC (decision 100, design §8 step 17d): h3 (RFC 9114) over
//! `quic`, with the TLS handshake run through `tls.quic.Client`, carrying the same exchanges and
//! reporting the same events as the TCP `Connection`.
//!
//! The caller opens a UDP flow to the server, passes each datagram it reads to `receive`, sends
//! each datagram `send` writes, and calls `on_instant` once the instant `deadline_ns` names has
//! come. colibri makes no system call and reads no clock (non-negotiable 3). It does the duties of
//! a QUIC caller itself (decisions 57, 61 and 62): it hands the provider the transport parameters,
//! derives the Initial keys, places the receive pool, and supplies each request stream's octets,
//! the HEADERS frame and DATA frame header it keeps (decision 79), then the exchange's content.
//! The connection IDs and h3's grease value are the caller's (invariant 5).
//!
//! The caller loops over `receive` as it does for the TCP connection, until it returns nothing
//! consumed and no event; a datagram is consumed whole. After each `send` and `on_instant` it loops
//! again with no datagram, which reports what they changed. An exchange's `finished` event waits
//! until its stream reads nothing more of the exchange (RFC 9000 §3.1), so the caller may reuse the
//! exchange's memory once the event arrives.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const constants = @import("constants.zig");
const event = @import("event.zig");
const slots_module = @import("slots.zig");
const owed_module = @import("owed.zig");
const connection_module = @import("connection.zig");
const quic_h3 = @import("quic_connection_h3.zig");

pub const Id = event.Id;
pub const Event = event.Event;
pub const Received = event.Received;
pub const HttpExchange = event.HttpExchange;
pub const RequestError = connection_module.RequestError;
pub const PeerAddress = quic.peer_address.PeerAddress;
const Parameters = quic.transport_parameters.Parameters;

/// What every QUIC connection to one origin borrows. The caller keeps it alive while any
/// connection holds it.
pub const Config = struct {
    /// The TLS configuration, whose ALPN list names "h3" (RFC 9114 §3.1).
    tls: *const tls.quic.ClientConfig,
    /// The authority every request names in `:authority` (RFC 9114 §4.3.1).
    authority: []const u8,
    /// The server's address as the caller names it (decision 72), which each datagram `send`
    /// writes goes to. Empty when the caller names none, and every datagram takes the one path.
    server_address: PeerAddress = .{},
    /// Decision 68: whether the caller reads each datagram's ECN codepoint and sets the one `send`
    /// names.
    ecn: bool = false,
    /// The idle timeout the client advertises (RFC 9000 §10.1), in milliseconds.
    idle_timeout_ms: u64 = constants.quic_idle_timeout_ms_default,
};

/// The unpredictable values one connection starts from, which the caller draws (invariant 5).
pub const Start = struct {
    /// The client's Source Connection ID, and the Destination Connection ID of its first Initial,
    /// which the Initial keys derive from (RFC 9000 §7.2, RFC 9001 §5.2).
    source_id: [constants.quic_id_len]u8,
    original_destination_id: [constants.quic_id_len]u8,
    /// The value h3's reserved setting and error codes are drawn from (RFC 9114 §7.2.4.1, §8.1).
    grease: u64,
};

pub const StartError = error{
    /// chapulin refused the TLS configuration or the ticket, or would not take the transport
    /// parameters or the Initial keys.
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
    session: tls.quic.Client,
    send_scratch: quic.connection_send.DefaultScratch,
    scratch: quic.connection_datagram.Scratch,
    pool: quic.stream.stream_incoming.DefaultPool,
    h3: h3.Connection,
    /// Where a request's field section is built, and where h3 copies a response's content.
    section: h3.http.FieldSection,
    body: [constants.quic_read_len]u8,
    /// Each slot's request stream frames, at the slot's index.
    streams: [constants.exchanges_max]quic_h3.RequestStream,
    slots: slots_module.Slots,
    owed: owed_module.Owed,
    start_values: Start,
    /// Whether h3 runs: the handshake completed and ALPN selected h3.
    started: bool,
    /// The connection takes no new request.
    draining: bool,
    /// The connection failed or is ending, so it writes no request and ends every exchange.
    stopped: bool,
    /// The caller's transport closed, so nothing more is read or written.
    closed: bool,
    /// The connection ended on a failure, or its transport closed before it was over, rather
    /// than after its last exchange.
    failed: bool,
    /// The latest ticket the server issued, until `take_ticket` hands it over.
    ticket: ?tls.Ticket,

    /// Prepares a connection whose first datagram `send` writes. Every draw the handshake makes
    /// comes from `random`, `now_seconds` is the instant a Web PKI chain is judged at, `now_ns` the
    /// instant the connection begins, and `resumption` offers a ticket an earlier one took.
    pub fn init(connection: *QuicConnection, config: *const Config, start: Start, random: tls.Random, now_seconds: u64, now_ns: u64, resumption: ?tls.Resumption) StartError!void {
        assert(config.authority.len > 0);
        connection.config = config;
        connection.start_values = start;
        connection.slots.init();
        connection.owed = .{};
        connection.started = false;
        connection.draining = false;
        connection.stopped = false;
        connection.closed = false;
        connection.failed = false;
        connection.ticket = null;
        connection.transport.init(.{
            .role = .client,
            .local_parameters = parameters(config),
            .now_ns = now_ns,
            .identity = .{ .local_initial_source = &connection.start_values.source_id, .original_destination = &connection.start_values.original_destination_id },
            .receive = connection.pool.storage(),
            .ecn_reads = config.ecn,
            .ecn_marks = config.ecn,
            .peer_address = config.server_address,
        });
        connection.send_scratch = .{};
        connection.h3.init(.{ .role = .client, .grease = start.grease });
        // RFC 9846 §4.7.1: chapulin refuses values it cannot run and a ticket too old.
        connection.session.start(config.tls, random, now_seconds, resumption) catch return error.TlsRefused;
        try connection.hand_over_parameters();
        const suite = connection.session.suite();
        // RFC 9001 §5.2: the Initial keys derive from the client's first Destination Connection ID.
        suite.vtable.install_initial_keys(suite.context, .client, &connection.start_values.original_destination_id) catch
            return error.TlsRefused;
    }

    /// RFC 9001 §8.2: the transport parameters travel in the handshake. `transport.init` wrote the
    /// connection IDs into them (RFC 9000 §7.3).
    fn hand_over_parameters(connection: *QuicConnection) StartError!void {
        var body: [constants.transport_parameters_len_max]u8 = undefined;
        var writer = quic.core.Writer.init(&body);
        // RFC 9000 §18: the parameters are encoded before the handshake carries them.
        quic.transport_parameters.write(&writer, &connection.transport.local_parameters, .client) catch return error.TlsRefused;
        // RFC 9001 §8.2: chapulin carries them in its quic_transport_parameters extension.
        connection.session.provider().set_transport_params(writer.written()) catch return error.TlsRefused;
    }

    /// Takes `exchange`, which goes out on a stream of its own once h3 runs and the server's
    /// stream limit allows (RFC 9000 §4.6), and returns its id.
    pub fn request(connection: *QuicConnection, exchange: *HttpExchange) RequestError!Id {
        // RFC 9000 §10 and RFC 9114 §8: a connection that closed or failed carries no request.
        if (connection.closed or connection.stopped) return error.ConnectionClosed;
        // RFC 9114 §5.2: a connection that heard GOAWAY, or is shutting down, opens no request.
        if (connection.draining) return error.Draining;
        try connection_module.check_request(exchange);
        exchange.clear();
        return connection.slots.take(exchange) orelse error.Full;
    }

    /// Ends exchange `id` and reports nothing for it. Its stream is reset with
    /// H3_REQUEST_CANCELLED (RFC 9114 §4.1.1), after which nothing reads the exchange, so its
    /// memory is the caller's again.
    pub fn cancel(connection: *QuicConnection, id: Id) void {
        const slot = connection.slots.of_id(id) orelse return;
        // RFC 9114 §4.1.1: every direction still open is reset. The stream is live while it holds
        // the exchange's octets, which QUIC reads until they are acknowledged (RFC 9000 §3.1),
        // after the response ended too.
        if (slot.holds_octets) quic_h3.cancel_stream(connection, slot.stream_id);
        slots_module.release(slot);
    }

    /// Reports what the connection owes the caller, then takes `datagram`, which the server sent
    /// and which the suite opens in place, and reads every event h3 has for the exchanges.
    pub fn receive(connection: *QuicConnection, datagram: []u8, ecn: quic.connection_receive.Datagram.Ecn, from: PeerAddress, now_ns: u64) Received {
        if (connection.owed_event()) |owed| return .{ .consumed = 0, .event = owed };
        if (datagram.len == 0 or connection.closed) return .{ .consumed = 0, .event = connection.owed_event() };
        const received = quic.connection_datagram.receive(
            &connection.transport,
            connection.session.suite(),
            connection.session.provider(),
            .{ .octets = datagram, .now_ns = now_ns, .ecn = ecn, .from = from },
            &connection.scratch,
        ) catch {
            // RFC 9000 §10.2: the connection closes, and QUIC owes its CONNECTION_CLOSE.
            connection.fail();
            return .{ .consumed = datagram.len, .event = connection.owed_event() };
        };
        _ = received;
        connection.after_change(now_ns);
        return .{ .consumed = datagram.len, .event = connection.owed_event() };
    }

    /// Writes the requests waiting, then the next datagram the connection owes into `output`, or
    /// null when it owes none.
    pub fn send(connection: *QuicConnection, output: []u8, now_ns: u64) ?Sent {
        if (connection.closed) return null;
        if (connection.started and !connection.stopped) quic_h3.write_requests(connection, now_ns);
        const sent = quic.connection_send.send(
            &connection.transport,
            connection.session.suite(),
            connection.session.provider(),
            quic_h3.provider(connection),
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
        _ = quic.connection_timer.on_instant(&connection.transport, connection.session.suite(), &connection.scratch.recovery, now_ns) catch {
            connection.fail();
            return;
        };
        connection.after_change(now_ns);
    }

    /// Ends the connection once the exchanges it holds have finished: no new request is taken, and
    /// QUIC then closes with H3_NO_ERROR (RFC 9114 §5.2, RFC 9000 §10.2).
    pub fn shutdown(connection: *QuicConnection) void {
        connection.start_draining();
    }

    /// Whether the caller closes the flow now: the connection is over, its CONNECTION_CLOSE is out
    /// and its closing period ran (RFC 9000 §10.2), or its transport already closed.
    pub fn should_close(connection: *const QuicConnection) bool {
        if (!connection.owed.closed_reported) return false;
        return connection.closed or connection.transport.termination.state == .closed;
    }

    /// The caller's flow closed or failed. Every exchange still held ends, nothing more is read or
    /// written, and the session's secrets are wiped. A second call changes nothing.
    pub fn transport_closed(connection: *QuicConnection) void {
        if (connection.closed) return;
        if (!connection.owed.closed_reported) connection.failed = true;
        connection.closed = true;
        connection.stopped = true;
        for (&connection.slots.slots) |*slot| slot.holds_octets = false;
        connection.slots.end_all(.refused, .closed);
        connection.session.close();
        connection.wipe_ticket();
    }

    /// h3 once the handshake completed with it, or null.
    pub fn protocol(connection: *const QuicConnection) ?event.Protocol {
        return if (connection.started) .h3 else null;
    }

    /// The resumption ticket the `ticket` event announced, which the call hands over and clears.
    pub fn take_ticket(connection: *QuicConnection) ?tls.Ticket {
        const ticket = connection.ticket orelse return null;
        connection.wipe_ticket();
        return ticket;
    }

    fn wipe_ticket(connection: *QuicConnection) void {
        if (connection.ticket) |*held| held.wipe();
        connection.ticket = null;
        connection.owed.ticket = false;
    }

    /// What a datagram or a deadline at `now_ns` may have changed: the handshake completed, a
    /// ticket arrived, h3 has events, a stream closed, or the connection ended.
    fn after_change(connection: *QuicConnection, now_ns: u64) void {
        connection.collect_ticket();
        if (!connection.started) connection.start_h3(now_ns);
        if (connection.started and !connection.stopped) quic_h3.read_events(connection, now_ns);
        quic_h3.release_closed(connection);
        // RFC 9000 §10: once the connection stops being active, nothing more comes on its streams.
        if (connection.transport.termination.state != .active and !connection.stopped) connection.fail();
    }

    /// Starts h3 once the handshake completed with ALPN's "h3" (RFC 9114 §3.1), and says which
    /// version the connection speaks. A handshake that chose another protocol ends the connection.
    fn start_h3(connection: *QuicConnection, now_ns: u64) void {
        if (!connection.transport.handshake_complete) return;
        const selected = connection.session.provider().negotiated_alpn() orelse "";
        // RFC 9114 §3.1: an h3 connection is one whose handshake selected the "h3" token.
        if (!std.mem.eql(u8, selected, h3_alpn)) {
            connection.close_quic(h3.constants.error_version_fallback);
            connection.fail();
            return;
        }
        connection.h3.start(&connection.transport, now_ns) catch {
            connection.fail();
            return;
        };
        connection.started = true;
        connection.owed.connected = true;
    }

    fn collect_ticket(connection: *QuicConnection) void {
        const issued = connection.session.take_ticket() orelse return;
        connection.wipe_ticket();
        connection.ticket = issued;
        connection.owed.ticket = true;
    }

    /// Takes no new request from here on, and owes the caller the `draining` event.
    pub fn start_draining(connection: *QuicConnection) void {
        if (connection.draining) return;
        connection.draining = true;
        connection.owed.draining = true;
    }

    /// Ends the connection on a failure: every exchange it holds ends, and what QUIC owes, such as
    /// its CONNECTION_CLOSE, still goes out.
    pub fn fail(connection: *QuicConnection) void {
        connection.stopped = true;
        connection.failed = true;
        const transport = &connection.transport;
        // RFC 9000 §10.2: an active connection that ends owes its CONNECTION_CLOSE, unless h3 or
        // QUIC already owes one. The loss timer's refusals owe none, and RFC 9000 §20.1 closes
        // them with INTERNAL_ERROR.
        if (transport.termination.state == .active and !quic.connection_close.owes(transport)) {
            quic.connection_close.owe(transport, quic.connection_close.transport(quic.error_code.internal_error, null));
        }
        // RFC 9000 §10.2.1: a connection that closes sends only its CONNECTION_CLOSE from here on,
        // so no stream reads an exchange's octets again.
        for (&connection.slots.slots) |*slot| slot.holds_octets = false;
        connection.slots.end_all(.refused, .closed);
        assert(connection.slots.idle());
    }

    /// Owes the server a CONNECTION_CLOSE carrying h3's `code` (RFC 9000 §10.2, RFC 9114 §8).
    pub fn close_quic(connection: *QuicConnection, code: u64) void {
        quic.connection_close.owe(&connection.transport, .{
            .layer = .application,
            .error_code = code,
            // RFC 9000 §19.19: only a transport close carries the Frame Type field.
            .frame_type = null,
            .reason = "",
        });
    }

    fn owed_event(connection: *QuicConnection) ?Event {
        return connection.owed.next(&connection.slots, connection.protocol(), connection.over());
    }

    /// Whether the connection carries nothing more and every exchange it held has finished.
    fn over(connection: *QuicConnection) bool {
        if (!connection.slots.idle() or connection.slots.count(.ended) > 0) return false;
        if (connection.closed or connection.stopped) return true;
        if (!connection.draining or !connection.started) return false;
        connection.finish_draining();
        return true;
    }

    /// The last exchange of a draining connection ended, so QUIC closes with H3_NO_ERROR. RFC
    /// 9114 §5.2: once "all accepted requests ... have been processed", an endpoint "MAY initiate
    /// an immediate closure", and "SHOULD use the H3_NO_ERROR error code". A client's GOAWAY would
    /// limit only server push, which colibri never allows, so none goes out.
    fn finish_draining(connection: *QuicConnection) void {
        assert(connection.draining and connection.slots.idle());
        if (connection.transport.termination.state == .active) connection.close_quic(connection.h3.no_error_code());
        connection.stopped = true;
    }
};

/// RFC 9114 §3.1: the ALPN token of h3.
const h3_alpn = "h3";

/// What the client grants the server (RFC 9000 §18.2): its receive pool for the responses on the
/// streams it opens, and h3's unidirectional streams (RFC 9114 §6.2).
fn parameters(config: *const Config) Parameters {
    var held = Parameters.initial();
    held.initial_max_data = quic.constants.receive_pool_len_default;
    held.initial_max_stream_data_bidi_local = quic.constants.receive_pool_len_default;
    held.initial_max_stream_data_uni = constants.quic_stream_window;
    held.initial_max_streams_uni = h3.constants.uni_streams_max;
    held.max_idle_timeout_ms = config.idle_timeout_ms;
    return held;
}
