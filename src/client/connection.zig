//! One connection of the client over TCP (decision 100, design §8 step 17c). The caller places an
//! exchange for each request and hands it to `request`, which returns its id. `send` writes the
//! requests as the protocol, the room and the peer allow, and the octets the caller read go in
//! through `receive`, which returns at most one event a call. Every exchange ends in one outcome,
//! reported by its `finished` event, in h11 and h2 alike.
//!
//! Over TLS, `receive` runs the handshake through `tls.record.Client`, and the protocol ALPN
//! selected serves the connection: h2 for "h2" (RFC 9113 §3.2), and h11 for "http/1.1" or for no
//! selection (decision 88). In cleartext, `Config.cleartext` names the protocol: h11, or h2 with
//! prior knowledge (RFC 9113 §3.3).
//!
//! The caller loops over `receive` until it returns nothing consumed and no event, calls `send`
//! whenever the transport can take octets, and closes the transport once `should_close` says so.
//! After each `send` it loops over `receive` again, even with no new octets: while the output was
//! full, h2 read no frame past the replies it owed (RFC 9113 §6.5.3), and those frames are read
//! then. A connection that fails reports it as its exchanges' outcomes and a `closed` event. The
//! caller owns the struct and every exchange, and colibri allocates nothing (decision 35).
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const h2 = @import("h2");
const tls = @import("tls");
const constants = @import("constants.zig");
const event = @import("event.zig");
const slots_module = @import("slots.zig");
const connection_h11 = @import("connection_h11.zig");
const connection_h2 = @import("connection_h2.zig");
const connection_tls = @import("connection_tls.zig");

pub const Id = event.Id;
pub const Protocol = event.Protocol;
pub const Event = event.Event;
pub const Received = event.Received;
pub const Exchange = event.Exchange;
pub const Field = event.Field;
const Slot = slots_module.Slot;

/// What every connection to one origin borrows. The caller keeps it alive while any connection
/// holds it.
pub const Config = struct {
    /// The TLS configuration, or null for cleartext. Its ALPN list names what the client offers,
    /// `h2` and `http/1.1` in the order it prefers them (RFC 7301 §3.1).
    tls: ?*const tls.record.ClientConfig = null,
    /// The protocol a cleartext connection speaks: h11, or h2 with prior knowledge (RFC 9113
    /// §3.3). Over TLS, ALPN chooses (decision 88).
    cleartext: Protocol = .h11,
    /// The authority every request names: `:authority` in h2 (RFC 9113 §8.3.1) and Host in h11
    /// (RFC 9112 §3.2).
    authority: []const u8,
};

pub const StartError = error{
    /// chapulin refused the TLS configuration or the ticket (`tls.record.Error.Refused`).
    TlsRefused,
};

pub const RequestError = error{
    /// Every slot holds an exchange, until one's `finished` event is reported.
    Full,
    /// The connection takes no new request, as its `draining` event said.
    Draining,
    /// The connection is over.
    ConnectionClosed,
    /// The method or the path is empty, or the method is CONNECT, whose tunnel is no exchange of
    /// a request and a response (RFC 9110 §9.3.6).
    RequestUnsupported,
    /// A field line the client writes itself, Host or Content-Length, or a connection-specific
    /// one, which h2 forbids (RFC 9113 §8.2.2), so a request means the same in every version.
    FieldReserved,
};

/// The names of the field lines `request` refuses, lowercase.
const reserved_names = [_][]const u8{
    // RFC 9112 §3.2 and RFC 9113 §8.3.1: the client names the authority itself.
    "host",
    // RFC 9110 §8.6: the client frames the content it sends.
    "content-length",
    // RFC 9113 §8.2.2: connection-specific fields.
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
};

const Phase = enum {
    /// The TLS handshake has not completed.
    handshake,
    /// The protocol serves the connection.
    open,
    /// Nothing more is read or written.
    closed,
};

pub const Session = union(enum) {
    /// No protocol serves the connection: its TLS handshake has not completed, or it failed.
    none,
    h11: h11.connection.Connection,
    h2: h2.Connection,
};

pub const Connection = struct {
    config: *const Config,
    phase: Phase,
    /// The protocol serving the connection, from the start in cleartext and over TLS once the
    /// handshake completes.
    session: Session,
    tls_client: tls.record.Client,
    /// The protocol's octets opened from records and not yet read.
    plain_in: [constants.plaintext_in_len]u8,
    plain_in_len: usize,
    /// What the connection wrote that `send` has not taken: the TLS flight's records first,
    /// `records_len` octets of them, then the protocol's octets, which `send` seals over TLS.
    output: [constants.output_len]u8,
    output_len: usize,
    records_len: usize,
    /// A KeyUpdate's reply is owed, and no record opens until `send` has sealed it (RFC 9846
    /// §4.7.3).
    reply_owed: bool,
    /// The peer's `close_notify` ended its data (RFC 9846 §6.1).
    peer_closed: bool,
    /// This side's `close_notify` is sealed.
    close_sent: bool,
    /// The connection failed or finished, so it reads nothing and writes nothing but what it owes.
    stopped: bool,
    /// The connection takes no new request.
    draining: bool,
    /// The exchanges the connection holds.
    slots: slots_module.Slots,
    /// Events owed to the caller, reported before anything more is read.
    connected_owed: bool,
    ticket_owed: bool,
    draining_owed: bool,
    closed_reported: bool,
    /// The latest ticket the server issued, until `take_ticket` hands it over.
    ticket: ?tls.Ticket,

    /// Prepares a connection the caller is opening, with nothing read or written. Over TLS, every
    /// draw the handshake makes comes from `random`, `now_seconds` is the instant a Web PKI chain
    /// is judged at, and `resumption` offers a ticket an earlier connection took.
    pub fn init(connection: *Connection, config: *const Config, random: tls.Random, now_seconds: u64, resumption: ?tls.Resumption) StartError!void {
        assert(config.authority.len > 0);
        connection.config = config;
        connection.session = .none;
        connection.plain_in_len = 0;
        connection.output_len = 0;
        connection.records_len = 0;
        connection.reply_owed = false;
        connection.peer_closed = false;
        connection.close_sent = false;
        connection.stopped = false;
        connection.draining = false;
        connection.slots.init();
        connection.connected_owed = false;
        connection.ticket_owed = false;
        connection.draining_owed = false;
        connection.closed_reported = false;
        connection.ticket = null;
        if (config.tls) |tls_config| {
            connection.phase = .handshake;
            // RFC 9846 §4.7.1: chapulin refuses values it cannot run and a ticket too old.
            connection.tls_client.start(tls_config, random, now_seconds, resumption) catch return error.TlsRefused;
        } else {
            connection.open_session(config.cleartext);
        }
        assert(connection.output_len == 0 and connection.plain_in_len == 0);
    }

    /// Makes the protocol's connection, which then serves this one.
    pub fn open_session(connection: *Connection, chosen: Protocol) void {
        switch (chosen) {
            .h2 => {
                connection.session = .{ .h2 = undefined };
                connection.session.h2.init(.client);
            },
            .h11 => {
                connection.session = .{ .h11 = undefined };
                connection.session.h11.init(.client, .{});
            },
        }
        connection.phase = .open;
        connection.connected_owed = true;
        assert(connection.protocol().? == chosen);
    }

    /// Takes `exchange`, which `send` writes when the protocol, the room and the peer allow, and
    /// returns its id. The caller keeps the exchange in place until its `finished` event.
    pub fn request(connection: *Connection, exchange: *Exchange) RequestError!Id {
        // RFC 9113 §5.4.1 and RFC 9112 §9.6: a connection that failed or closed carries no request.
        if (connection.phase == .closed or connection.stopped) return error.ConnectionClosed;
        // RFC 9113 §6.8 and §5.1.1, RFC 9112 §9.6: a connection that heard GOAWAY, spent its
        // identifiers or said it closes opens no new request.
        if (connection.draining) return error.Draining;
        try check_request(exchange);
        exchange.clear();
        const id = connection.slots.take(exchange) orelse return error.Full;
        assert(connection.slots.of_id(id).?.stage == .queued);
        return id;
    }

    /// Ends exchange `id` before its response is whole, and reports nothing for it. One not yet
    /// written is dropped. A written one: h2 resets its stream with CANCEL (RFC 9113 §6.4), and h11
    /// reads its response and drops it, or, while its content is going out, ends the connection.
    pub fn cancel(connection: *Connection, id: Id) void {
        const slot = connection.slots.of_id(id) orelse return;
        switch (slot.stage) {
            .queued, .ended => slots_module.release(slot),
            .dropping => slot.report_after_drop = false,
            .sent => switch (connection.session) {
                .h2 => connection_h2.cancel(connection, slot),
                .h11 => connection_h11.cancel(connection, slot),
                // An exchange is written only once a protocol serves the connection.
                .none => unreachable,
            },
            .free => unreachable,
        }
    }

    /// Reports what the connection owes the caller, then reads at most one event from `input`,
    /// the octets the transport read. Over TLS it runs the handshake first, and `input` is records,
    /// which chapulin may open in place.
    pub fn receive(connection: *Connection, input: []u8, now_ns: u64) Received {
        if (connection.owed_event()) |owed| return .{ .consumed = 0, .event = owed };
        const consumed = switch (connection.phase) {
            .closed => 0,
            .handshake => connection_tls.handshake(connection, input, now_ns),
            .open => if (connection.config.tls == null)
                connection.read_protocol(input, now_ns)
            else
                connection_tls.read(connection, input, now_ns),
        };
        return .{ .consumed = consumed, .event = connection.owed_event() };
    }

    /// Reads the protocol's octets until an exchange ends, or the octets run out, and returns
    /// the octets taken.
    pub fn read_protocol(connection: *Connection, plaintext: []const u8, now_ns: u64) usize {
        if (connection.stopped) return 0;
        return switch (connection.session) {
            .h2 => connection_h2.receive(connection, plaintext, now_ns),
            .h11 => connection_h11.receive(connection, plaintext),
            // `receive` reads the protocol only once the connection is open.
            .none => unreachable,
        };
    }

    /// Writes the requests waiting and what the protocol owes into `output`, sealed over TLS, and
    /// returns the octets written. What does not fit waits for the next call.
    pub fn send(connection: *Connection, output: []u8, now_ns: u64) usize {
        if (connection.phase == .open) connection.write_protocol(now_ns);
        if (connection.config.tls != null) return connection_tls.send(connection, output, now_ns);
        const written = @min(output.len, connection.output_len);
        @memcpy(output[0..written], connection.output[0..written]);
        connection.take_output(written);
        return written;
    }

    /// Ends the connection once the exchanges it holds have finished: no new request is taken, h2
    /// sends GOAWAY (RFC 9113 §6.8), and both close.
    pub fn shutdown(connection: *Connection) void {
        connection.start_draining();
    }

    /// Whether the caller closes the transport now: the connection is over and `send` has written
    /// everything, over TLS the `close_notify` too (RFC 9846 §6.1).
    pub fn should_close(connection: *const Connection) bool {
        if (connection.output_len > 0 or !connection.closed_reported) return false;
        return switch (connection.phase) {
            .handshake => false,
            .closed => true,
            .open => connection.config.tls == null or connection.close_sent or connection.tls_failed(),
        };
    }

    /// The transport closed: the peer closed it, the caller closed it once `should_close` said so,
    /// or it failed. Every exchange still held ends, nothing more is read or written, and over TLS
    /// the session's secrets are wiped. A second call changes nothing.
    pub fn transport_closed(connection: *Connection) void {
        if (connection.phase == .open and connection.session == .h11) connection_h11.transport_closed(connection);
        // RFC 9112 §9.3.1 and RFC 9113 §8.7: what was never written may go on another connection.
        connection.slots.end_all(.refused, .closed);
        connection.phase = .closed;
        connection.stopped = true;
        connection.output_len = 0;
        connection.records_len = 0;
        // chapulin's close wipes every secret, and is safe on a session that closed or failed.
        if (connection.config.tls != null) connection.tls_client.close();
        connection.wipe_ticket();
    }

    /// The protocol serving the connection, or null while the TLS handshake runs or after it failed.
    pub fn protocol(connection: *const Connection) ?Protocol {
        return switch (connection.session) {
            .none => null,
            .h11 => .h11,
            .h2 => .h2,
        };
    }

    /// The resumption ticket the `ticket` event announced, which the call hands over and clears.
    /// The caller offers it to a later connection's `init`, and wipes it when it drops it.
    pub fn take_ticket(connection: *Connection) ?tls.Ticket {
        const ticket = connection.ticket orelse return null;
        connection.wipe_ticket();
        return ticket;
    }

    /// Takes the ticket the server issued, if any, and owes the caller its event. Over TLS only.
    pub fn collect_ticket(connection: *Connection) void {
        assert(connection.config.tls != null);
        const issued = connection.tls_client.take_ticket() orelse return;
        connection.wipe_ticket();
        connection.ticket = issued;
        connection.ticket_owed = true;
    }

    fn wipe_ticket(connection: *Connection) void {
        if (connection.ticket) |*held| held.wipe();
        connection.ticket = null;
        connection.ticket_owed = false;
    }

    /// Takes no new request from here on, and owes the caller the `draining` event.
    pub fn start_draining(connection: *Connection) void {
        if (connection.draining) return;
        connection.draining = true;
        connection.draining_owed = true;
    }

    /// Ends the connection on a failure: every exchange it holds ends, nothing more is read, and
    /// what it owes goes out.
    pub fn fail(connection: *Connection) void {
        // RFC 9113 §5.4.1, RFC 9112 §9.6 and RFC 9846 §6: after a connection error nothing more is
        // read, and the connection closes once what it owes is out.
        connection.stopped = true;
        connection.slots.end_all(.refused, .closed);
        assert(connection.slots.idle());
    }

    /// The first event owed to the caller, in the order the header of `event.zig` gives them.
    fn owed_event(connection: *Connection) ?Event {
        if (connection.connected_owed) {
            connection.connected_owed = false;
            return .{ .connected = connection.protocol().? };
        }
        if (connection.ticket_owed) {
            connection.ticket_owed = false;
            return .ticket;
        }
        if (connection.slots.oldest(.ended)) |slot| {
            const ended: event.Finished = .{ .id = slot.id, .exchange = slot.exchange };
            slots_module.release(slot);
            return .{ .finished = ended };
        }
        if (connection.draining_owed) {
            connection.draining_owed = false;
            return .draining;
        }
        if (!connection.closed_reported and connection.over()) {
            connection.closed_reported = true;
            return .closed;
        }
        return null;
    }

    /// Whether the connection carries nothing more and every exchange it held has finished: it
    /// failed, its transport closed, or it was draining and its last exchange ended.
    fn over(connection: *Connection) bool {
        if (!connection.slots.idle() or connection.slots.count(.ended) > 0) return false;
        if (connection.phase == .closed or connection.stopped) return true;
        if (!connection.draining or connection.phase != .open) return false;
        // What the protocol owes, such as h2's GOAWAY, goes out first.
        connection.finish_draining();
        return true;
    }

    /// The last exchange of a draining connection ended: h2 says GOAWAY (RFC 9113 §6.8), and
    /// nothing more is read.
    fn finish_draining(connection: *Connection) void {
        assert(connection.draining and connection.slots.idle());
        switch (connection.session) {
            .h2 => connection.session.h2.shutdown(h2.constants.error_no_error),
            .h11 => {},
            .none => unreachable,
        }
        connection.stopped = true;
    }

    /// Writes what the protocol owes, then the requests and their content, after what `output`
    /// holds.
    fn write_protocol(connection: *Connection, now_ns: u64) void {
        _ = connection.write_owed(now_ns);
        if (connection.stopped) return;
        switch (connection.session) {
            .h2 => connection_h2.write_requests(connection),
            .h11 => connection_h11.write_requests(connection),
            .none => unreachable,
        }
        _ = connection.write_owed(now_ns);
    }

    /// Writes what the protocol owes on its own, such as its preface, the acknowledgments and a
    /// GOAWAY, after what `output` holds. Returns whether it wrote anything.
    pub fn write_owed(connection: *Connection, now_ns: u64) bool {
        if (connection.phase != .open) return false;
        const free = connection.room();
        const written = switch (connection.session) {
            .h2 => connection.session.h2.write_pending(free, now_ns),
            .h11 => connection.session.h11.write_pending(free) catch 0,
            // An open connection has a protocol.
            .none => unreachable,
        };
        connection.output_len += written;
        return written > 0;
    }

    /// Whether the protocol owes octets `write_owed` has not written yet.
    pub fn protocol_pending(connection: *const Connection) bool {
        return switch (connection.session) {
            .h2 => connection.session.h2.has_pending(),
            .h11 => connection.session.h11.has_pending(),
            .none => false,
        };
    }

    /// Drops the first `written` octets of `output`, which `send` has taken.
    pub fn take_output(connection: *Connection, written: usize) void {
        assert(written <= connection.output_len);
        std.mem.copyForwards(u8, &connection.output, connection.output[written..connection.output_len]);
        connection.output_len -= written;
        connection.records_len -= @min(connection.records_len, written);
    }

    /// Drops the first `read` octets of the protocol's plaintext, which the protocol has taken.
    pub fn take_plaintext(connection: *Connection, read: usize) void {
        assert(read <= connection.plain_in_len);
        std.mem.copyForwards(u8, &connection.plain_in, connection.plain_in[read..connection.plain_in_len]);
        connection.plain_in_len -= read;
    }

    /// The room left in `output`.
    pub fn room(connection: *Connection) []u8 {
        return connection.output[connection.output_len..];
    }

    /// Whether the connection has nothing more to write but what `output` holds and, over TLS,
    /// its `close_notify`.
    pub fn finished(connection: *const Connection) bool {
        return connection.closed_reported and !connection.protocol_pending();
    }

    fn tls_failed(connection: *const Connection) bool {
        return switch (connection.session) {
            .h2 => connection.session.h2.tls_failed,
            .h11 => connection.session.h11.tls_failed,
            .none => false,
        };
    }
};

/// Refuses what no protocol could send as an exchange, before the exchange takes a slot.
fn check_request(exchange: *const Exchange) RequestError!void {
    // RFC 9110 §9.1: a method is a token, which is never empty.
    if (exchange.method.len == 0) return error.RequestUnsupported;
    // RFC 9113 §8.3.1: `:path` "MUST NOT be empty" for an http or https URI, and RFC 9112 §3.2.1's
    // origin form starts with its absolute path.
    if (exchange.path.len == 0) return error.RequestUnsupported;
    // RFC 9110 §9.3.6: CONNECT asks for a tunnel, which is no exchange of a request and a response.
    if (std.mem.eql(u8, exchange.method, "CONNECT")) return error.RequestUnsupported;
    for (exchange.fields) |field| {
        for (reserved_names) |reserved| {
            // RFC 9113 §8.2.2, RFC 9112 §3.2 and RFC 9110 §8.6: see `reserved_names`. Field names
            // are case-insensitive (RFC 9110 §5.1).
            if (std.ascii.eqlIgnoreCase(field.name, reserved)) return error.FieldReserved;
        }
    }
}

test {
    _ = @import("connection_request_test.zig");
    _ = @import("connection_h2_test.zig");
    _ = @import("connection_h2_flow_test.zig");
    _ = @import("connection_h11_test.zig");
    _ = @import("connection_tls_test.zig");
}
