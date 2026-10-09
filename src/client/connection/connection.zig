//! One connection of the client over TCP (decision 100, design §8 step 17c). The caller places an
//! exchange for each request and hands it to `request`, which returns its id. `send` writes the
//! requests as the protocol, the room and the peer allow, and the octets the caller read go in
//! through `receive`, which returns at most one event a call. Every exchange ends in one outcome,
//! reported by its `finished` event, in h11 and h2 alike.
//!
//! Over TLS, `receive` runs the handshake through `tls.record.Client`, and the protocol ALPN
//! selected serves the connection: h2 for "h2" (RFC 9113 §3.2), and h11 for "http/1.1" or for no
//! selection (decision 88). In cleartext, the connection speaks h11 when `Config.versions` allows
//! it, and h2 with prior knowledge when it does not (RFC 9113 §3.3, decision 117).
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
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const slots_module = @import("../slots.zig");
const coding = @import("../coding.zig");
const coding_pool = @import("../coding_pool.zig");
const owed_module = @import("../owed.zig");
const connection_h11 = @import("connection_h11.zig");
const connection_h2 = @import("connection_h2.zig");
const connection_tls = @import("connection_tls.zig");
const connection_request = @import("connection_request.zig");
const internal = @import("connection_internal.zig");
const alt_svc = @import("../alt_svc.zig");
const versions_module = @import("../versions.zig");

pub const Id = event.Id;
pub const Protocol = event.Protocol;
pub const Event = event.Event;
pub const Received = event.Received;
pub const HttpExchange = event.HttpExchange;
pub const Field = event.Field;
const Slot = slots_module.Slot;

/// What every connection to one origin borrows. The caller keeps it alive while any connection
/// holds it.
pub const Config = struct {
    /// The TLS configuration, or null for cleartext. Its ALPN list names what the client offers,
    /// `h2` and `http/1.1` in the order it prefers them (RFC 7301 §3.1).
    tls: ?*const tls.record.ClientConfig = null,
    /// The versions the client speaks (decision 117). A connection in cleartext speaks h11 when it
    /// allows h11, and h2 with prior knowledge when it does not (RFC 9113 §3.3). Over TLS, ALPN
    /// chooses (decision 88).
    versions: versions_module.Versions = .{},
    /// The authority every request names: `:authority` in h2 (RFC 9113 §8.3.1) and Host in h11
    /// (RFC 9112 §3.2).
    authority: []const u8,
    /// The content codings the client offers in each request's Accept-Encoding, in its order of
    /// preference, and the pools of decoders it removes them with, which connections may share
    /// (decision 101 as amended): `decoders` for `gzip` and `deflate`, `zstd_decoders` and
    /// `br_decoders`. Each coding is named once at most and has its pool, and each pool given serves
    /// a coding named.
    codings: []const http.content_coding.Coding = &.{},
    decoders: ?h11.coding.Storage = null,
    zstd_decoders: ?coding_pool.ZstdDecoders = null,
    br_decoders: ?coding_pool.BrotliDecoders = null,
};

pub const StartError = error{
    /// chapulin refused the TLS configuration or the ticket (`tls.record.Error.Refused`).
    TlsRefused,
    /// `Config.versions` allows neither h11 nor h2, which leaves a TCP connection nothing to speak
    /// (RFC 9114 §3.1, decision 117).
    NoVersion,
};

pub const RequestError = connection_request.RequestError;
pub const check_request = connection_request.check_request;

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
    h11: h11.Connection,
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
    /// The connection ended on a failure, or its transport closed before it was over, rather
    /// than after its last exchange.
    failed: bool,
    /// What the latest final response's Alt-Svc said of h3 on the origin's host (RFC 7838 §3),
    /// until `take_alt_svc` hands it over.
    alt_svc: ?alt_svc.Advert,
    /// The exchanges the connection holds.
    slots: slots_module.Slots,
    /// Events owed to the caller, reported before anything more is read.
    owed: owed_module.Owed,
    /// The latest ticket the server issued, until `take_ticket` hands it over.
    ticket: ?tls.Ticket,

    /// Prepares a connection the caller is opening, with nothing read or written. Over TLS, every
    /// draw the handshake makes comes from `random`, `now_seconds` is the instant a Web PKI chain
    /// is judged at, and `resumption` offers a ticket an earlier connection took.
    pub fn init(connection: *Connection, config: *const Config, random: tls.Random, now_seconds: u64, resumption: ?tls.Resumption) StartError!void {
        assert(coding.codings_valid(config.codings, .of(config)));
        assert(config.authority.len > 0);
        // RFC 9114 §3.1: a TCP connection speaks h11 or h2, never h3, so `versions` allows one.
        const cleartext = versions_module.cleartext(config.versions) orelse return error.NoVersion;
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
        connection.failed = false;
        connection.alt_svc = null;
        connection.slots.init();
        connection.owed = .{};
        connection.ticket = null;
        if (config.tls) |tls_config| {
            connection.phase = .handshake;
            // RFC 9846 §4.7.1: chapulin refuses values it cannot run and a ticket too old.
            connection.tls_client.start(tls_config, random, now_seconds, resumption) catch return error.TlsRefused;
        } else {
            internal.open_session(connection, cleartext);
        }
        assert(connection.output_len == 0 and connection.plain_in_len == 0);
    }

    /// Takes `exchange`, which `send` writes when the protocol, the room and the peer allow, and
    /// returns its id. The caller keeps the exchange in place until its `finished` event.
    pub fn request(connection: *Connection, exchange: *HttpExchange) RequestError!Id {
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

    /// Ends exchange `id` before its response is whole, and reports nothing for it. The client
    /// reads and writes nothing of the exchange after the call, so its memory is the caller's
    /// again. One not yet written is dropped. A written one: h2 resets its stream with CANCEL (RFC
    /// 9113 §6.4), and h11 reads its response and drops it, or, while its content is going out,
    /// ends the connection.
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
                internal.read_protocol(connection, input, now_ns)
            else
                connection_tls.read(connection, input, now_ns),
        };
        return .{ .consumed = consumed, .event = connection.owed_event() };
    }

    /// Writes the requests waiting and what the protocol owes into `output`, sealed over TLS, and
    /// returns the octets written. What does not fit waits for the next call.
    pub fn send(connection: *Connection, output: []u8, now_ns: u64) usize {
        if (connection.phase == .open) connection.write_protocol(now_ns);
        if (connection.config.tls != null) return connection_tls.send(connection, output, now_ns);
        const written = @min(output.len, connection.output_len);
        @memcpy(output[0..written], connection.output[0..written]);
        internal.take_output(connection, written);
        return written;
    }

    /// Ends the connection once the exchanges it holds have finished: no new request is taken, h2
    /// sends GOAWAY (RFC 9113 §6.8), and both close.
    pub fn shutdown(connection: *Connection) void {
        internal.start_draining(connection);
    }

    /// Whether the caller closes the transport now: the connection is over and `send` has written
    /// everything, over TLS the `close_notify` too (RFC 9846 §6.1), or the alert of a failure.
    pub fn should_close(connection: *const Connection) bool {
        if (connection.output_len > 0 or !connection.owed.closed_reported) return false;
        return switch (connection.phase) {
            .handshake => false,
            .closed => true,
            .open => connection.config.tls == null or connection.close_sent or connection.failure_sent(),
        };
    }

    /// The transport closed: the peer closed it, the caller closed it once `should_close` said so,
    /// or it failed. Every exchange still held ends, nothing more is read or written, and over TLS
    /// the session's secrets are wiped. A second call changes nothing.
    pub fn transport_closed(connection: *Connection) void {
        if (!connection.owed.closed_reported) connection.failed = true;
        if (connection.phase == .open and connection.session == .h11) connection_h11.transport_closed(connection);
        // RFC 9112 §9.3.1 and RFC 9113 §8.7: what was never written may go on another connection.
        connection.slots.end_all(.refused, .closed);
        connection.phase = .closed;
        connection.stopped = true;
        connection.output_len = 0;
        connection.records_len = 0;
        // chapulin's close wipes every secret, and is safe on a session that closed or failed.
        if (connection.config.tls != null) connection.tls_client.close();
        internal.wipe_ticket(connection);
    }

    /// The protocol serving the connection, or null during the TLS handshake or after it failed.
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
        internal.wipe_ticket(connection);
        return ticket;
    }

    /// What a response said of h3 in Alt-Svc since the last call, or null.
    pub fn take_alt_svc(connection: *Connection) ?alt_svc.Advert {
        defer connection.alt_svc = null;
        return connection.alt_svc;
    }

    /// The first event owed to the caller, in the order `owed.zig` gives them.
    fn owed_event(connection: *Connection) ?Event {
        return connection.owed.next(&connection.slots, connection.protocol(), connection.over());
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
        _ = internal.write_owed(connection, now_ns);
        if (connection.stopped) return;
        switch (connection.session) {
            .h2 => connection_h2.write_requests(connection),
            .h11 => connection_h11.write_requests(connection),
            .none => unreachable,
        }
        _ = internal.write_owed(connection, now_ns);
    }

    /// Whether the record layer failed and `send` has written the alert the provider owed.
    fn failure_sent(connection: *const Connection) bool {
        return switch (connection.session) {
            // RFC 9846 §5.2 and §6.2: the connection ends with the alert, so it closes once the
            // alert is out.
            .h2 => connection.session.h2.tls_failed and !connection.session.h2.handshake_owed,
            .h11 => connection.session.h11.tls_failed and !connection.session.h11.handshake_owed,
            .none => false,
        };
    }
};

test "design §8 step 17f: the connection's public functions are the calls a program makes" {
    // What the connection's own files call on it lives in `connection_internal.zig`, which the
    // module does not export. A function added here is one every program can call.
    const public_names = @import("core").public_names;
    try public_names.expect(Connection, &.{
        "init",         "request",      "cancel",           "receive",  "send",
        "shutdown",     "should_close", "transport_closed", "protocol", "take_ticket",
        "take_alt_svc",
    });
}

test {
    _ = @import("connection_request_test.zig");
    _ = @import("connection_coding_test.zig");
    _ = @import("connection_coding_zstd_br_test.zig");
    _ = @import("connection_h2_test.zig");
    _ = @import("connection_h2_flow_test.zig");
    _ = @import("connection_h11_test.zig");
    _ = @import("connection_tls_test.zig");
}
