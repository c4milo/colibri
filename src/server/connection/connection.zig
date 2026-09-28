//! One connection of the server over TCP (decision 100, design §8 step 17a). The octets the caller
//! read go in through `receive`, which returns at most one event a call, and the octets the
//! connection owes the peer come out through `send`. The caller answers a request by its id with
//! `respond`, `write_body` and `write_trailers`, in h11 and h2 alike.
//!
//! Over TLS, `receive` runs the handshake through `tls.record.Server`, and the protocol ALPN
//! selected serves the connection: h2 for "h2" (RFC 9113 §3.2), and h11 for "http/1.1" or for no
//! selection (decision 88). In cleartext, `Config.cleartext` names the protocol: h11, or h2 with
//! prior knowledge (RFC 9113 §3.3).
//!
//! What the connection writes waits in `output` until `send` takes it, sealed into records over
//! TLS. A call that finds no room fails with `error.NoSpaceLeft`, or `write_body` with
//! `error.Blocked`, and the caller sends before it calls again. Field names a response carries are
//! lowercase, as h2 sends them (RFC 9113 §8.2), and h11 sends them as given.
//!
//! The caller loops over `receive` until it returns nothing consumed and no event, keeping the
//! octets an event points into until the next call. After each `send` it loops over `receive`
//! again, even with no new octets: while the output was full, h2 read no frame past the replies it
//! owed (RFC 9113 §6.5.3), and those frames are read then. It closes the transport once
//! `should_close` says so, after `send` has written everything. The caller owns the struct and
//! colibri allocates nothing (decision 35).
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const h11 = @import("h11");
const h2 = @import("h2");
const tls = @import("tls");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_h11 = @import("connection_h11.zig");
const connection_h2 = @import("connection_h2.zig");
const connection_tls = @import("connection_tls.zig");
const expect = @import("../expect.zig");
const done = @import("../done.zig");

pub const Id = event.Id;
pub const Protocol = event.Protocol;
pub const Event = event.Event;
pub const Received = event.Received;
pub const Field = http.field.Field;

/// What every connection of a server borrows. The caller keeps it alive while any connection
/// holds it.
pub const Config = struct {
    /// The TLS configuration, or null for cleartext. Its ALPN list names what the server offers,
    /// `h2` and `http/1.1` in the order it prefers them (RFC 7301 §3.2).
    tls: ?*const tls.record.ServerConfig = null,
    /// The protocol a cleartext connection speaks: h11, or h2 with prior knowledge (RFC 9113
    /// §3.3). Over TLS, ALPN chooses (decision 88).
    cleartext: Protocol = .h11,
    /// h11's decoders of the `gzip` and `deflate` transfer codings, which connections may share
    /// (decision 91). With none, h11 answers a request carrying either coding 501.
    decoders: ?h11.coding.Storage = null,
    /// Where h11 decodes a body carrying `gzip` or `deflate` (decision 98). A `body` event's octets
    /// point into it until the next `receive` of any connection sharing it. Empty with no decoders.
    decoded: []u8 = &.{},
};

/// Why `receive` stopped reading for good: the peer broke the protocol, or TLS failed (RFC 9846
/// §6). What the connection owes the peer, such as a GOAWAY, an error response or an alert, waits
/// for `send`, and the caller closes once `should_close` says so.
pub const Error = error{ConnectionFailed};

pub const StartError = error{
    /// chapulin refused the TLS configuration (`tls.record.Error.Refused`).
    TlsRefused,
};

pub const SendError = error{
    /// `output` has no room for what the call writes: `send`, then call again.
    NoSpaceLeft,
    /// `write_body` wrote nothing: no room, or h2's flow-control window is closed (RFC 9113 §6.9).
    /// `send`, `receive`, then call again.
    Blocked,
    /// No request with this id waits for this call: it never arrived, is answered, or is cancelled.
    RequestUnknown,
    /// The connection is closing and writes no more responses.
    ConnectionClosed,
    /// The status is not a code from 100 to 599 (RFC 9110 §15), or is 101, which colibri does not
    /// implement (RFC 9110 §15.2.2).
    StatusInvalid,
    /// A field line h11 or h2 refuses to send (RFC 9110 §5.1, §5.5, RFC 9113 §8.2).
    FieldLineInvalid,
    /// A response after the final one, content before it, or trailers before it (RFC 9110 §6.4.1,
    /// RFC 9113 §8.1).
    SectionOutOfOrder,
    /// More field lines than `field_count_max`, or a field section larger than the output holds
    /// when empty.
    SectionTooLarge,
    /// Trailers h11 cannot carry: on a response that is not chunked (RFC 9112 §7.1.2), or a field
    /// that frames or routes the message (RFC 9110 §6.5.1).
    TrailersRefused,
    /// Content that does not match the response's Content-Length (RFC 9110 §8.6).
    ContentLengthMismatch,
};

/// RFC 9110 §15.2.1: 100 (Continue).
const continue_status: u16 = @intFromEnum(http.status.Code.@"continue");

const Phase = enum {
    /// The TLS handshake has not completed.
    handshake,
    /// The protocol is serving the connection.
    open,
    /// Nothing more is read.
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
    tls_server: tls.record.Server,
    /// The protocol's octets opened from records and not yet read. Its first `plain_in_read`
    /// octets are what the last event pointed into, dropped at the next call.
    plain_in: [constants.plaintext_in_len]u8,
    plain_in_len: usize,
    plain_in_read: usize,
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
    /// The connection failed, or the caller stopped it, so it reads nothing and finishes once its
    /// last octets are out.
    stopped: bool,
    /// The caller asked the connection to end once its requests are answered.
    shutting_down: bool,
    /// The request a 100 (Continue) is owed to (RFC 9110 §10.1.1), which the next `receive` or
    /// `send` writes unless the caller answers the request first.
    continue_owed: ?Id,
    /// h11: the id the next request gets, and the id of the request being answered.
    next_id: Id,
    current_id: Id,
    /// h11: the request being answered came as HTTP/1.1, so a response of unknown length is
    /// chunked (RFC 9112 §7.1). An HTTP/1.0 one runs until the close (RFC 9112 §6.3 rule 8).
    chunked_allowed: bool,
    /// h11: the request being answered is a HEAD (RFC 9110 §9.3.2).
    head_request: bool,
    /// The responses made whole whose `done` event `receive` has not reported (decision 103).
    done_owed: done.Owed,
    /// h11: the last request whose `done` event is owed, so its response owes no second one.
    done_id: Id,

    /// Prepares a connection the listener accepted, with nothing read or written. Over TLS, every
    /// draw the handshake makes comes from `random`, and `now_seconds` is the clock its tickets
    /// are issued at, or 0 for none.
    pub fn init(connection: *Connection, config: *const Config, random: tls.Random, now_seconds: u64) StartError!void {
        // RFC 9114 §3.1: a TCP connection speaks h11 or h2, never h3.
        assert(config.cleartext != .h3);
        connection.config = config;
        connection.plain_in_len = 0;
        connection.plain_in_read = 0;
        connection.output_len = 0;
        connection.records_len = 0;
        connection.reply_owed = false;
        connection.peer_closed = false;
        connection.close_sent = false;
        connection.stopped = false;
        connection.shutting_down = false;
        connection.continue_owed = null;
        connection.next_id = 1;
        connection.current_id = 0;
        connection.chunked_allowed = false;
        connection.head_request = false;
        connection.done_owed = .{};
        connection.done_id = 0;
        connection.session = .none;
        if (config.tls) |tls_config| {
            connection.phase = .handshake;
            // RFC 9846 §9.2: chapulin refuses values it cannot serve a handshake from.
            connection.tls_server.start(tls_config, random, now_seconds) catch return error.TlsRefused;
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
                connection.session.h2.init(.server);
            },
            .h11 => {
                connection.session = .{ .h11 = undefined };
                connection.session.h11.init(.server, .{ .decoders = connection.config.decoders });
            },
            // RFC 9114 §3.1: h3 runs over QUIC alone, which `QuicConnection` serves.
            .h3 => unreachable,
        }
        connection.phase = .open;
        assert(connection.protocol().? == chosen);
    }

    /// Reads at most one event from `input`, the octets the transport read. Over TLS it runs the
    /// handshake first, and `input` is records, which chapulin may open in place.
    pub fn receive(connection: *Connection, input: []u8, now_ns: u64) Error!Received {
        // RFC 9110 §10.1.1: the 100 goes out before the server waits for the content.
        if (!connection.write_continue()) return .{ .consumed = 0, .event = null };
        // Decision 103: a response made whole since the last call is reported before anything
        // more is read, so no request arrives while one is owed.
        if (connection.done_owed.take()) |id| return .{ .consumed = 0, .event = .{ .done = .{ .id = id } } };
        const received = try switch (connection.phase) {
            .closed => Received{ .consumed = 0, .event = null },
            .handshake => connection_tls.handshake(connection, input, now_ns),
            .open => if (connection.config.tls == null)
                connection.read_protocol(input, now_ns)
            else
                connection_tls.read(connection, input, now_ns),
        };
        const reported = received.event orelse return received;
        if (reported == .request and expect.expects_continue(reported.request)) connection.continue_owed = reported.request.id;
        return received;
    }

    /// Writes the 100 (Continue) owed, and returns whether none is owed any more. A request the
    /// caller answered with a final response, or cancelled, needs none, and the protocol refuses one.
    fn write_continue(connection: *Connection) bool {
        const id = connection.continue_owed orelse return true;
        if (connection.phase != .open or connection.stopped) {
            connection.continue_owed = null;
            return true;
        }
        const written = switch (connection.session) {
            .h2 => connection_h2.write_continue(connection, id),
            .h11 => connection_h11.write_continue(connection),
            .none => unreachable,
        } catch |failure| {
            // No room: the caller sends, and the 100 goes out on the next call.
            if (failure == error.NoSpaceLeft) return false;
            // The request ended before the 100 could go out, and needs none.
            connection.continue_owed = null;
            return true;
        };
        connection.output_len += written;
        connection.continue_owed = null;
        return true;
    }

    /// Reads at most one event from the protocol's octets, and the octets before it that mean
    /// nothing to the caller.
    pub fn read_protocol(connection: *Connection, plaintext: []const u8, now_ns: u64) Error!Received {
        if (connection.stopped) return .{ .consumed = 0, .event = null };
        return switch (connection.session) {
            .h2 => connection_h2.receive(connection, plaintext, now_ns),
            .h11 => connection_h11.receive(connection, plaintext),
            // `receive` reads the protocol only once the connection is open.
            .none => unreachable,
        };
    }

    /// Writes the head of the response to request `id`: an interim one (1xx) or the final one.
    /// With `end`, the final response carries no content. An interim response ignores `end`,
    /// because the final response still follows it (RFC 9110 §15.2).
    pub fn respond(connection: *Connection, id: Id, status: u16, fields: []const Field, end: bool) SendError!void {
        try connection.check_writable();
        // RFC 9110 §10.1.1: the caller's own 100 replaces the one owed. A final response replaces
        // it too: the protocol refuses a 100 after it, and `write_continue` drops the one owed.
        if (connection.continue_owed == id and status == continue_status) connection.continue_owed = null;
        switch (connection.session) {
            .h2 => try connection_h2.respond(connection, id, status, fields, end),
            .h11 => try connection_h11.respond(connection, id, status, fields, end),
            // RFC 9110 §3.4: a response answers a request, and none arrives before the handshake
            // completes.
            .none => return error.RequestUnknown,
        }
    }

    /// Writes content of the response to request `id`, as much of `octets` as the room and h2's
    /// windows allow, and returns the octets taken. With `end`, the content ends once every octet
    /// is taken; a call that takes fewer leaves the rest, and the end, to the next call.
    pub fn write_body(connection: *Connection, id: Id, octets: []const u8, end: bool) SendError!usize {
        try connection.check_writable();
        if (octets.len == 0 and !end) return 0;
        return switch (connection.session) {
            .h2 => connection_h2.write_body(connection, id, octets, end),
            .h11 => connection_h11.write_body(connection, id, octets, end),
            // RFC 9110 §3.4: no request arrives before the handshake completes.
            .none => error.RequestUnknown,
        };
    }

    /// Ends the response to request `id` with a trailer section (RFC 9110 §6.5).
    pub fn write_trailers(connection: *Connection, id: Id, fields: []const Field) SendError!void {
        try connection.check_writable();
        switch (connection.session) {
            .h2 => try connection_h2.write_trailers(connection, id, fields),
            .h11 => try connection_h11.write_trailers(connection, id, fields),
            // RFC 9110 §3.4: no request arrives before the handshake completes.
            .none => return error.RequestUnknown,
        }
    }

    /// Ends request `id` before its response is whole: h2 resets its stream with CANCEL (RFC
    /// 9113 §6.4), and h11, which cannot end one request alone, ends the connection.
    pub fn cancel(connection: *Connection, id: Id) void {
        if (connection.phase != .open) return;
        switch (connection.session) {
            .h2 => connection_h2.cancel(connection, id),
            .h11 => connection_h11.cancel(connection, id),
            .none => {},
        }
    }

    /// Ends the connection once the requests it holds are answered: h2 sends GOAWAY (RFC 9113
    /// §6.8), and h11 closes after the current response (RFC 9112 §9.6).
    pub fn shutdown(connection: *Connection) void {
        connection.shutting_down = true;
        if (connection.phase != .open) return;
        switch (connection.session) {
            .h2 => connection.session.h2.shutdown(h2.constants.error_no_error),
            .h11 => connection_h11.shutdown(connection),
            .none => {},
        }
    }

    /// Writes what the connection owes the peer into `output`, sealed over TLS, and returns the
    /// octets written. What does not fit waits for the next call.
    pub fn send(connection: *Connection, output: []u8, now_ns: u64) usize {
        // What the protocol owes goes out whether or not this call finds any, the 100 first.
        _ = connection.write_continue();
        _ = connection.write_owed(now_ns);
        if (connection.config.tls != null) return connection_tls.send(connection, output, now_ns);
        const written = @min(output.len, connection.output_len);
        @memcpy(output[0..written], connection.output[0..written]);
        connection.take_output(written);
        return written;
    }

    /// Whether the caller closes the transport now: the connection has finished and `send` has
    /// written everything, over TLS the `close_notify` too (RFC 9846 §6.1).
    pub fn should_close(connection: *const Connection) bool {
        if (connection.output_len > 0) return false;
        return switch (connection.phase) {
            .handshake => false,
            .closed => true,
            .open => connection.finished() and
                (connection.config.tls == null or connection.close_sent or connection.tls_failed()),
        };
    }

    /// The transport closed: the peer closed it, the caller closed it once `should_close` said so,
    /// or it failed. Nothing more is read or written, and over TLS the session's secrets are wiped.
    /// It is idempotent: a second call changes nothing.
    pub fn transport_closed(connection: *Connection) void {
        if (connection.phase == .open and connection.session == .h11) _ = connection.session.h11.transport_closed();
        connection.phase = .closed;
        connection.stopped = true;
        connection.output_len = 0;
        connection.records_len = 0;
        connection.done_owed.clear();
        // chapulin's close wipes every secret, and is safe on a session that closed or failed.
        if (connection.config.tls != null) connection.tls_server.close();
    }

    /// The protocol serving the connection, or null while the TLS handshake runs or after it failed.
    pub fn protocol(connection: *const Connection) ?Protocol {
        return switch (connection.session) {
            .none => null,
            .h11 => .h11,
            .h2 => .h2,
        };
    }

    /// The server_name the client sent over TLS, or null (RFC 9846 §9.2).
    pub fn server_name(connection: *const Connection) ?[]const u8 {
        if (connection.config.tls == null) return null;
        return connection.tls_server.sni();
    }

    /// Whether the connection has nothing more to say but what `output` holds: it failed or was
    /// stopped, its protocol closed, or it was asked to end and no request is open.
    pub fn finished(connection: *const Connection) bool {
        if (connection.phase != .open) return connection.phase == .closed;
        // What the protocol owes, such as h11's error response or h2's GOAWAY, goes out first.
        if (connection.protocol_pending()) return false;
        if (connection.stopped) return true;
        const idle = switch (connection.session) {
            .h2 => connection_h2.idle(connection),
            .h11 => connection_h11.idle(connection),
            // An open connection has a protocol.
            .none => unreachable,
        };
        if (idle and (connection.shutting_down or connection.peer_closed)) return true;
        return switch (connection.session) {
            .h2 => connection.session.h2.has_failed() and !connection.session.h2.has_pending(),
            .h11 => connection.session.h11.should_close(),
            .none => unreachable,
        };
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

    /// Ends the connection on a failure: nothing more is read, and what it owes goes out.
    pub fn fail(connection: *Connection) Error {
        connection.stopped = true;
        // RFC 9113 §5.4.1, RFC 9112 §9.6 and RFC 9846 §6: after a connection error nothing more is
        // read, and the connection closes once what it owes is out.
        return error.ConnectionFailed;
    }

    /// Drops the first `written` octets of `output`, which `send` has taken.
    pub fn take_output(connection: *Connection, written: usize) void {
        assert(written <= connection.output_len);
        std.mem.copyForwards(u8, &connection.output, connection.output[written..connection.output_len]);
        connection.output_len -= written;
        connection.records_len -= @min(connection.records_len, written);
    }

    /// Drops the protocol's octets the last event pointed into.
    pub fn drop_read_plaintext(connection: *Connection) void {
        const read = connection.plain_in_read;
        assert(read <= connection.plain_in_len);
        std.mem.copyForwards(u8, &connection.plain_in, connection.plain_in[read..connection.plain_in_len]);
        connection.plain_in_len -= read;
        connection.plain_in_read = 0;
    }

    /// The room left in `output`.
    pub fn room(connection: *Connection) []u8 {
        return connection.output[connection.output_len..];
    }

    fn check_writable(connection: *const Connection) SendError!void {
        // RFC 9113 §5.4.1 and RFC 9112 §9.6: a connection that failed or closed sends no response.
        if (connection.phase == .closed or connection.stopped) return error.ConnectionClosed;
    }

    /// Whether the protocol owes octets `write_owed` has not written yet.
    fn protocol_pending(connection: *const Connection) bool {
        return switch (connection.session) {
            .h2 => connection.session.h2.has_pending(),
            .h11 => connection.session.h11.has_pending(),
            .none => false,
        };
    }

    fn tls_failed(connection: *const Connection) bool {
        return switch (connection.session) {
            .h2 => connection.session.h2.tls_failed,
            .h11 => connection.session.h11.tls_failed,
            .none => false,
        };
    }
};

test {
    _ = @import("connection_h11_test.zig");
    _ = @import("connection_h2_test.zig");
    _ = @import("connection_tls_test.zig");
    _ = @import("connection_records_test.zig");
    _ = @import("connection_done_test.zig");
}
