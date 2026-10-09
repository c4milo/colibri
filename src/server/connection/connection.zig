//! One connection of the server over TCP (decision 100, design §8 step 17a). The octets the caller
//! read go in through `receive`, which returns at most one event a call, and the octets the
//! connection owes the peer come out through `send`. The caller answers a request by its id with
//! `respond`, `write_body` and `write_trailers`, in h11 and h2 alike.
//!
//! Over TLS, `receive` runs the handshake through `tls.record.Server`, and the protocol ALPN
//! selected serves the connection: h2 for "h2" (RFC 9113 §3.2), and h11 for "http/1.1" or for no
//! selection (decision 88). In cleartext, the connection speaks the version `Config.versions`
//! allows. When it allows both h11 and h2, the connection preface chooses h2 and any other first
//! octets h11 (RFC 9113 §3.3, `connection_cleartext.zig`).
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
//!
//! Decision 110's deadlines bound how long a peer holds the connection: `deadline_ns` names the
//! soonest instant one passes, and the caller wakes then and calls `on_instant`. `receive` and
//! `send` end the connection first when their instant is past a deadline. A deadline counts only
//! what colibri has seen, so the caller hands `receive` every octet its socket holds and calls
//! `send` whenever its socket takes octets, before it calls `on_instant`. `close_reason` names the
//! deadline that ended the connection, or the limit its peer passed, and `set_deadlines` changes
//! one connection's limits.
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
const connection_errors = @import("connection_errors.zig");
const connection_coding = @import("connection_coding.zig");
const connection_config = @import("connection_config.zig");
const coding_pool = @import("../coding/coding_pool.zig");
const connection_continue = @import("connection_continue.zig");
const connection_deadline = @import("connection_deadline.zig");
const connection_bodies = @import("connection_bodies.zig");
const connection_sends = @import("connection_sends.zig");
const connection_events = @import("connection_events.zig");
const connection_close = @import("connection_close.zig");
const connection_cleartext = @import("connection_cleartext.zig");
const internal = @import("connection_internal.zig");
const versions_module = @import("../versions.zig");
const deadline = @import("../deadline.zig");
const close_reason_module = @import("../close_reason.zig");
const done = @import("../done.zig");
const alt_svc = @import("../alt_svc.zig");

pub const Id = event.Id;
pub const Protocol = event.Protocol;
pub const Event = event.Event;
pub const Received = event.Received;
pub const Field = http.Field;
pub const Deadline = deadline.Deadline;
pub const Deadlines = deadline.Deadlines;
pub const CloseReason = close_reason_module.CloseReason;

pub const Config = connection_config.Config;

pub const Error = connection_errors.Error;
pub const StartError = connection_errors.StartError;
pub const SendError = connection_errors.SendError;

/// RFC 9110 §15.2.1: 100 (Continue).
const continue_status: u16 = @intFromEnum(http.status.Code.@"continue");

const Phase = enum {
    /// The TLS handshake has not completed.
    handshake,
    /// In cleartext, the first octets have not chosen between h11 and h2 (RFC 9113 §3.3).
    choosing,
    /// The protocol is serving the connection.
    open,
    /// Nothing more is read.
    closed,
};

pub const Session = union(enum) {
    /// No protocol serves the connection: its TLS handshake has not completed or failed, or in
    /// cleartext its first octets have not chosen one.
    none,
    h11: h11.Connection,
    h2: h2.Connection,
};

pub const Connection = struct {
    config: *const Config,
    phase: Phase,
    /// The protocol serving the connection: in cleartext from the start or once the first octets
    /// chose it, and over TLS once the handshake completes.
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
    /// h2: the octets at the front of `output` that go out before the last WINDOW_UPDATE written
    /// into it has gone. While any remain, a body's rate deadline waits (decision 110 as amended).
    update_held_len: usize,
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
    /// The Alt-Svc value the connection advertises h3 with, if any.
    advert: alt_svc.Advert,
    /// The requests whose responses may be coded, and the coded responses (decision 101).
    coding: connection_coding.Table,
    /// This connection's limits and where its deadlines stand (decision 110).
    deadlines: Deadlines,
    clock: connection_deadline.Clock,
    bodies: connection_bodies.Bodies,
    sends: connection_sends.Sends,

    /// Prepares a connection the listener accepted at `now_ns`, with nothing read or written. Over
    /// TLS, every draw the handshake makes comes from `random`, and `now_seconds` is the clock its
    /// tickets are issued at, or 0 for none.
    pub fn init(connection: *Connection, config: *const Config, random: tls.Random, now_seconds: u64, now_ns: u64) StartError!void {
        // RFC 9114 §3.1: a TCP connection speaks h11 or h2, never h3, so `versions` allows one.
        const choice = versions_module.tcp_choice(config.versions) orelse return error.NoVersion;
        assert((config.codings.len == 0) == (config.encoders == null));
        for (config.codings) |coding| assert(coding_pool.encodes(coding));
        assert(config.limits.data_frame_len_min <= h2.constants.max_frame_size_initial);
        assert(config.limits.requests_max > 0 and config.limits.requests_max <= h2.constants.concurrent_streams_max);
        try config.deadlines.validate();
        if (connection_config.whole_units(config)) try config.deadlines.validate_units();
        connection.deadlines = config.deadlines;
        connection.clock = .init(now_ns);
        connection.bodies.init();
        connection.sends.init();
        connection.config = config;
        connection.plain_in_len = 0;
        connection.plain_in_read = 0;
        connection.output_len = 0;
        connection.records_len = 0;
        connection.update_held_len = 0;
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
        connection.advert.init(config.tls != null, config.h3_alternative);
        connection.coding.init();
        connection.session = .none;
        if (config.tls) |tls_config| {
            connection.phase = .handshake;
            // RFC 9846 §9.2: chapulin refuses values it cannot serve a handshake from.
            connection.tls_server.start(tls_config, random, now_seconds) catch return error.TlsRefused;
        } else switch (choice) {
            .speak => |chosen| internal.open_session(connection, chosen),
            .read_preface => connection.phase = .choosing,
        }
        assert(connection.output_len == 0 and connection.plain_in_len == 0);
    }

    /// Reads at most one event from `input`, the octets the transport read. Over TLS it runs the
    /// handshake first, and `input` is records, which chapulin may open in place. A deadline that
    /// has passed at `now_ns` ends the connection first (decision 110).
    pub fn receive(connection: *Connection, input: []u8, now_ns: u64) Error!Received {
        _ = connection_deadline.fire(connection, now_ns);
        const received = try connection.receive_event(input, now_ns);
        connection_deadline.observe(connection, now_ns);
        return received;
    }

    fn receive_event(connection: *Connection, input: []u8, now_ns: u64) Error!Received {
        // RFC 9110 §10.1.1: the 100 goes out before the server waits for the content.
        if (!connection_continue.write(connection)) return .{ .consumed = 0, .event = null };
        // Decision 103: a response made whole since the last call is reported before anything
        // more is read, so no request arrives while one is owed.
        if (connection.done_owed.take()) |id| return .{ .consumed = 0, .event = .{ .done = .{ .id = id } } };
        // Decision 110: a request an h2 body deadline ended is reported the same way.
        if (connection_bodies.take_cancelled(connection)) |cancelled| return .{ .consumed = 0, .event = .{ .cancelled = cancelled } };
        const received = try switch (connection.phase) {
            .closed => Received{ .consumed = 0, .event = null },
            .handshake => connection_tls.handshake(connection, input, now_ns),
            .choosing => connection_cleartext.choose(connection, input, now_ns),
            .open => if (connection.config.tls == null)
                internal.read_protocol(connection, input, now_ns)
            else
                connection_tls.read(connection, input, now_ns),
        };
        if (received.event) |reported| connection_events.note(connection, reported);
        return received;
    }

    /// Writes the head of the response to request `id`: an interim one (1xx) or the final one.
    /// With `end`, the final response carries no content. A final response marked `codable` goes
    /// out as decision 101 has it (`connection_coding.zig`).
    pub fn respond(connection: *Connection, id: Id, response: event.Response) SendError!void {
        try connection.check_writable();
        // RFC 9110 §10.1.1: the caller's own 100 replaces the one owed. A final response replaces
        // it too: the protocol refuses a 100 after it, and `write_continue` drops the one owed.
        if (connection.continue_owed == id and response.status == continue_status) connection.continue_owed = null;
        return connection_coding.respond(connection, id, response);
    }

    /// Writes content of the response to request `id`, as much of `content.octets` as the room
    /// and h2's windows allow, or for a coded response as much as its encoder's ring takes, and
    /// returns the octets taken. With `end`, the content ends once every octet is taken; a call
    /// that takes fewer leaves the rest, and the end, to the next call. A coded response's last
    /// octets go out in `send`.
    pub fn write_body(connection: *Connection, id: Id, content: event.Content) SendError!usize {
        try connection.check_writable();
        if (content.octets.len == 0 and !content.end) return 0;
        return connection_coding.write_body(connection, id, content);
    }

    /// Ends the response to request `id` with a trailer section (RFC 9110 §6.5). A coded
    /// response's trailer section waits, with `error.Blocked`, until its coded octets are written.
    pub fn write_trailers(connection: *Connection, id: Id, fields: []const Field) SendError!void {
        try connection.check_writable();
        return connection_coding.write_trailers(connection, id, fields);
    }

    /// Ends request `id` before its response is whole: h2 resets its stream with CANCEL (RFC
    /// 9113 §6.4), and h11, which cannot end one request alone, ends the connection.
    pub fn cancel(connection: *Connection, id: Id) void {
        if (connection.phase != .open) return;
        connection_coding.forget(connection, id);
        connection_bodies.remove(connection, id);
        connection_sends.remove(connection, id);
        switch (connection.session) {
            .h2 => connection_h2.cancel(connection, id),
            .h11 => connection_h11.cancel(connection, id),
            .none => {},
        }
    }

    /// Ends the connection once the requests it holds are answered: h2 sends GOAWAY (RFC 9113
    /// §6.8), and h11 closes after the current response (RFC 9112 §9.6). A connection whose
    /// protocol is not open yet holds no request: in cleartext it ends at once, and over TLS the
    /// protocol the handshake opens takes the shutdown then (`internal.open_session`).
    pub fn shutdown(connection: *Connection) void {
        connection.shutting_down = true;
        switch (connection.phase) {
            .open => internal.shut_session(connection),
            // As an idle h11 connection does, one that has said nothing and holds no request ends
            // at once.
            .choosing => {
                connection.phase = .closed;
                connection.stopped = true;
            },
            .handshake, .closed => {},
        }
    }

    /// Writes what the connection owes the peer into `output`, sealed over TLS, and returns the
    /// octets written. What does not fit waits for the next call. A deadline that has passed at
    /// `now_ns` ends the connection first (decision 110).
    pub fn send(connection: *Connection, output: []u8, now_ns: u64) usize {
        _ = connection_deadline.fire(connection, now_ns);
        const written = connection.send_owed(output, now_ns);
        connection_sends.count(connection, written);
        connection_deadline.observe(connection, now_ns);
        return written;
    }

    fn send_owed(connection: *Connection, output: []u8, now_ns: u64) usize {
        // What the protocol owes goes out whether or not this call finds any, the 100 first, and
        // then what the coded responses' rings hold.
        _ = connection_continue.write(connection);
        _ = internal.write_owed(connection, now_ns);
        connection_coding.drain(connection);
        if (connection.config.tls != null) return connection_tls.send(connection, output, now_ns);
        const written = @min(output.len, connection.output_len);
        @memcpy(output[0..written], connection.output[0..written]);
        internal.take_output(connection, written);
        return written;
    }

    /// The soonest instant one of decision 110's deadlines passes, or null when none runs. The
    /// caller wakes then and calls `on_instant`, and asks again after each `receive` and `send`.
    pub fn deadline_ns(connection: *const Connection) ?u64 {
        return connection_deadline.soonest(connection);
    }

    /// Ends the connection when a deadline has passed at `now_ns` (decision 110). What it then owes
    /// the peer waits for `send`, and `should_close` says when to close.
    pub fn on_instant(connection: *Connection, now_ns: u64) void {
        _ = connection_deadline.fire(connection, now_ns);
        connection_deadline.observe(connection, now_ns);
    }

    /// Replaces this connection's limits (decision 110), for a caller short of connections that
    /// shortens its deadlines. It refuses what `init` refuses. A deadline that has started keeps
    /// its start.
    pub fn set_deadlines(connection: *Connection, deadlines: Deadlines) error{DeadlineInvalid}!void {
        try deadlines.validate();
        if (internal.whole_units(connection)) try deadlines.validate_units();
        connection.deadlines = deadlines;
    }

    /// Why colibri closed the connection on its own: the deadline that passed, or the limit the
    /// peer passed. Null while the connection runs, and after any other end.
    pub fn close_reason(connection: *const Connection) ?CloseReason {
        return connection_close.close_reason(connection);
    }

    /// Whether the caller closes the transport now: the connection has finished and `send` has
    /// written everything, over TLS the `close_notify` too (RFC 9846 §6.1), or the alert of a
    /// failure, or its linger has passed (`connection_close.zig`).
    pub fn should_close(connection: *const Connection) bool {
        return connection_close.should_close(connection);
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
        connection.update_held_len = 0;
        connection.done_owed.clear();
        connection_coding.forget_all(connection);
        // chapulin's close wipes every secret, and is safe on a session that closed or failed.
        if (connection.config.tls != null) connection.tls_server.close();
    }

    /// The protocol serving the connection, or null while the TLS handshake runs or after it failed,
    /// and in cleartext until the first octets choose it.
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

    fn check_writable(connection: *const Connection) SendError!void {
        // RFC 9113 §5.4.1 and RFC 9112 §9.6: a connection that failed or closed sends no response.
        if (connection.phase == .closed or connection.stopped) return error.ConnectionClosed;
    }
};

test "design §8 step 17f: the connection's public functions are the calls a program makes" {
    // What the connection's own files call on it lives in `connection_internal.zig`, which the
    // module does not export. A function added here is one every program can call.
    const public_names = @import("core").public_names;
    try public_names.expect(Connection, &.{
        "init",          "receive",      "respond",      "write_body",       "write_trailers",
        "cancel",        "shutdown",     "send",         "deadline_ns",      "on_instant",
        "set_deadlines", "close_reason", "should_close", "transport_closed", "protocol",
        "server_name",
    });
}

test {
    _ = @import("connection_cleartext.zig");
    _ = @import("connection_cleartext_test.zig");
    _ = @import("connection_h11_test.zig");
    _ = @import("connection_h2_test.zig");
    _ = @import("connection_tls_test.zig");
    _ = @import("connection_records_test.zig");
    _ = @import("connection_done_test.zig");
    _ = @import("connection_altsvc_test.zig");
    _ = @import("connection_coding_h11_test.zig");
    _ = @import("connection_coding_h2_test.zig");
    _ = @import("connection_deadline_test.zig");
    _ = @import("connection_bodies_test.zig");
    _ = @import("connection_sends_test.zig");
}
