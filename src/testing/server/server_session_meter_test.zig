//! The tests of what design §9's server session lends, and of what it asks the engine (decision
//! 176). An h2 stream whose window opens slowly: each step lends what it wrote before it reads
//! again, so the stream's send meter never waits on the output, and the engine cuts the stream at
//! the send rate (decision 110 as amended). Then the call a step does not make: no read for a
//! socket with no unread bytes. The last tests pass a session whose engine is a stand-in that
//! counts each call: a step passes its unread bytes once, and answers a request that its read of
//! the engine's events reports.
const std = @import("std");
const server = @import("server");
const h2 = @import("h2");
const session_module = @import("server_session.zig");
const server_mode = @import("server_mode.zig");

const testing = std.testing;
/// A session of one entry. Test-only.
const Session = session_module.Session(1);

/// The session, its configuration and its buffers, outside any stack frame. Test-only.
var test_session: Session align(@alignOf(Session)) = undefined;
var test_config: server.Config align(@alignOf(server.Config)) = .{ .cpu_features = .none() };
var test_input: [input_len]u8 = undefined;
const input_len = 256;
/// What the socket sent: each lend whole, as a socket whose sends complete at once. Test-only.
var test_sent: [sent_len_max]u8 = undefined;
var sent_len: usize = 0;
const sent_len_max = 65_536;

/// The client preface with a SETTINGS_INITIAL_WINDOW_SIZE (0x4) of 0, so a stream's window opens
/// by WINDOW_UPDATE alone (RFC 9113 §6.9.2), then the acknowledgment of the server's SETTINGS.
const preface_no_window = h2.constants.protocol.client_preface ++ "\x00\x00\x06\x04\x00\x00\x00\x00\x00" ++
    "\x00\x04\x00\x00\x00\x00" ++ "\x00\x00\x00\x04\x01\x00\x00\x00\x00";
/// A HEADERS frame on stream 1 ending it, whose block is the static table's `:method: GET`,
/// `:scheme: http` and `:path: /` (RFC 7541 §6.1, Appendix A).
const get_frame = "\x00\x00\x03\x01\x05\x00\x00\x00\x01" ++ "\x82\x86\x84";
/// A WINDOW_UPDATE of one byte on stream 1 (RFC 9113 §6.9).
const window_update = "\x00\x00\x04\x08\x00\x00\x00\x00\x01" ++ "\x00\x00\x00\x01";
/// A RST_STREAM on stream 1 with CANCEL, 0x8 (RFC 9113 §6.4, §7).
const reset_cancel = "\x00\x00\x04\x03\x00\x00\x00\x00\x01" ++ "\x00\x00\x00\x08";
/// The seconds the peer opens its window for at most: past decision 110's default grace period
/// and window, 10 s each. The answer is longer than one byte for each of them.
const seconds_max: u64 = 40;
const body_len: u32 = 1024;

/// Steps the entry over `octets` at `now_ns`. Each lend goes out whole, and the entry is stepped
/// again until it lends nothing. Test-only.
fn step_at(octets: []const u8, now_ns: u64) void {
    @memcpy(test_input[0..octets.len], octets);
    var input: []u8 = test_input[0..octets.len];
    // Bounded: each pass sends a lend, or ends the loop.
    for (0..input_len) |_| {
        input = input[test_session.step(0, input, now_ns).consumed..];
        const lent = test_session.lend(0);
        @memcpy(test_sent[sent_len..][0..lent.len], lent);
        sent_len += lent.len;
        if (lent.len == 0) return;
        test_session.sent(0, lent.len, now_ns);
    }
}

test "decision 110 as amended: an h2 stream whose window opens an octet a second is cut at the send rate" {
    server_mode.set_answer_body(body_len);
    defer server_mode.reset_answer_body();
    test_config = .{ .cpu_features = .none(), .protocols = .{ .h11 = false } };
    try test_session.init(&test_config, .{ .unix_seconds = 0, .monotonic_ns = 0 });
    try testing.expect(test_session.accept(0, false, null, 0));
    sent_len = 0;
    step_at(preface_no_window, 0);
    step_at(get_frame, 0);
    try testing.expectEqual(1, test_session.entries[0].answers.owed_count);
    for (1..seconds_max) |second| {
        const now_ns = second * server.constants.nanoseconds_per_second;
        test_session.on_instant(now_ns);
        step_at("", now_ns);
        if (test_session.entries[0].answers.owed_count == 0) break;
        step_at(window_update, now_ns);
    }
    // The engine reset the stream, and the session forgot its answer.
    try testing.expectEqual(0, test_session.entries[0].answers.owed_count);
    try testing.expect(std.mem.indexOf(u8, test_sent[0..sent_len], reset_cancel) != null);
}

const get_h11 = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
/// The instants of the h11 test's calls. Test-only.
const first_ns: u64 = 1_000;
const later_ns: u64 = 2_000;

/// The instant the entry's connection last checked its deadlines at: each call the engine makes
/// on the connection at a new instant moves it. Test-only.
fn asked_ns() ?u64 {
    return test_session.engine.tcp[test_session.entries[0].handle.slot].clock.checked_ns;
}

test "a step with no unread bytes passes the engine no read" {
    test_config = .{ .cpu_features = .none(), .protocols = .{ .h2 = false } };
    try test_session.init(&test_config, .{ .unix_seconds = 0, .monotonic_ns = 0 });
    try testing.expect(test_session.accept(0, false, null, 0));
    @memcpy(test_input[0..get_h11.len], get_h11);
    try testing.expectEqual(get_h11.len, test_session.step(0, test_input[0..get_h11.len], first_ns).consumed);
    const lent = test_session.lend(0);
    try testing.expect(std.mem.startsWith(u8, lent, "HTTP/1.1 200 OK\r\n"));
    test_session.sent(0, lent.len, first_ns);
    // The step after the send reads what the engine reports of it, at the same instant.
    try testing.expectEqual(0, test_session.step(0, test_input[0..0], first_ns).consumed);
    try testing.expectEqual(@as(?u64, first_ns), asked_ns());
    // At a later instant no deadline is due, and the engine has nothing to report.
    test_session.on_instant(later_ns);
    try testing.expectEqual(@as(?u64, first_ns), asked_ns());
    // The socket has no unread bytes, so the step passes the engine none.
    try testing.expectEqual(0, test_session.step(0, test_input[0..0], later_ns).consumed);
    try testing.expectEqual(@as(?u64, first_ns), asked_ns());
    try testing.expectEqual(null, test_session.next_pending());
}

/// The one connection of the stand-in engine, in slot 0. Test-only.
const counted_connection: server.ConnectionHandle = .{ .slot = 0, .generation = 1 };
const counted_events_max = 16;

/// Stands in for the engine: counts its reads of bytes, and reports the events a test queued, one
/// a call. It takes the response to request `n` once it has reported `n` events, as an engine
/// takes a response only to a request it has reported. Test-only.
const CountingEngine = struct {
    queued: []const server.Event = &.{},
    reported: u64 = 0,
    stream_reads: usize = 0,

    const Input = union(enum) { none, stream: server.StreamBytes };
    const Accepted = struct { tls: bool };

    pub fn accept(_: *CountingEngine, _: Accepted, _: u64) ?server.ConnectionHandle {
        return counted_connection;
    }

    pub fn receive(engine: *CountingEngine, input: Input, _: u64, result: *server.ReceiveResult) void {
        result.consumed = 0;
        switch (input) {
            .none => {},
            .stream => |read| {
                engine.stream_reads += 1;
                result.consumed = read.bytes.len;
            },
        }
        result.event = null;
        if (engine.queued.len == 0) return;
        result.event = engine.queued[0];
        engine.queued = engine.queued[1..];
        engine.reported += 1;
    }

    pub fn respond(engine: *CountingEngine, id: server.RequestId, _: server.ResponseHeader) server.SendError!void {
        if (id.number > engine.reported) return error.Blocked;
    }

    pub fn write_body(_: *CountingEngine, _: server.RequestId, content: server.ResponseBody) server.SendError!usize {
        return content.bytes.len;
    }
};

/// What a step reads of a session, over the stand-in engine. Test-only.
const CountingSession = struct {
    engine: CountingEngine = .{},
    entries: [1]session_module.Entry = undefined,
    entry_of: [1]?u32 = .{null},
    pending: std.bit_set.IntegerBitSet(1) = .initEmpty(),
    undrained: bool = false,
    events_max: usize = counted_events_max,
    now_ns: u64 = 0,
    received: server.ReceiveResult = .{ .consumed = 0, .event = null },
    /// No router: each response is one of the entry's answers.
    routes: union(enum) { none, unused: *UnusedRouter } = .none,
};
/// The router a session's event handler compiles against, which no test names. Test-only.
const UnusedRouter = struct {
    pub fn handle(_: *UnusedRouter, _: *void, _: *CountingEngine, _: *const server.Event) server.Handled {
        return .taken;
    }
};
var counted: CountingSession align(@alignOf(CountingSession)) = undefined;

/// An event that names the stand-in's connection and asks nothing of the session, which stands
/// for the engine's report of request `number`. Test-only.
fn reported_event(number: u64) server.Event {
    return .{ .writable = .{ .id = .{ .connection = counted_connection, .number = number }, .user_data = 0 } };
}
const one_event = [_]server.Event{reported_event(1)};

/// A session over the stand-in engine, whose entry holds a connection and owes a response to
/// each of the requests 1 to `owed`. Test-only.
fn counted_session(owed: u32) !*CountingSession {
    counted = .{};
    counted.entries[0].attached = false;
    try testing.expect(session_module.accept_into(&counted, 0, false, null, 0));
    const answers = &counted.entries[0].answers;
    for (0..owed) |index| answers.owed[index] = .{ .number = index + 1, .head = false, .connect = false };
    answers.owed_count = owed;
    return &counted;
}

test "a step passes its unread bytes to the engine once, and none when it has none" {
    const session = try counted_session(0);
    const stepped = session_module.step_entry(session, 0, test_input[0..input_len], 0);
    try testing.expectEqual(input_len, stepped.consumed);
    try testing.expectEqual(1, session.engine.stream_reads);
    _ = session_module.step_entry(session, 0, test_input[0..0], 0);
    try testing.expectEqual(1, session.engine.stream_reads);
}

test "a request that a step's read of the engine's events reports is answered in that step" {
    // Over TLS the engine may hold a request of a record after it consumed the record's bytes,
    // and reports it with its events.
    const session = try counted_session(1);
    session.engine.queued = &one_event;
    _ = session_module.step_entry(session, 0, test_input[0..0], 0);
    try testing.expectEqual(0, session.engine.stream_reads);
    // The response waited for the event, and the pass after the read wrote it.
    try testing.expectEqual(0, session.entries[0].answers.owed_count);
    try testing.expect(!session.pending.isSet(0));
}
