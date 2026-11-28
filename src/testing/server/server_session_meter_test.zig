//! The tests of what design §9's server session lends, and of what it asks the engine (decision
//! 176). An h2 stream whose window opens slowly: each step lends what it wrote before it reads
//! again, so the stream's send meter never waits on the output, and the engine cuts the stream at
//! the send rate (decision 110 as amended). Then the calls the session does not make: no read
//! for a socket with no unread bytes, and no lend for an entry that owes nothing. The last tests
//! pass a session whose engine is a stand-in that counts each call: a step passes its unread
//! bytes once, and answers a request that its read of the engine's events reports.
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
        const stepped = test_session.step(0, input, true, now_ns);
        input = input[stepped.consumed..];
        const lent = stepped.lent;
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

test "a step lends the response it wrote, and one with no bytes asks the engine for no read and no lend" {
    test_config = .{ .cpu_features = .none(), .protocols = .{ .h2 = false } };
    try test_session.init(&test_config, .{ .unix_seconds = 0, .monotonic_ns = 0 });
    try testing.expect(test_session.accept(0, false, null, 0));
    @memcpy(test_input[0..get_h11.len], get_h11);
    const answered = test_session.step(0, test_input[0..get_h11.len], true, first_ns);
    try testing.expectEqual(get_h11.len, answered.consumed);
    // The step lent the response it wrote, so the entry owes nothing.
    try testing.expect(std.mem.startsWith(u8, answered.lent, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(!test_session.entries[0].send_owed and !answered.done);
    test_session.sent(0, answered.lent.len, first_ns);
    // At a later instant no deadline is due, and the engine has nothing to report.
    test_session.on_instant(later_ns);
    try testing.expectEqual(@as(?u64, first_ns), asked_ns());
    // The socket has no unread bytes and the entry owes nothing, so the step passes the engine
    // no bytes and asks it for no lend.
    const idle = test_session.step(0, test_input[0..0], true, later_ns);
    try testing.expectEqual(0, idle.consumed + idle.lent.len);
    try testing.expectEqual(@as(?u64, first_ns), asked_ns());
    try testing.expectEqual(null, test_session.next_pending());
    // The connection ends while its entry owes, and the entry's next connection owes nothing.
    test_session.peer_closed(0, later_ns);
    test_session.entries[0].send_owed = true;
    try testing.expect(test_session.accept(0, false, null, later_ns));
    try testing.expect(!test_session.entries[0].send_owed);
}

const get_h11_close = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

test "decision 176 as amended: a step reads the close that its lend brought, and the slot waits for the send" {
    test_config = .{ .cpu_features = .none(), .protocols = .{ .h2 = false } };
    try test_session.init(&test_config, .{ .unix_seconds = 0, .monotonic_ns = 0 });
    try testing.expect(test_session.accept(0, false, null, 0));
    @memcpy(test_input[0..get_h11_close.len], get_h11_close);
    // The socket has a send in flight: the response waits for its lend, and the close with it.
    const held = test_session.step(0, test_input[0..get_h11_close.len], false, first_ns);
    try testing.expect(!held.done and held.lent.len == 0);
    // The send ended: the step lends the response, and reads the close that the lend brought.
    const closing = test_session.step(0, test_input[0..0], true, first_ns);
    try testing.expect(closing.done and std.mem.startsWith(u8, closing.lent, "HTTP/1.1 200 OK\r\n"));
    // The engine holds the lent bytes, and the connection, until the send's count comes back.
    try testing.expect(test_session.entries[0].attached);
    test_session.sent(0, closing.lent.len, first_ns);
    _ = test_session.step(0, test_input[0..0], true, first_ns);
    try testing.expect(!test_session.entries[0].attached);
}

/// The one connection of the stand-in engine, in slot 0. Test-only.
const counted_connection: server.ConnectionHandle = .{ .slot = 0, .generation = 1 };
const counted_events_max = 16;

/// What the stand-in engine lends. Test-only.
const counted_owed = "lent";

/// Stands in for the engine: counts its reads of bytes and its lends, notes the order of its
/// calls, and reports the events a test queued, one a call. It takes the response to request `n`
/// once it has reported `n` events, as an engine takes a response only to a request it has
/// reported. Test-only.
const CountingEngine = struct {
    queued: []const server.Event = &.{},
    reported: u64 = 0,
    stream_reads: usize = 0,
    lends: usize = 0,
    /// The bytes of content the engine has room for: `write_body` takes them, and with none
    /// left it is blocked.
    body_room: usize = std.math.maxInt(usize),
    /// The lends that give bytes. A later one gives none, as a lend for a connection that the
    /// engine closed.
    lends_max: usize = std.math.maxInt(usize),
    /// A letter for each call, in order: `r` a read of bytes, `e` a read of events, `w` a
    /// response's head written, and `l` a lend.
    calls: [counted_calls_max]u8 = undefined,
    calls_len: usize = 0,

    const Input = union(enum) { none, stream: server.StreamBytes };
    const Accepted = struct { tls: bool };

    fn note(engine: *CountingEngine, call: u8) void {
        engine.calls[engine.calls_len] = call;
        engine.calls_len += 1;
    }

    pub fn accept(_: *CountingEngine, _: Accepted, _: u64) ?server.ConnectionHandle {
        return counted_connection;
    }

    pub fn receive(engine: *CountingEngine, input: Input, _: u64, result: *server.ReceiveResult) void {
        result.consumed = 0;
        switch (input) {
            .none => engine.note('e'),
            .stream => |read| {
                engine.note('r');
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
        engine.note('w');
    }

    pub fn write_body(engine: *CountingEngine, _: server.RequestId, content: server.ResponseBody) server.SendError!usize {
        if (engine.body_room == 0) return error.Blocked;
        const taken = @min(content.bytes.len, engine.body_room);
        engine.body_room -= taken;
        return taken;
    }

    pub fn output_stream(engine: *CountingEngine, _: server.ConnectionHandle, _: u64) []const u8 {
        engine.note('l');
        engine.lends += 1;
        return if (engine.lends > engine.lends_max) "" else counted_owed;
    }
};
/// The calls a test's steps make at most. Test-only.
const counted_calls_max = 32;

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
    /// No router, where each response is one of the entry's answers, or the stand-in router.
    routes: union(enum) { none, taking: *TakingRouter } = .none,

    /// The calls the stand-in engine took, a letter each.
    fn calls(session: *const CountingSession) []const u8 {
        return session.engine.calls[0..session.engine.calls_len];
    }
};
/// Stands in for the router: it takes each event of a request, and writes nothing. Test-only.
const TakingRouter = struct {
    pub fn handle(_: *TakingRouter, _: *void, _: *CountingEngine, _: *const server.Event) server.Handled {
        return .taken;
    }
};
var counted: CountingSession align(@alignOf(CountingSession)) = undefined;
var taking_router: TakingRouter align(@alignOf(TakingRouter)) = .{};

/// An event that names the stand-in's connection and asks nothing of the session, which stands
/// for the engine's report of request `number`. Test-only.
fn reported_event(number: u64) server.Event {
    return .{ .writable = .{ .id = .{ .connection = counted_connection, .number = number }, .user_data = 0 } };
}
const one_event = [_]server.Event{reported_event(1)};
const two_events = [_]server.Event{ reported_event(1), reported_event(1 + 1) };
/// The `finished` of a response the stand-in's connection wrote whole. Test-only.
const finished_event = [_]server.Event{.{ .finished = .{ .id = .{ .connection = counted_connection, .number = 1 }, .user_data = 0, .result = .sent } }};

/// A session over the stand-in engine, whose entry holds a cleartext connection and owes a
/// response to each of the requests 1 to `owed`. Test-only.
fn counted_session(owed: u32) !*CountingSession {
    return counted_session_over(owed, false);
}

/// The same session, whose connection runs TLS when `tls` says so. Test-only.
fn counted_session_over(owed: u32, tls: bool) !*CountingSession {
    counted = .{};
    counted.entries[0].attached = false;
    try testing.expect(session_module.accept_into(&counted, 0, tls, null, 0));
    const answers = &counted.entries[0].answers;
    for (0..owed) |index| answers.owed[index] = .{ .number = index + 1, .head = false, .connect = false };
    answers.owed_count = owed;
    return &counted;
}

test "a step passes its unread bytes to the engine once, and none when it has none" {
    const session = try counted_session(0);
    const stepped = session_module.step_entry(session, 0, test_input[0..input_len], true, 0);
    try testing.expectEqual(input_len, stepped.consumed);
    try testing.expectEqual(1, session.engine.stream_reads);
    _ = session_module.step_entry(session, 0, test_input[0..0], true, 0);
    try testing.expectEqual(1, session.engine.stream_reads);
    // No response was written and the engine reported no `send`: the entry asked for no lend.
    try testing.expectEqual(0, session.engine.lends);
}

test "design §8 step 80: a step lends the response it wrote before it reads the engine's events" {
    const session = try counted_session(1);
    session.engine.queued = &one_event;
    const stepped = session_module.step_entry(session, 0, test_input[0..input_len], true, 0);
    // The read reported the request, the response was written and lent, and the events came last.
    try testing.expectEqualStrings("rwle", session.calls()[0..4]);
    try testing.expectEqualStrings(counted_owed, stepped.lent);
    try testing.expectEqual(1, session.engine.lends);
    try testing.expect(!session.entries[0].send_owed and !session.pending.isSet(0));
}

test "design §8 step 80: each part of a response that the engine took is lent in its step" {
    // A response to HEAD is its head alone.
    const head_only = try counted_session(1);
    head_only.entries[0].answers.owed[0].head = true;
    head_only.engine.queued = &one_event;
    _ = session_module.step_entry(head_only, 0, test_input[0..input_len], true, 0);
    try testing.expectEqualStrings("rwle", head_only.calls()[0..4]);
    // The engine takes the head and one byte of the content, and the step lends them.
    const session = try counted_session(1);
    session.engine.queued = &one_event;
    session.engine.body_room = 1;
    _ = session_module.step_entry(session, 0, test_input[0..input_len], true, 0);
    try testing.expectEqual(1, session.engine.lends);
    try testing.expectEqual(1, session.entries[0].answers.owed_count);
    // The next step writes content alone, and lends it too.
    session.engine.body_room = std.math.maxInt(usize);
    _ = session_module.step_entry(session, 0, test_input[0..0], true, 0);
    try testing.expectEqual(0, session.entries[0].answers.owed_count);
    try testing.expectEqual(1 + 1, session.engine.lends);
}

test "decision 176: a socket with a send in flight takes no lend, and its entry stays owing" {
    const session = try counted_session(1);
    session.engine.queued = &one_event;
    const held = session_module.step_entry(session, 0, test_input[0..input_len], false, 0);
    try testing.expectEqual(0, held.lent.len + session.engine.lends);
    try testing.expect(session.entries[0].send_owed);
    // The send ended: the next step lends what the entry owes.
    const stepped = session_module.step_entry(session, 0, test_input[0..0], true, 0);
    try testing.expectEqualStrings(counted_owed, stepped.lent);
    try testing.expectEqual(1, session.engine.lends);
}

test "decision 119 as amended: over TLS a step lends once, after its last pass" {
    // The read reports the first request, and the engine holds the second for its events.
    const session = try counted_session_over(two_events.len, true);
    session.engine.queued = &two_events;
    const stepped = session_module.step_entry(session, 0, test_input[0..input_len], true, 0);
    // Both responses were written before the one lend, which seals them into one record.
    try testing.expectEqualStrings("rweeweel", session.calls());
    try testing.expectEqualStrings(counted_owed, stepped.lent);
    // In cleartext a response is lent as soon as it is written, before the events are read.
    const cleartext = try counted_session(two_events.len);
    cleartext.engine.queued = &two_events;
    _ = session_module.step_entry(cleartext, 0, test_input[0..input_len], true, 0);
    try testing.expectEqualStrings("rwleewlee", cleartext.calls());
    try testing.expectEqual(two_events.len, cleartext.engine.lends);
    // A second lend that gives nothing leaves the socket what the first one gave.
    const closed = try counted_session(two_events.len);
    closed.engine.queued = &two_events;
    closed.engine.lends_max = 1;
    const kept = session_module.step_entry(closed, 0, test_input[0..input_len], true, 0);
    try testing.expectEqual(two_events.len, closed.engine.lends);
    try testing.expectEqualStrings(counted_owed, kept.lent);
    // A TLS entry whose socket has a send in flight lends nothing, and stays owing.
    const held = try counted_session_over(1, true);
    held.engine.queued = &one_event;
    _ = session_module.step_entry(held, 0, test_input[0..input_len], false, 0);
    try testing.expect(held.engine.lends == 0 and held.entries[0].send_owed);
}

test "design §8 step 80: an entry may owe after an event that the router may write at" {
    const session = try counted_session(0);
    session.routes = .{ .taking = &taking_router };
    session.engine.queued = &one_event;
    _ = session_module.step_entry(session, 0, test_input[0..input_len], true, 0);
    // The router may have written more of a response at its `writable`, so the step asked for
    // a lend.
    try testing.expectEqual(1, session.engine.lends);
    // The `finished` of a response brings no bytes.
    session.engine.queued = &finished_event;
    _ = session_module.step_entry(session, 0, test_input[0..0], true, 0);
    try testing.expectEqual(1, session.engine.lends);
}

test "design §8 step 80: the router may write at the end of a request and at a writable" {
    const writes = session_module.router_writes;
    var head: server.Request = undefined;
    head.end = false;
    try testing.expect(!writes(&.{ .request = head }));
    head.end = true;
    try testing.expect(writes(&.{ .request = head }));
    const id: server.RequestId = .{ .connection = counted_connection, .number = 1 };
    try testing.expect(!writes(&.{ .body = .{ .id = id, .bytes = "", .end = false } }));
    try testing.expect(writes(&.{ .body = .{ .id = id, .bytes = "", .end = true } }));
    try testing.expect(writes(&.{ .trailers = undefined }));
    try testing.expect(writes(&one_event[0]) and !writes(&finished_event[0]));
    try testing.expect(!writes(&.{ .send = counted_connection }));
}

test "a request that a step's read of the engine's events reports is answered in that step" {
    // Over TLS the engine may hold a request of a record after it consumed the record's bytes,
    // and reports it with its events.
    const session = try counted_session(1);
    session.engine.queued = &one_event;
    _ = session_module.step_entry(session, 0, test_input[0..0], true, 0);
    try testing.expectEqual(0, session.engine.stream_reads);
    // The response waited for the event, and the pass after the read wrote it.
    try testing.expectEqual(0, session.entries[0].answers.owed_count);
    try testing.expect(!session.pending.isSet(0));
}
