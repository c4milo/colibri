//! The tests of a TCP socket that sends from its connection's output (decision 176, design §8
//! steps 79 and 80): `output_stream` lends the bytes where the engine holds them, they stay in
//! place until `sent_stream`, and the slot of a closed socket ends only after that call. Bytes
//! that a lend gave the socket are out, so a connection's `close` comes with the lend of its
//! last bytes. Over TLS the bytes are sealed records, and a `send_stream` after a partial send
//! copies the records left first.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const support = @import("engine_tcp_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");

const testing = std.testing;
const engine = &support.engine;

const ok: http.Status = .ok;
/// A request h11 keeps the connection open after, and one it closes after.
const get_kept = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
const get_closed = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

/// How much later the send of a test ends than its lend.
const later_ns: u64 = 1_000_000;
/// The bytes the transport of one slot carries in a test.
const carried_max = support.sent[0].len;
/// A copy of what a lend held, made before the bytes move.
threadlocal var saved: [carried_max]u8 = undefined;

/// Sends `sent` bytes of what the connection lends, as a socket's send takes them: they join what
/// the transport carried, and `sent_stream` returns the count. Returns the bytes lent.
fn send_lent(handle: event.ConnectionHandle, sent: usize) []const u8 {
    const lent = engine.output_stream(handle, support.now_ns);
    send_whole(handle, lent[0..@min(sent, lent.len)]);
    return lent;
}

/// Sends `taken`, the front of what a lend gave, as a socket's send that ends now: the bytes join
/// what the transport carried, and `sent_stream` returns their count.
fn send_whole(handle: event.ConnectionHandle, taken: []const u8) void {
    const slot = handle.slot;
    @memcpy(support.sent[slot][support.sent_len[slot]..][0..taken.len], taken);
    support.sent_len[slot] += taken.len;
    engine.sent_stream(handle, taken.len, support.now_ns);
}

/// Answers request `id` with a 200 and the body "body".
fn answer(id: event.RequestId) !void {
    try engine.respond(id, .{ .status = ok, .end = false });
    _ = try engine.write_body(id, .{ .bytes = "body", .end = true });
}

/// How many `send` events the engine reported.
fn sends() usize {
    var count: usize = 0;
    while (support.nth(.send, count) != null) count += 1;
    return count;
}

/// A cleartext h2 connection that read the client's preface and an open request on stream 1, with
/// every byte it owed before the request sent. A `send` then lends nothing by itself.
fn start_h2() !event.ConnectionHandle {
    try support.start(null, .{});
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    _ = support.give(handle, h2_support.client_preface);
    _ = support.give(handle, try h2_support.request_frame(1, "/", true));
    try testing.expectEqual(1, support.nth(.request, 0).?.number);
    support.flushing = false;
    return handle;
}

test "decision 176: output_stream lends the octets in place, and sent_stream drops what a send took" {
    const handle = try start_h2();
    const id = support.id_of(handle, 1);
    try engine.respond(id, .{ .status = ok, .end = false });
    _ = try engine.write_body(id, .{ .bytes = "first", .end = false });
    const lent = engine.output_stream(handle, support.now_ns);
    try testing.expect(std.mem.endsWith(u8, lent, "first"));
    @memcpy(saved[0..lent.len], lent);
    // While a send reads the bytes, the connection writes after them and moves none.
    _ = try engine.write_body(id, .{ .bytes = "second", .end = true });
    try testing.expectEqualSlices(u8, saved[0..lent.len], lent);
    // A send that took three bytes: the rest moves to the front, and the bytes written while
    // it ran follow.
    engine.sent_stream(handle, 3, support.now_ns);
    const rest = engine.output_stream(handle, support.now_ns);
    try testing.expectEqual(@intFromPtr(lent.ptr), @intFromPtr(rest.ptr));
    try testing.expectEqualSlices(u8, saved[3..lent.len], rest[0 .. lent.len - 3]);
    try testing.expect(std.mem.endsWith(u8, rest, "second"));
    engine.sent_stream(handle, rest.len, support.now_ns);
    try testing.expectEqual(0, engine.output_stream(handle, support.now_ns).len);
    engine.sent_stream(handle, 0, support.now_ns);
}

test "decision 176: a lent output and a copy send the same octets" {
    // The same request on two connections: one copies its response out, and one lends it.
    try support.start(null, .{});
    const copied = engine.accept(.{ .tls = false }, support.now_ns).?;
    _ = support.give(copied, get_kept);
    const lent = engine.accept(.{ .tls = false }, support.now_ns).?;
    support.flushing = false;
    _ = support.give(lent, get_kept);
    try answer(support.id_of(copied, support.nth(.request, 0).?.number));
    try answer(support.id_of(lent, support.nth(.request, 1).?.number));
    support.flush(copied);
    _ = send_lent(lent, carried_max);
    try testing.expect(std.mem.startsWith(u8, support.sent_of(lent.slot), "HTTP/1.1 200"));
    try testing.expectEqualStrings(support.sent_of(copied.slot), support.sent_of(lent.slot));
}

test "decision 176: the slot of a socket closed with a send in flight ends only after sent_stream" {
    try support.start(null, .{});
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    support.flushing = false;
    _ = support.give(handle, get_kept);
    try engine.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = ok, .end = true });
    try testing.expect(engine.output_stream(handle, support.now_ns).len > 0);
    // The peer left while the send ran: the connection ends, and its slot waits for the send.
    engine.transport_closed(handle);
    support.collect();
    try testing.expect(support.nth(.done, 0) != null);
    try testing.expectEqual(null, support.nth(.ended, 0));
    // The send failed: it took nothing, and the slot frees.
    engine.sent_stream(handle, 0, support.now_ns);
    support.collect();
    try testing.expectEqual(handle, support.nth(.ended, 0).?.connection);
}

test "decision 176 as amended: a connection that finished closes once its last byte is lent, and ends after the send" {
    try support.start(null, .{});
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    support.flushing = false;
    _ = support.give(handle, get_closed);
    try engine.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = ok, .end = true });
    // A send took part of a lend before the engine was asked for an event: the connection owes
    // the rest, and stays open.
    const lent = send_lent(handle, 4);
    support.collect();
    try testing.expectEqual(null, support.nth(.close, 0));
    // The next lend gives the socket the last byte. The engine reports the close while that send
    // is in flight, and holds the slot for it.
    const rest = engine.output_stream(handle, support.now_ns);
    try testing.expectEqual(lent.len - 4, rest.len);
    support.collect();
    try testing.expect(support.nth(.close, 0) != null);
    try testing.expectEqual(null, support.nth(.ended, 0));
    // The send's count frees the slot.
    send_whole(handle, rest);
    support.collect();
    try testing.expectEqual(handle, support.nth(.ended, 0).?.connection);
    try testing.expect(std.mem.startsWith(u8, support.sent_of(handle.slot), "HTTP/1.1 200"));
}

test "design §8 step 80: a send that took a whole lend reports nothing, and asks for no poll" {
    try support.start(null, .{});
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    support.flushing = false;
    _ = support.give(handle, get_kept);
    try answer(support.id_of(handle, support.nth(.request, 0).?.number));
    const lent = engine.output_stream(handle, support.now_ns);
    // INV-31: the lend started the idle deadline, and the engine's deadline follows at once.
    support.check_deadline();
    support.collect();
    const reported = support.seen_len;
    // h11 in cleartext reads nothing with no bytes, and no response waits for room.
    send_whole(handle, lent);
    try testing.expectEqual(0, engine.state.ready.len);
    support.collect();
    try testing.expectEqual(reported, support.seen_len);
    // A lend of the output in place frees no room, and leaves a `receive` with no bytes nothing
    // new to read at this instant.
    const room = engine.state.room[handle.slot];
    try testing.expectEqual(0, engine.output_stream(handle, support.now_ns).len);
    try testing.expectEqual(room, engine.state.room[handle.slot]);
    try testing.expectEqual(@as(?u64, support.instant_ns), engine.state.empty_read_ns[handle.slot]);
}

test "design §8 step 80: over TLS a send that took a whole lend drops its records" {
    const handle = try start_tls(get_kept);
    try answer(support.id_of(handle, support.nth(.request, 0).?.number));
    support.check_deadline();
    const lent = engine.output_stream(handle, support.now_ns);
    try testing.expect(lent.len > 0);
    // INV-31: the lend sealed the output, which moved the connection's deadline, and the
    // engine's deadline follows at once.
    support.check_deadline();
    send_whole(handle, lent);
    try testing.expectEqual(0, engine.output_stream(handle, support.now_ns).len);
    try testing.expect(std.mem.startsWith(u8, try support.open_sent(handle.slot), "HTTP/1.1 200"));
}

test "decision 92: over TLS a pipelined request that a record held is read once no request is open" {
    const handle = try start_tls(get_kept ++ get_kept);
    try testing.expectEqual(null, support.nth(.request, 1));
    try answer(support.id_of(handle, support.nth(.request, 0).?.number));
    support.collect();
    // The first response is done, and the connection's table holds no request. The connection
    // is open, so the engine still asks it for what it holds.
    try testing.expect(support.nth(.request, 1) != null);
}

/// An h11 connection in cleartext whose request takes gzip, in an engine that codes responses
/// (decision 101).
fn start_coded() !event.ConnectionHandle {
    try support.start(null, .{});
    tcp_support.fill_incompressible();
    tcp_support.pool.init();
    support.config.codings = &tcp_support.codings;
    support.config.encoders = tcp_support.pool.encoders();
    try engine.init(&support.config, .{ .unix_seconds = tcp_support.now_seconds, .monotonic_ns = support.now_ns });
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    support.flushing = false;
    _ = support.give(handle, "GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\n\r\n");
    return handle;
}

test "decision 101: a lend that writes a coded ring's bytes out frees room, and ends a response" {
    const handle = try start_coded();
    const id = support.id_of(handle, support.nth(.request, 0).?.number);
    try engine.respond(id, .{ .status = ok, .end = false, .codable = true });
    // The ring holds less than the content, and the rest waits for room.
    const content = tcp_support.incompressible[0..];
    const taken = try engine.write_body(id, .{ .bytes = content, .end = false });
    try testing.expect(taken < content.len);
    support.collect();
    try testing.expectEqual(null, support.nth(.writable, 0));
    // The lend writes ring bytes into the output, so the ring has room again.
    try testing.expect(engine.output_stream(handle, support.now_ns).len > 0);
    support.collect();
    try testing.expect(support.nth(.writable, 0) != null);
}

test "decision 101: the response whose last coded bytes a lend writes out is done at that instant" {
    const handle = try start_coded();
    const id = support.id_of(handle, support.nth(.request, 0).?.number);
    try engine.respond(id, .{ .status = ok, .end = false, .codable = true });
    // The ring takes the whole content, which is more than the output holds.
    const content = tcp_support.incompressible[0..long_content.len];
    try testing.expectEqual(content.len, try engine.write_body(id, .{ .bytes = content, .end = true }));
    const first = engine.output_stream(handle, support.now_ns);
    support.collect();
    try testing.expectEqual(null, support.nth(.done, 0));
    // The send frees the output, and the next lend writes the ring's last bytes there. The
    // response is whole, and a `receive` with no bytes reports it, though one read nothing at
    // this instant before.
    send_whole(handle, first);
    try testing.expect(engine.output_stream(handle, support.now_ns).len > 0);
    support.collect();
    try testing.expect(support.nth(.done, 0) != null);
}

/// How far past the output the coded response of the test below goes. An encoder's ring holds it
/// whole, and so does an h2 stream's first window.
const coded_past_len: usize = 4_096;

test "decision 101: a coded h2 response past the output owes a send once a send freed its room" {
    try support.start(null, .{});
    tcp_support.fill_incompressible();
    tcp_support.pool.init();
    support.config.codings = &tcp_support.codings;
    support.config.encoders = tcp_support.pool.encoders();
    try engine.init(&support.config, .{ .unix_seconds = tcp_support.now_seconds, .monotonic_ns = support.now_ns });
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    _ = support.give(handle, h2_support.client_preface);
    const accepts_gzip = [_]tcp_support.Field{.{ .name = "accept-encoding", .value = "gzip" }};
    _ = support.give(handle, try h2_support.request_frame_with(1, "GET", "/", &accepts_gzip, true));
    support.flushing = false;
    const id = support.id_of(handle, 1);
    try engine.respond(id, .{ .status = ok, .end = false, .codable = true });
    // The ring takes the whole response, so no write waits for room.
    const content = tcp_support.incompressible[0 .. long_content.len + coded_past_len];
    try testing.expectEqual(content.len, try engine.write_body(id, .{ .bytes = content, .end = true }));
    const first = engine.output_stream(handle, support.now_ns);
    support.collect();
    const before = sends();
    try testing.expectEqual(null, support.nth(.done, 0));
    // The send frees the output. h2 frames content only into room, so the ring's next bytes owe
    // their `send` now, and no response waits that would ask for the poll.
    send_whole(handle, first);
    support.collect();
    try testing.expectEqual(before + 1, sends());
    send_whole(handle, engine.output_stream(handle, support.now_ns));
    support.collect();
    try testing.expect(support.nth(.done, 0) != null);
}

test "design §8 step 80: over TLS a lend seals the output, which frees its room" {
    const handle = try start_tls(get_kept);
    const id = support.id_of(handle, support.nth(.request, 0).?.number);
    try engine.respond(id, .{ .status = ok, .end = false });
    const taken = try engine.write_body(id, .{ .bytes = &long_content, .end = true });
    try testing.expect(taken < long_content.len);
    support.collect();
    try testing.expectEqual(null, support.nth(.writable, 0));
    // The records hold the output's bytes, so the response can write more while they are sent.
    try testing.expect(engine.output_stream(handle, support.now_ns).len > 0);
    support.collect();
    try testing.expect(support.nth(.writable, 0) != null);
}

test "design §8 step 80: the poll that ends a closed connection with no request left asks it nothing" {
    try support.start(null, .{});
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    support.flushing = false;
    _ = support.give(handle, get_closed);
    try engine.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = ok, .end = true });
    const lent = engine.output_stream(handle, support.now_ns);
    support.collect();
    try testing.expect(support.nth(.close, 0) != null and support.nth(.done, 0) != null);
    // The lent bytes are the socket's to send: no linger bounds them (decision 110 as amended).
    try testing.expectEqual(null, engine.deadline_ns());
    // The send ends at a later instant. The connection's deadlines are not asked again.
    const checked_ns = engine.tcp[handle.slot].clock.checked_ns;
    support.instant_ns += later_ns;
    send_whole(handle, lent);
    support.collect();
    try testing.expectEqual(handle, support.nth(.ended, 0).?.connection);
    try testing.expectEqual(checked_ns, engine.tcp[handle.slot].clock.checked_ns);
}

/// An h11 connection over TLS whose handshake completed and whose request is open, with every
/// record it owed before the request sent.
fn start_tls(request: []const u8) !event.ConnectionHandle {
    try support.start(support.identity(), .{ .h2 = false });
    const handle = engine.accept(.{}, support.now_ns).?;
    try support.start_client(&tcp_support.protocols_both);
    try testing.expect(try support.handshake(handle));
    support.flushing = false;
    _ = try support.give_sealed(handle, request);
    return handle;
}

test "decision 176: over TLS output_stream lends sealed records, sent in two sends" {
    const handle = try start_tls(get_kept);
    try answer(support.id_of(handle, support.nth(.request, 0).?.number));
    support.collect();
    const before = sends();
    // The first send takes part of a record. The engine reports another `send` for the rest,
    // though no plaintext waits.
    const lent = send_lent(handle, 7);
    try testing.expect(lent.len > 7);
    support.collect();
    try testing.expectEqual(before + 1, sends());
    try testing.expectEqual(lent.len - 7, send_lent(handle, carried_max).len);
    const opened = try support.open_sent(handle.slot);
    try testing.expect(std.mem.startsWith(u8, opened, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, opened, "\r\nbody\r\n") != null);
}

test "decision 176: over TLS a send_stream after a partial send copies the records left first" {
    const handle = try start_tls(get_kept);
    try answer(support.id_of(handle, support.nth(.request, 0).?.number));
    _ = send_lent(handle, 5);
    support.flush(handle);
    const opened = try support.open_sent(handle.slot);
    try testing.expect(std.mem.startsWith(u8, opened, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, opened, "\r\nbody\r\n") != null);
}

test "decision 176 as amended: over TLS a close comes once the records and the close_notify are lent" {
    const handle = try start_tls(get_closed);
    try engine.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = ok, .end = true });
    // The lend seals the response and the close_notify. A send that took part of them before the
    // engine was asked for an event leaves the connection open.
    _ = send_lent(handle, 3);
    support.collect();
    try testing.expectEqual(null, support.nth(.close, 0));
    // The lend of the records left brings the close. Their send reads them after it.
    const rest = engine.output_stream(handle, support.now_ns);
    support.collect();
    try testing.expect(support.nth(.close, 0) != null);
    try testing.expectEqual(null, support.nth(.ended, 0));
    send_whole(handle, rest);
    support.collect();
    try testing.expectEqual(handle, support.nth(.ended, 0).?.connection);
    _ = try support.open_sent(handle.slot);
    try testing.expect(support.client_saw_alert);
}

/// h11 content longer than a connection's output, by one byte.
const long_content: [@import("../constants.zig").limits.output_len + 1]u8 = @splat('c');

test "decision 176: h11 content past the output is writable once a send took the lent octets" {
    try support.start(null, .{});
    support.flushing = false;
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    _ = support.give(handle, get_kept);
    const id = support.id_of(handle, support.nth(.request, 0).?.number);
    try engine.respond(id, .{ .status = ok, .end = false });
    const taken = try engine.write_body(id, .{ .bytes = &long_content, .end = true });
    try testing.expect(taken < long_content.len);
    const lent = engine.output_stream(handle, support.now_ns);
    support.collect();
    try testing.expectEqual(null, support.nth(.writable, 0));
    engine.sent_stream(handle, lent.len, support.now_ns);
    support.collect();
    try testing.expect(support.nth(.writable, 0) != null);
    try testing.expect(try engine.write_body(id, .{ .bytes = long_content[taken..], .end = true }) > 0);
}

test "decision 176: a TLS session that ended with sealed records left serves its next connection" {
    try support.start_held(support.identity(), .{ .h2 = false }, 1);
    const first = engine.accept(.{}, support.now_ns).?;
    try support.start_client(&tcp_support.protocols_both);
    try testing.expect(try support.handshake(first));
    support.flushing = false;
    _ = try support.give_sealed(first, get_kept);
    try answer(support.id_of(first, support.nth(.request, 0).?.number));
    // A send took part of the records, and then the peer left. A socket that closed lends
    // nothing, so the records left never go out.
    _ = send_lent(first, 3);
    engine.transport_closed(first);
    try testing.expectEqual(0, engine.output_stream(first, support.now_ns).len);
    engine.sent_stream(first, 0, support.now_ns);
    support.collect();
    try testing.expectEqual(first, support.nth(.ended, 0).?.connection);
    // The next connection takes the same session, and its handshake starts from the front.
    try support.start_held(support.identity(), .{ .h2 = false }, 1);
    const next = engine.accept(.{}, support.now_ns).?;
    try support.start_client(&tcp_support.protocols_both);
    try testing.expect(try support.handshake(next));
}

/// The head of a POST whose body is one byte past the bound, so the server closes in stages
/// (decision 160).
const past_bound_head = std.fmt.comptimePrint("POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: {d}\r\n\r\n", .{@import("../constants.zig").limits.discard_len_max + 1});

test "decision 176 as amended: over TLS a staged close's half_close comes once the records are lent" {
    const handle = try start_tls(past_bound_head);
    // RFC 9110 §15.5.6: 405 (Method Not Allowed), before the body.
    try engine.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = .method_not_allowed, .end = true });
    // The lend seals the 405 and the close_notify, and a send takes part of them before the
    // engine is asked for an event: the connection owes the rest.
    _ = send_lent(handle, 3);
    support.collect();
    try testing.expectEqual(null, support.nth(.half_close, 0));
    // The lend of the records left brings the half_close, while their send is in flight.
    const rest = engine.output_stream(handle, support.now_ns);
    support.collect();
    try testing.expect(support.nth(.half_close, 0) != null);
    send_whole(handle, rest);
    _ = try support.open_sent(handle.slot);
    try testing.expect(support.client_saw_alert);
}

test "decision 176: a lend before the send starts holds the earlier lend and what was written since" {
    const handle = try start_h2();
    const id = support.id_of(handle, 1);
    try engine.respond(id, .{ .status = ok, .end = false });
    support.collect();
    const before = sends();
    const first = engine.output_stream(handle, support.now_ns);
    @memcpy(saved[0..first.len], first);
    // A write after the lend brings a new `send`, for the bytes no lend gave.
    _ = try engine.write_body(id, .{ .bytes = "more", .end = true });
    support.collect();
    try testing.expectEqual(before + 1, sends());
    const second = engine.output_stream(handle, support.now_ns);
    try testing.expectEqual(@intFromPtr(first.ptr), @intFromPtr(second.ptr));
    try testing.expectEqualSlices(u8, saved[0..first.len], second[0..first.len]);
    try testing.expect(std.mem.endsWith(u8, second, "more"));
    // Every byte owed is lent, so no `send` comes.
    support.collect();
    try testing.expectEqual(before + 1, sends());
    engine.sent_stream(handle, second.len, support.now_ns);
}

test "decision 176: over TLS a second lend seals what was written since after the first's records" {
    const handle = try start_tls(get_kept);
    const id = support.id_of(handle, support.nth(.request, 0).?.number);
    try engine.respond(id, .{ .status = ok, .end = false });
    const first_len = engine.output_stream(handle, support.now_ns).len;
    _ = try engine.write_body(id, .{ .bytes = "body", .end = true });
    // Every record owed is lent, so no `send` comes before the socket's send.
    support.collect();
    const before = sends();
    _ = engine.output_stream(handle, support.now_ns);
    support.collect();
    try testing.expectEqual(before, sends());
    const lent = send_lent(handle, carried_max);
    try testing.expect(lent.len > first_len);
    const opened = try support.open_sent(handle.slot);
    try testing.expect(std.mem.startsWith(u8, opened, "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, opened, "\r\nbody\r\n") != null);
}
