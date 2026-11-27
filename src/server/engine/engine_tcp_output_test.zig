//! The tests of a TCP socket that sends from its connection's output (decision 176, design §8
//! step 79): `output_stream` lends the bytes where the engine holds them, they stay in place until
//! `sent_stream`, and the slot of a closed socket ends only after that call. Over TLS the bytes
//! are sealed records, and a `send_stream` after a partial send copies the records left first.
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

/// The bytes the transport of one slot carries in a test.
const carried_max = support.sent[0].len;
/// A copy of what a lend held, made before the bytes move.
threadlocal var saved: [carried_max]u8 = undefined;

/// Sends `sent` bytes of what the connection lends, as a socket's send takes them: they join what
/// the transport carried, and `sent_stream` returns the count. Returns the bytes lent.
fn send_lent(handle: event.ConnectionHandle, sent: usize) []const u8 {
    const lent = engine.output_stream(handle, support.now_ns);
    const slot = handle.slot;
    const taken = @min(sent, lent.len);
    @memcpy(support.sent[slot][support.sent_len[slot]..][0..taken], lent[0..taken]);
    support.sent_len[slot] += taken;
    engine.sent_stream(handle, taken, support.now_ns);
    return lent;
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

test "decision 176: a connection that finished closes once a send took its last octet" {
    try support.start(null, .{});
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    support.flushing = false;
    _ = support.give(handle, get_closed);
    try engine.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = ok, .end = true });
    const lent = send_lent(handle, 4);
    support.collect();
    try testing.expectEqual(null, support.nth(.close, 0));
    _ = send_lent(handle, lent.len);
    support.collect();
    try testing.expect(support.nth(.close, 0) != null);
    try testing.expect(std.mem.startsWith(u8, support.sent_of(handle.slot), "HTTP/1.1 200"));
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

test "decision 176: over TLS a close waits for the sealed records, the close_notify last" {
    const handle = try start_tls(get_closed);
    try engine.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = ok, .end = true });
    // The lend seals the response and the close_notify. A send that took part of them leaves the
    // connection open.
    const lent = send_lent(handle, 3);
    support.collect();
    try testing.expectEqual(null, support.nth(.close, 0));
    _ = send_lent(handle, lent.len);
    support.collect();
    try testing.expect(support.nth(.close, 0) != null);
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

test "decision 176: over TLS a staged close's half_close waits for the sealed records" {
    const handle = try start_tls(past_bound_head);
    // RFC 9110 §15.5.6: 405 (Method Not Allowed), before the body.
    try engine.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = .method_not_allowed, .end = true });
    // The lend seals the 405 and the close_notify, and a send takes part of them.
    const lent = send_lent(handle, 3);
    support.collect();
    try testing.expectEqual(null, support.nth(.half_close, 0));
    _ = send_lent(handle, lent.len);
    support.collect();
    try testing.expect(support.nth(.half_close, 0) != null);
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
