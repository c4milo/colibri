//! The tests of a `.hosted` `colibri.Server` whose sockets send what the engine lends (decision
//! 176, design §8 step 79), on a fake host: the test is the host, and it chooses how much each send
//! takes and when each operation completes. The tests open no socket.
const std = @import("std");
const support = @import("test_support.zig");
const host_support = @import("fake_host_send_test_support.zig");

const testing = std.testing;
const find = host_support.find;
const turn = host_support.turn;
const stop = host_support.stop;
const turns_max = host_support.turns_max;
const operations_len = host_support.operations_len;
const in_flight = &host_support.in_flight;

/// A request h11 keeps the connection open after (RFC 9112 §9.3).
const get_kept = "GET / HTTP/1.1\r\nHost: h\r\n\r\n";
/// The octets the first send takes in a test of a partial send.
const partial_len = 5;
/// A copy of the octets of the first send, made before they move: the head and "body".
var first_sent: [first_sent_len_max]u8 = undefined;
const first_sent_len_max = 256;

/// Starts the server in cleartext, accepts a connection, and gives it `request`. Returns the
/// operations of the turn that follows, which answers it.
fn serve_request(counter: *support.Counter, request: []const u8) !usize {
    try host_support.start(counter, .{});
    const receive = find(turn(operations_len), .receive) orelse return error.OperationMissing;
    @memcpy(receive.kind.receive.buffer[0..request.len], request);
    in_flight.complete(receive.id, .{ .received = @intCast(request.len) });
    return turn(operations_len);
}

test "design §8 step 79: a hosted server sends from the engine, and a partial send's rest goes next" {
    var counter: support.Counter = .{};
    const written = try serve_request(&counter, get_kept);
    const send = find(written, .send) orelse return error.OperationMissing;
    const bytes = send.kind.send.bytes;
    try testing.expect(std.mem.startsWith(u8, bytes, "HTTP/1.1 200"));
    @memcpy(first_sent[0..bytes.len], bytes);
    // The send takes five octets. The rest moves to the front of the same octets, and the next
    // send writes it.
    in_flight.complete(send.id, .{ .sent = partial_len });
    const rest = (find(turn(operations_len), .send) orelse return error.OperationMissing).kind.send.bytes;
    try testing.expectEqual(@intFromPtr(bytes.ptr), @intFromPtr(rest.ptr));
    try testing.expectEqualStrings(first_sent[partial_len..bytes.len], rest);
    try stop();
}

test "design §8 step 79: a socket that fails with octets it never sent frees for the next connection" {
    var counter: support.Counter = .{};
    const written = try serve_request(&counter, get_kept);
    const send = find(written, .send) orelse return error.OperationMissing;
    const receive = find(written, .receive) orelse return error.OperationMissing;
    // The send takes part of the response. The next turn has no room, so the socket holds the
    // rest that the engine lent, with no send written.
    in_flight.complete(send.id, .{ .sent = partial_len });
    _ = turn(0);
    // The peer leaves. The socket hands the rest back, closes, and frees for another accept.
    in_flight.complete(receive.id, .{ .received = 0 });
    for (0..turns_max) |_| {
        const written_now = turn(operations_len);
        if (find(written_now, .accept) != null) return stop();
        if (find(written_now, .close)) |close| in_flight.complete(close.id, .closed);
    }
    return error.TestUnexpectedResult;
}

test "design §8 step 79: the part of a stream that a send's room lets the route write leaves in that turn" {
    var counter: support.Counter = .{};
    const written = try serve_request(&counter, "GET /stream HTTP/1.1\r\nHost: h\r\n\r\n");
    const first = find(written, .send) orelse return error.OperationMissing;
    // The first part fills the connection's output. Its send frees the room, the route writes the
    // next part as it reads its `writable`, and the same turn sends it.
    in_flight.complete(first.id, .{ .sent = @intCast(first.kind.send.bytes.len) });
    const next = find(turn(operations_len), .send) orelse return error.OperationMissing;
    try testing.expect(next.kind.send.bytes.len > 0);
    try stop();
}
