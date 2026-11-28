//! The tests of a lent output and decision 110's send meter (`connection_output.zig`, decision
//! 176): what a socket's send takes of a lent output counts as taken, as a copy's bytes do.
const std = @import("std");
const http = @import("http");
const support = @import("connection_test_support.zig");
const deadline_support = @import("connection_deadline_test_support.zig");
const connection_output = @import("connection_output.zig");

const testing = std.testing;
const connection = &support.connection;
const server_constants = support.server_constants;
const early_ns = deadline_support.early_ns;

const grace_ns = server_constants.policy.rate_grace_ns;
const window_ns = server_constants.policy.rate_window_ns;
const idle_ns = server_constants.policy.idle_timeout_ns;
const first_end_ns = early_ns + grace_ns + window_ns;
/// The bytes each window owes at the default send rate.
const quota: usize = server_constants.policy.send_rate_min * (window_ns / server_constants.nanoseconds_per_second);
/// An answer of `answer_windows` windows of quota, past what the test's peer takes, with its
/// status: 200 (OK), RFC 9110 §15.3.1.
const content: [answer_windows * quota]u8 = @splat('a');
const answer_windows: usize = 3;
const ok_status: http.Status = .ok;

/// The peer's send takes `len` bytes of what the connection lends at `now_ns`.
fn take(len: usize, now_ns: u64) void {
    const lent = connection_output.lend(connection, now_ns);
    connection_output.took(connection, @min(len, lent.len), now_ns);
}

test "decision 176: what a send takes of a lent output feeds the send meter" {
    try support.start_cleartext(.h11);
    const id = (try deadline_support.receive_at("GET / HTTP/1.1\r\nHost: h\r\n\r\n", early_ns)).event.?.request.id.number;
    try connection.respond(id, .{ .status = ok_status, .end = false });
    _ = try connection.write_body(id, .{ .bytes = &content, .end = true });
    take(64, early_ns);
    try testing.expectEqual(first_end_ns, connection.deadline_ns().?);
    // A peer that takes the quota each window moves its deadline a window on, and is not cut.
    take(quota, early_ns + 1);
    try testing.expectEqual(first_end_ns + window_ns, connection.deadline_ns().?);
    connection.on_instant(first_end_ns);
    try testing.expectEqual(null, connection.close_reason());
}

/// The bytes of content the test below writes while a send is in flight.
const late_len: usize = 64;

test "decision 176 as amended: a send that took a whole lend counts its bytes and starts no deadline" {
    try support.start_cleartext(.h11);
    const id = (try deadline_support.receive_at("GET / HTTP/1.1\r\nHost: h\r\n\r\n", early_ns)).event.?.request.id.number;
    try connection.respond(id, .{ .status = ok_status, .end = false });
    _ = try connection.write_body(id, .{ .bytes = content[0..quota], .end = false });
    try testing.expect(connection_output.lend(connection, early_ns).len > quota);
    // The connection writes the end of the response while the send is in flight.
    _ = try connection.write_body(id, .{ .bytes = content[quota..][0..late_len], .end = true });
    connection_output.took_whole(connection);
    // The send's bytes fill the first window's quota, so the meter looks at the next window. It
    // runs on, for the bytes written since.
    try testing.expectEqual(@as(?u64, first_end_ns + window_ns), connection.deadline_ns());
    // The response is whole, and its last bytes wait for a lend: the connection is not idle yet.
    _ = try connection.receive(&.{}, early_ns + 1);
    try testing.expectEqual(@as(?u64, first_end_ns + window_ns), connection.deadline_ns());
    // The lend gives the socket the last bytes, and the idle deadline runs from it. Their send
    // empties the output, so the meter stops, and no other deadline is left.
    try testing.expect(connection_output.lend(connection, early_ns + 2).len > 0);
    connection_output.took_whole(connection);
    try testing.expectEqual(@as(?u64, early_ns + 2 + idle_ns), connection.deadline_ns());
}
