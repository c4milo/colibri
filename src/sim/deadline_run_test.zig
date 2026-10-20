//! The test of the deadline run's honest peer (`deadline_run.zig`) for what no seed of the check
//! brings: a pool that asks for a second socket (design §8 step 21c). In every seed the server
//! closes the socket first, so the test plays the server by hand: an h11 response in cleartext
//! that closes the connection (RFC 9112 §9.6).
const std = @import("std");
const run_module = @import("deadline_run.zig");
const plan_module = @import("deadline_plan.zig");

const testing = std.testing;

/// The run's storage, outside any stack frame. Test-only.
var storage: run_module.Storage align(@alignOf(run_module.Storage)) = undefined;

/// A response with no content, after which the server closes the connection (RFC 9112 §9.6).
const closing_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
/// The content each request of the uploading peer carries, and its exchanges.
const upload_len: u32 = 16;
const exchanges_len: u8 = 2;

test "decision 120: an honest peer opens no second socket, and the exchange that waits for one ends refused" {
    // An uploading peer makes its exchanges one at a time, so its second one starts once the
    // first ends, and the pool asks for a socket to carry it.
    var plan = std.mem.zeroes(plan_module.Plan);
    plan.protocol = .h11;
    plan.peer = .upload;
    plan.deadlines = .{};
    plan.exchanges_len = exchanges_len;
    plan.upload_len = @splat(upload_len);
    plan.piece_len = upload_len;
    try run_module.start(&storage, &plan, 0);
    _ = try run_module.peer_write(&storage, &plan, 0);
    const stream = &storage.to_client;
    @memcpy(stream.octets[stream.written..][0..closing_response.len], closing_response);
    stream.written += closing_response.len;
    _ = try run_module.peer_read(&storage, &plan, 0);
    try testing.expectEqual(1, storage.record.exchanges_done);
    try testing.expectEqual(exchanges_len, storage.exchanges_requested);
    // RFC 9113 §8.7: no server processed the second request, so it ends refused, and the peer
    // started no second connection.
    try testing.expectEqual(.refused, storage.responses[1].outcome);
    try testing.expectEqual(.closed, storage.pool.phase(.tcp));
}
