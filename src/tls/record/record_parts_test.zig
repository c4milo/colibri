//! The tests of `encrypt_parts` over chapulin's `writeParts` (decision 139): a client and a server
//! of the library's TCP object run against each other in memory (`record_test_support.zig`).
const std = @import("std");
const support = @import("record_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;
const to_server = &support.to_server;
const scratch = &support.scratch;

/// The two parts the test seals: a frame header's length of head, and data past one record.
const head = "HEAD:abcd";
const data: [data_len]u8 = @splat('x');
const data_len: usize = 20_000;
/// An output that holds one short record. Test-only.
const small_len: usize = 64;

test "decision 139: two parts seal as one run of plaintext, whole or not at all" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    const sender = client.provider();
    const receiver = server.provider();
    const room = to_server.free();
    try testing.expect(sender.vtable.writable_len(sender.context, room.len) >= head.len + data.len);
    to_server.len += try sender.vtable.encrypt_parts(sender.context, head, &data, room);
    // RFC 9846 §5.1: the peer opens the head and then the data, across the records' boundaries.
    const opened = scratch[0..try support.open_all(receiver, to_server, scratch)];
    try testing.expectEqual(head.len + data.len, opened.len);
    try testing.expectEqualStrings(head, opened[0..head.len]);
    try testing.expectEqualSlices(u8, &data, opened[head.len..]);
    // One octet past the writable length seals nothing, and the writable length seals both whole.
    var small: [small_len]u8 = undefined;
    const fits = sender.vtable.writable_len(sender.context, small.len);
    try testing.expect(fits > head.len);
    try testing.expectError(error.NoSpaceLeft, sender.vtable.encrypt_parts(sender.context, head, data[0 .. fits - head.len + 1], &small));
    const written = try sender.vtable.encrypt_parts(sender.context, head, data[0 .. fits - head.len], &small);
    try testing.expect(written > fits and written <= small.len);
}
