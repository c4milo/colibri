//! The test that holds `connection_send.frame_block`, which cuts a block into frames where it
//! lies, to the `write_block` it replaced, which copied a block from the connection's buffer into
//! its frames (design §8 step 61b). The old call stays here as the reference. Test-only.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const connection_send = @import("connection_send.zig");
const support = @import("connection_test_support.zig");

const Writer = core.Writer;
const testing = std.testing;
const test_connection = &support.test_connection;

/// The reference: the old call, which cut `block` into a HEADERS frame and its CONTINUATION frames
/// written into `output`, each at most `limit` octets (RFC 9113 §4.2, §6.10). Test-only.
fn write_block_reference(limit: usize, output: []u8, stream_id: u32, block: []const u8, end_stream: bool) !usize {
    var writer = Writer.init(output);
    var offset: usize = 0;
    for (0..constants.limits.continuation_count_max + 1) |index| {
        const end = @min(offset + limit, block.len);
        const last = end == block.len;
        const fragment = block[offset..end];
        if (index == 0) {
            try frame.write_headers(&writer, stream_id, fragment, end_stream, last, 0, null);
        } else {
            try frame.write_continuation(&writer, stream_id, fragment, last);
        }
        offset = end;
        if (last) return writer.written().len;
    }
    unreachable;
}

/// Where the reference writes, where the change cuts the block in place, and the block itself.
/// Room for the longest block and every header it needs. Test-only.
const output_len = constants.limits.send_block_len_max + frame_headers_max * constants.protocol.frame_header_len;
const frame_headers_max = constants.limits.send_block_len_max / constants.protocol.max_frame_size_min + 1;
threadlocal var reference_output: [output_len]u8 = undefined;
threadlocal var change_output: [output_len]u8 = undefined;
threadlocal var test_block_octets: [constants.limits.send_block_len_max]u8 = undefined;

/// The frame sizes the peer may set: the least, which is the initial, and two larger ones.
const frame_size_factor = 4;
const frame_sizes = [_]u32{ constants.protocol.max_frame_size_min, constants.protocol.max_frame_size_min + 1, frame_size_factor * constants.protocol.max_frame_size_min };

/// Requires both calls to write the same frames for a block of `block_len` octets, or both to refuse
/// it, in an output of `room` octets. Test-only.
fn expect_same_frames(limit: u32, block_len: usize, room: usize, end_stream: bool) !void {
    test_connection.peer.max_frame_size = limit;
    const block = test_block_octets[0..block_len];
    const expected = write_block_reference(limit, reference_output[0..room], 1, block, end_stream) catch null;
    // A block longer than the space after the first header is refused as it is encoded.
    const space = connection_send.block_space(change_output[0..room]);
    const written = if (space.len < block_len) null else written: {
        @memcpy(space[0..block_len], block);
        break :written connection_send.frame_block(test_connection, change_output[0..room], 1, block_len, end_stream) catch null;
    };
    const length = expected orelse return testing.expectEqual(null, written);
    try testing.expectEqual(length, written.?);
    try testing.expectEqualSlices(u8, reference_output[0..length], change_output[0..length]);
}

test "design §8 step 61b: a block cut into frames where it lies is the frames the old copy wrote" {
    try support.start_server();
    for (&test_block_octets, 0..) |*octet, index| octet.* = @truncate(index *% 31 +% 7);
    for (frame_sizes) |limit| {
        test_connection.peer.max_frame_size = limit;
        // Each length about the edges of one and two frames, and the longest block.
        for ([_]usize{ 0, 1, limit - 1, limit, limit + 1, 2 * limit - 1, 2 * limit, 2 * limit + 1, constants.limits.send_block_len_max }) |wanted| {
            const block_len = @min(wanted, constants.limits.send_block_len_max);
            const needed = connection_send.block_frames_len(test_connection, block_len);
            for ([_]bool{ false, true }) |end_stream| {
                try expect_same_frames(limit, block_len, @min(needed, output_len), end_stream);
                // One octet short of the frames refuses the block in both.
                if (needed > constants.protocol.frame_header_len) try expect_same_frames(limit, block_len, needed - 1, end_stream);
            }
        }
    }
}
