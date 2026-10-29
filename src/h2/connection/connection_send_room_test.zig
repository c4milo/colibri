//! The tests of a field block refused for room (`connection_send.zig`, `connection_request.zig`):
//! it leaves nothing behind. A request opens no stream (RFC 9113 §5.1.1), and no block is declared
//! to the peer's decoder until its frames are written (RFC 7541 §4.2), so the size updates a refused
//! block carried open the next one. Split out of `connection_request.zig` for length.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const connection = @import("connection.zig");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const test_connection = &support.test_connection;
const test_output = &support.test_output;

/// A request with every pseudo-header field RFC 9113 §8.3.1 requires. Test-only.
const test_request: connection.Request_ = .{ .method = "GET", .scheme = "https", .path = "/", .authority = "example.com" };

/// RFC 7541 §6.3: a dynamic table size update starts with the bits 001. Test-only.
const size_update_mask: u8 = 0xe0;
const size_update_pattern: u8 = 0x20;
/// Room for less than a frame header, which no block's frames fit. Test-only.
const room_short: usize = 4;
const ok: u16 = 200;

/// Feeds the peer's SETTINGS frame setting HEADER_TABLE_SIZE to `size`, after which colibri's
/// encoder owes a size update (RFC 7541 §4.2). Test-only.
fn feed_table_size(size: u32) !void {
    return feed_setting(constants.setting_header_table_size, size);
}

/// Feeds the peer's SETTINGS frame with one setting. Test-only.
fn feed_setting(identifier: u16, value: u32) !void {
    var payload: [constants.setting_len]u8 = undefined;
    var writer = core.Writer.init(&payload);
    try writer.write_int(u16, identifier);
    try writer.write_int(u32, value);
    const settings = try support.frame_bytes(&support.test_input, constants.frame_type_settings, 0, 0, writer.written());
    _ = try support.feed(settings);
}

/// Whether the field block of the HEADERS frame at the front of `frames` opens with a size
/// update. An empty block opens with nothing. Test-only.
fn opens_with_size_update(frames: []const u8) bool {
    const block_len = std.mem.readInt(u24, frames[0..frame_length_len], .big);
    return block_len > 0 and frames[constants.frame_header_len] & size_update_mask == size_update_pattern;
}

/// Octets of a frame header's Length field (RFC 9113 §4.1). Test-only.
const frame_length_len: usize = 3;
/// A trailer section of one field line, so its block is never empty. Test-only.
const trailers = [_]@import("hpack").Field{.{ .name = "grpc-status", .value = "0" }};

test "RFC 9113 §5.1.1: a request refused for room opens no stream, and its size update goes next" {
    try support.start_client();
    try feed_table_size(0);
    const short = test_output[0..room_short];
    try testing.expectError(error.OutputTooSmall, test_connection.write_request(short, test_request, &.{}, &.{}, true));
    try testing.expectEqual(0, test_connection.streams.local_active);
    const sent = try test_connection.write_request(test_output, test_request, &.{}, &.{}, true);
    // RFC 9113 §5.1.1: the refused request spent no identifier.
    try testing.expectEqual(1, sent.stream_id);
    // RFC 7541 §4.2: the size update the refused block carried opens this one.
    try testing.expect(opens_with_size_update(test_output));
}

test "RFC 7541 §4.2: a response or a trailer section refused for room leaves its size update owed" {
    try support.start_server();
    _ = try support.feed_request(1, "/", true);
    try feed_table_size(0);
    const short = test_output[0..room_short];
    try testing.expectError(error.OutputTooSmall, test_connection.write_response(short, 1, ok, &.{}, false));
    _ = try test_connection.write_response(test_output, 1, ok, &.{}, false);
    try testing.expect(opens_with_size_update(test_output));
    // The response declared its block, so a new limit makes the trailer section owe an update.
    try feed_table_size(core.constants.field_value_len_max);
    try testing.expectError(error.OutputTooSmall, test_connection.write_trailers(short, 1, &trailers));
    _ = try test_connection.write_trailers(test_output, 1, &trailers);
    try testing.expect(opens_with_size_update(test_output));
}

/// What `send_block` holds before a response that must not write it. Test-only.
const sentinel: u8 = 0xa5;

test "a response whose block fits one frame is encoded in place, and send_block is not written" {
    try support.start_server();
    _ = try support.feed_request(1, "/", true);
    @memset(&test_connection.send_block, sentinel);
    const written = try test_connection.write_response(test_output, 1, ok, &.{.{ .name = "x-a", .value = "b" }}, true);
    try testing.expect(std.mem.allEqual(u8, &test_connection.send_block, sentinel));
    // One HEADERS frame that ends the block and the stream, and holds the whole block.
    const block_len = std.mem.readInt(u24, test_output[0..frame_length_len], .big);
    try testing.expectEqual(written - constants.frame_header_len, block_len);
    try testing.expectEqual(constants.frame_type_headers, test_output[3]);
    try testing.expectEqual(constants.flag_end_stream | constants.flag_end_headers, test_output[4]);
}

/// Room for a block longer than `send_block_len_max` in one frame: twice that. Test-only.
const huge_output_len: usize = constants.send_block_len_max + constants.send_block_len_max;
var test_huge_output: [huge_output_len]u8 = undefined;
/// Values Huffman coding would not shorten, longer together than `send_block_len_max`. Test-only.
const huge_value_len = 4000;
const huge_values_count = 9;

test "design §7: a block longer than send_block_len_max is refused, though the peer's frames allow it" {
    try support.start_server();
    try feed_setting(constants.setting_max_frame_size, constants.max_frame_size_max);
    _ = try support.feed_request(1, "/", true);
    var values: [huge_values_count][huge_value_len]u8 = undefined;
    var fields: [huge_values_count]@import("hpack").Field = undefined;
    for (&values, &fields, 0..) |*value, *field_line, index| {
        value.* = @splat(@intCast(0x80 + index));
        field_line.* = .{ .name = "x-a", .value = value };
    }
    comptime std.debug.assert(huge_value_len * huge_values_count > constants.send_block_len_max);
    try testing.expectError(error.OutputTooSmall, test_connection.write_response(&test_huge_output, 1, ok, &fields, false));
}

/// The lines of the responses of decision 132's tests. Test-only.
const indexed_lines = [_]@import("hpack").Field{
    .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    .{ .name = "x-a", .value = "b" },
};
/// The block of a response whose `:status` is 200 and whose lines both tables hold: one octet
/// each (RFC 7541 §6.1). Test-only.
const indexed_block_len: usize = 1 + indexed_lines.len;

/// The field block of the HEADERS frame at the front of `frames`. Test-only.
fn block_of(frames: []const u8) []const u8 {
    const block_len = std.mem.readInt(u24, frames[0..frame_length_len], .big);
    return frames[constants.frame_header_len..][0..block_len];
}

/// Requires the peer's decoder, which reads every block colibri sent, to read `:status` 200 and
/// `lines` from the response at the front of `frames`. Test-only.
fn expect_decoded(frames: []const u8, lines: []const @import("hpack").Field) !void {
    var expected: [indexed_lines.len + 1]@import("hpack").Field = undefined;
    expected[0] = .{ .name = ":status", .value = "200" };
    @memcpy(expected[1..][0..lines.len], lines);
    try @import("hpack").decoder.expect_lines(block_of(frames), expected[0 .. lines.len + 1]);
}

test "decision 132: a response's lines go into the table, so the next response sends each as one octet" {
    try support.start_server();
    @import("hpack").decoder.test_decoder().init(constants.header_table_size_initial);
    _ = try support.feed_request(1, "/", true);
    _ = try support.feed_request(3, "/", true);
    _ = try test_connection.write_response(test_output, 1, ok, &indexed_lines, true);
    try expect_decoded(test_output, &indexed_lines);
    _ = try test_connection.write_response(test_output, 3, ok, &indexed_lines, true);
    try expect_decoded(test_output, &indexed_lines);
    try testing.expectEqual(indexed_block_len, block_of(test_output).len);
}

/// Room for a frame header and a block that holds `:status` and the first line, but not the
/// second: `:status` 200 is one octet, and "x-new: 1" with its name and value as literals nine.
/// Test-only.
const block_one_line_len: usize = 12;
const room_one_line: usize = constants.frame_header_len + block_one_line_len;
const long_value_len = 100;

test "decision 132: a response refused after its block inserted makes the next block empty both tables" {
    try support.start_server();
    @import("hpack").decoder.test_decoder().init(constants.header_table_size_initial);
    _ = try support.feed_request(1, "/", true);
    _ = try support.feed_request(3, "/", true);
    _ = try test_connection.write_response(test_output, 1, ok, indexed_lines[1..2], true);
    try expect_decoded(test_output, indexed_lines[1..2]);
    // The block inserts "x-new" and then finds no room for the long line, so it is refused and
    // the peer never reads it.
    const long_value: [long_value_len]u8 = @splat('v');
    const refused = [_]@import("hpack").Field{ .{ .name = "x-new", .value = "1" }, .{ .name = "x-long", .value = &long_value } };
    try testing.expectError(error.OutputTooSmall, test_connection.write_response(test_output[0..room_one_line], 3, ok, &refused, true));
    // RFC 7541 §6.3: the next block opens with the update to 0, and the peer reads its lines over
    // the emptied table.
    _ = try test_connection.write_response(test_output, 3, ok, indexed_lines[1..2], true);
    try testing.expect(opens_with_size_update(test_output));
    try testing.expectEqual(size_update_pattern, block_of(test_output)[0]);
    try expect_decoded(test_output, indexed_lines[1..2]);
}

/// A status the static table does not hold (RFC 7541 Appendix A), so only the dynamic table can
/// index it. Test-only.
const created: u16 = 201;

test "decision 132: a status the static table lacks goes into the table too" {
    try support.start_server();
    @import("hpack").decoder.test_decoder().init(constants.header_table_size_initial);
    const status = [_]@import("hpack").Field{.{ .name = ":status", .value = "201" }};
    for ([_]u32{ 1, 3 }) |stream_id| {
        _ = try support.feed_request(stream_id, "/", true);
        _ = try test_connection.write_response(test_output, stream_id, created, &.{}, true);
        try @import("hpack").decoder.expect_lines(block_of(test_output), &status);
    }
    // RFC 7541 §6.1: the second response's status is one octet, an index into the dynamic table.
    try testing.expectEqual(1, block_of(test_output).len);
}
