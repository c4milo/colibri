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
    var payload: [constants.setting_len]u8 = undefined;
    var writer = core.Writer.init(&payload);
    try writer.write_int(u16, constants.setting_header_table_size);
    try writer.write_int(u32, size);
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
