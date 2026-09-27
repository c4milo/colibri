//! The fixtures and helpers the tests of `field_block.zig`, `field_block_decode.zig` and
//! `field_block_limit.zig` share: the slot, the decoder and encoder they run on, one frame of
//! octets, and RFC 7541 Appendix C's first request. Test-only. They sit in their own file because
//! a fixture several files share is a plain global, and `tools/lint/global_state.zig` refuses one
//! in a library file.
const std = @import("std");
const core = @import("core");
const hpack = @import("hpack");
const constants = @import("../constants.zig");
const field_block = @import("field_block.zig");

const FieldBlock = field_block.FieldBlock;
const Origin = field_block.Origin;
const Done = field_block.Done;
const testing = std.testing;

/// The slot the tests of this file and of `field_block_decode.zig` run on, placed outside any
/// stack frame. Test-only.
pub var test_block: FieldBlock align(@alignOf(FieldBlock)) = undefined;
/// The decoder those tests run on. Test-only.
pub var test_decoder: hpack.Decoder align(@alignOf(hpack.Decoder)) = undefined;
/// The encoder those tests build fragments with. Test-only.
pub var test_encoder: hpack.Encoder align(@alignOf(hpack.Encoder)) = undefined;
/// One frame of octets the tests write fragments into. Test-only.
pub var test_frame: [constants.frame_size_max]u8 = @splat('v');
/// A value as long as a value may be. Test-only.
pub const long_value: [core.constants.field_value_len_max]u8 = @splat('v');

/// RFC 7541 Appendix C.3.1: the first request, raw. Test-only.
pub const request_raw = "\x82\x86\x84\x41\x0fwww.example.com";
/// RFC 7541 Appendix C.4.1: the same request, Huffman-coded. Test-only.
pub const request_huffman = "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
/// The field lines both encodings of the first request decode to. Test-only.
pub const request_lines = [_]hpack.Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "www.example.com" },
};

/// Begins a block on a fresh slot over a fresh decoder. Test-only.
pub fn start(identifier: u32, origin: Origin, end_stream: bool) void {
    test_decoder.init(constants.header_table_size_initial);
    test_block.init();
    test_block.begin(identifier, origin, end_stream);
}

/// Requires the slot's section to hold exactly `expected`, in order. Test-only.
pub fn expect_section(expected: []const hpack.Field) !void {
    try testing.expectEqual(expected.len, test_block.section.len());
    for (expected, 0..) |field, index| {
        const line = test_block.section.get(@intCast(index));
        try testing.expectEqualStrings(field.name, line.name);
        try testing.expectEqualStrings(field.value, line.value);
    }
}

/// Requires `result` to be `expected` and the slot to be free with nothing kept. Test-only.
pub fn expect_done(result: ?Done, expected: Done) !void {
    const done = result orelse return error.TestUnexpectedResult;
    try testing.expectEqual(expected, done);
    try testing.expect(!test_block.is_in_progress());
    try testing.expectEqual(null, test_block.stream_id());
    try testing.expectEqual(0, test_block.buffer_len);
}

/// Requires the slot to be as `abandon` and a refusal leave it. Test-only.
pub fn expect_cleared() !void {
    try testing.expect(!test_block.is_in_progress());
    try testing.expectEqual(0, test_block.buffer_len);
    try testing.expectEqual(0, test_block.section.len());
    try testing.expectEqual(0, test_block.octets_fed);
}
