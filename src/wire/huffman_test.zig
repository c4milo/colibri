//! The tests that hold `huffman.zig`'s `encode` to the encoder it replaced
//! (https://github.com/c4milo/colibri/issues/57). That encoder measured the string first and then
//! wrote one octet at a time. It stays here as the reference: `encode` must return what it returns
//! and leave the same octets written, for every input and in every room.
const std = @import("std");
const core = @import("core");
const constants = @import("constants.zig");
const table = @import("huffman_table.zig");
const huffman = @import("huffman.zig");

const Writer = core.Writer;
const testing = std.testing;

/// Most whole octets ready to write after one symbol. At most seven bits remain between symbols and
/// a code is at most thirty, so no more than four octets are ever ready at once.
const ready_octets_max = (constants.huffman_padding_bits_max + constants.huffman_code_bits_max) /
    @bitSizeOf(u8);

/// The reference: the encoder `huffman.encode` replaced. All of the octets are written, or none.
fn encode_by_octets(bytes: []const u8, output: *Writer) core.writer.Error!void {
    if (huffman.encoded_len(bytes) > output.remaining_len()) return error.NoSpaceLeft;
    var pending: u64 = 0;
    var pending_bits: u8 = 0;
    for (bytes) |byte| {
        const row = table.codes[byte];
        pending = (pending << @intCast(row.bit_count)) | row.code;
        pending_bits += row.bit_count;
        for (0..ready_octets_max) |_| {
            if (pending_bits < @bitSizeOf(u8)) break;
            pending_bits -= @bitSizeOf(u8);
            output.write_byte(@truncate(pending >> @intCast(pending_bits))) catch unreachable;
        }
        pending &= (@as(u64, 1) << @intCast(pending_bits)) - 1;
    }
    if (pending_bits == 0) return;
    const padding_bits: u8 = @bitSizeOf(u8) - pending_bits;
    const padding: u64 = (@as(u64, 1) << @intCast(padding_bits)) - 1;
    output.write_byte(@truncate((pending << @intCast(padding_bits)) | padding)) catch unreachable;
}

/// The longest string the tests vary, and room for its code and one octet more.
const varied_len_max = 40;
const room_max = huffman.encoded_len_max(varied_len_max) + 1;
/// What a buffer holds before a call.
const untouched: u8 = 0xee;
/// The bits `encode` writes at a time.
const word_bits = @bitSizeOf(u32);
/// The octet values, 0 to 255.
const octet_values = std.math.maxInt(u8) + 1;

/// Fails, printing both outcomes, when `encode` and the reference differ on `bytes` with `room`
/// octets of output: in what they return, or in the octets they leave written.
fn expect_same(bytes: []const u8, room: usize) !void {
    var changed_buffer: [room_max]u8 = @splat(untouched);
    var reference_buffer: [room_max]u8 = @splat(untouched);
    var changed = Writer.init(changed_buffer[0..room]);
    var reference = Writer.init(reference_buffer[0..room]);
    const changed_result = huffman.encode(bytes, &changed);
    const reference_result = encode_by_octets(bytes, &reference);
    const same_result = std.meta.eql(changed_result, reference_result);
    if (same_result and std.mem.eql(u8, changed.written(), reference.written())) return;
    std.debug.print("first difference: input {x} with room {d}: encode {any} {x}, reference {any} {x}\n", .{
        bytes, room, changed_result, changed.written(), reference_result, reference.written(),
    });
    return error.TestUnexpectedResult;
}

/// The bits of code `bytes` leaves waiting once `encode` has written its last whole word.
fn waiting_bits(bytes: []const u8) usize {
    var bit_total: usize = 0;
    for (bytes) |byte| bit_total += table.codes[byte].bit_count;
    return bit_total % word_bits;
}

test "encode writes what the reference writes, at every length and in every room" {
    var seen: [word_bits]bool = @splat(false);
    var bytes: [varied_len_max]u8 = undefined;
    // Octets that step through the table by a stride, so that the strings mix code lengths.
    for ([_]usize{ 1, 7, 29, 131 }) |stride| {
        for (&bytes, 0..) |*byte, index| byte.* = @truncate((index + 1) * stride);
        for (0..bytes.len + 1) |len| {
            const input = bytes[0..len];
            seen[waiting_bits(input)] = true;
            // No room, each room short of the code, the room that holds it, and one octet more.
            for (0..huffman.encoded_len(input) + 2) |room| try expect_same(input, room);
        }
    }
    // The strings left every count of waiting bits, 0 to 31, so the tail ran each of its paths.
    for (seen) |count_seen| try testing.expect(count_seen);
}

test "encode writes what the reference writes for every pair of octets, with room and an octet short" {
    for (0..octet_values) |first| {
        for (0..octet_values) |second| {
            const pair = [_]u8{ @intCast(first), @intCast(second) };
            const needed = huffman.encoded_len(&pair);
            try expect_same(&pair, needed);
            try expect_same(&pair, needed - 1);
        }
    }
}

test "encode writes what the reference writes for the strings the judge's exchange carries" {
    const strings = [_][]const u8{
        "", "8", "200", "text/plain; charset=utf-8", "127.0.0.1:8080", "h2load nghttp2/1.59.0",
    };
    for (strings) |text| {
        for (0..huffman.encoded_len(text) + 2) |room| try expect_same(text, room);
    }
}

test "four codes of eight bits fill one word, and encode writes it with nothing waiting" {
    // RFC 7541 Appendix B: '&' is 11111000, eight bits.
    try testing.expectEqual(0, waiting_bits("&&&&"));
    var buffer: [room_max]u8 = @splat(untouched);
    var output = Writer.init(&buffer);
    try huffman.encode("&&&&", &output);
    try testing.expectEqualSlices(u8, &.{ 0xf8, 0xf8, 0xf8, 0xf8 }, output.written());
}
