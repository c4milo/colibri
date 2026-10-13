//! The string literal the HPACK encoder writes when it Huffman-codes a string only where the code
//! is shorter than the string (RFC 7541 §5.2), split off encoder.zig for length. The code's length
//! is measured once: it chooses the coding and it is the literal's length.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");

const Writer = core.Writer;

/// The H flag of a string literal: the highest bit of its prefix (RFC 7541 §5.2).
const huffman_flag: u8 = 1 << (constants.string_prefix_bits - 1);

/// Writes `octets` as a string literal, Huffman-coded when the code is shorter than the octets and
/// raw otherwise. All of the octets are written, or none.
pub fn write_shorter(output: *Writer, octets: []const u8) core.writer.Error!void {
    const coded_len = wire.huffman.encoded_len(octets);
    if (coded_len >= octets.len) return wire.string_literal.encode(constants.string_prefix_bits, output, 0, octets, .raw);
    assert(coded_len < octets.len);
    var cursor = output.*;
    // RFC 7541 §5.2: the H flag set, then the length of the Huffman code as an integer with a
    // prefix of the seven bits below the flag (§5.1), then the code.
    try wire.prefixed_integer.encode(constants.string_prefix_bits - 1, &cursor, huffman_flag, coded_len);
    try wire.huffman.encode(octets, &cursor);
    // The literal is its length's octets and then the code.
    assert(cursor.offset - output.offset > coded_len);
    output.* = cursor;
}

// The tests below hold `write_shorter` to the code it replaced, which measured the string once to
// choose the coding and once more inside `string_literal.encode`. It stays here as the reference.

/// The reference: the string as the encoder wrote it before.
fn write_by_two_measures(output: *Writer, octets: []const u8) core.writer.Error!void {
    const coding: wire.string_literal.Coding = if (wire.huffman.encoded_len(octets) < octets.len) .huffman else .raw;
    try wire.string_literal.encode(constants.string_prefix_bits, output, 0, octets, coding);
}

/// The longest string the tests vary, and the longest run of one octet: a run of a 5-bit code
/// this long Huffman-codes to more than 127 octets, whose length takes two octets of a 7-bit
/// prefix (RFC 7541 §5.1).
const varied_len_max = 40;
const run_len_max = 220;
/// The rooms the tests give a string past its raw literal's length: its length's octets, and one
/// octet more.
const rooms_past_string = 3;
const room_max = run_len_max + rooms_past_string;
/// What a buffer holds before a call.
const untouched: u8 = 0xee;
/// The octet values, 0 to 255.
const octet_values = std.math.maxInt(u8) + 1;

/// Fails, printing both outcomes, when `write_shorter` and the reference differ on `octets` with
/// `room` octets of output: in whether they fail, or in the octets they leave written.
fn expect_same(octets: []const u8, room: usize) !void {
    var changed_buffer: [room_max]u8 = @splat(untouched);
    var reference_buffer: [room_max]u8 = @splat(untouched);
    var changed = Writer.init(changed_buffer[0..room]);
    var reference = Writer.init(reference_buffer[0..room]);
    const changed_failed = if (write_shorter(&changed, octets)) false else |_| true;
    const reference_failed = if (write_by_two_measures(&reference, octets)) false else |_| true;
    const same = changed_failed == reference_failed and changed.offset == reference.offset and
        std.mem.eql(u8, &changed_buffer, &reference_buffer);
    if (same) return;
    std.debug.print("first difference: string {x}, room {d}: write_shorter {} {x}, reference {} {x}\n", .{
        octets, room, changed_failed, changed.written(), reference_failed, reference.written(),
    });
    return error.TestUnexpectedResult;
}

/// Compares on `octets` in each room from none to one octet past its raw literal.
fn expect_same_in_every_room(octets: []const u8) !void {
    for (0..octets.len + rooms_past_string + 1) |room| try expect_same(octets, room);
}

test "write_shorter writes what the reference writes for every string of up to two octets" {
    var octets: [2]u8 = undefined;
    try expect_same_in_every_room(octets[0..0]);
    for (0..octet_values) |first| {
        octets[0] = @intCast(first);
        try expect_same_in_every_room(octets[0..1]);
        for (0..octet_values) |second| {
            octets[1] = @intCast(second);
            try expect_same_in_every_room(&octets);
        }
    }
}

test "write_shorter writes what the reference writes for strings that mix code lengths, at every length" {
    var octets: [varied_len_max]u8 = undefined;
    // Octets that step through the table by a stride, so that the strings mix short and long codes.
    for ([_]usize{ 1, 7, 29, 131 }) |stride| {
        for (&octets, 0..) |*octet, index| octet.* = @truncate((index + 1) * stride);
        for (0..octets.len + 1) |len| try expect_same_in_every_room(octets[0..len]);
    }
}

test "write_shorter writes what the reference writes for the strings a response carries" {
    const strings = [_][]const u8{ "", "8", "200", "text/plain; charset=utf-8", "colibri", "302", "307" };
    for (strings) |text| try expect_same_in_every_room(text);
}

test "write_shorter writes what the reference writes for runs that Huffman-code past a one-octet length" {
    var run: [run_len_max]u8 = undefined;
    // RFC 7541 Appendix B: 'a', 'e' and '0' have codes of five bits, so their runs code shorter.
    for ("ae0") |octet| {
        @memset(&run, octet);
        for (0..run.len + 1) |len| try expect_same_in_every_room(run[0..len]);
    }
}
