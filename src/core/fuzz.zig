//! The fuzz harness every decoder's tests share (decision 29). Test-only: nothing outside a `test`
//! block references it, so it is never compiled into the library.
//!
//! Each decoder has one property function of the shape `std.testing.fuzz` takes. Two things drive
//! it, and neither reads randomness (invariant 5):
//!   1. `std.testing.fuzz` with a corpus. Under `zig build test` it runs the corpus and an empty
//!      input; under `--fuzz` it runs the fuzzer.
//!   2. `sweep`, which runs the same function once for every octet string of up to
//!      `sweep_len_max` octets, so every short input is checked on every `zig build test`.
//!
//! A corpus entry is not the raw octets. Outside `--fuzz`, `std.testing.Smith` reads a slice as a
//! 4-octet little-endian length and then the octets, and reads an integer as 8 little-endian octets.
//! `input` and `input_with_value` write entries in that shape, so a corpus entry reaches the
//! property function as the octets it names.
const std = @import("std");
const assert = std.debug.assert;

const Smith = std.testing.Smith;

/// The longest octet string `sweep` enumerates. Two octets is 65,793 inputs per value swept.
pub const sweep_len_max = 2;

/// Octets `Smith` reads for a slice's length, and for an integer value.
const slice_length_octets = 4;
const value_octets = 8;

/// A corpus entry that makes `Smith.slice` return exactly `octets`.
pub fn input(comptime octets: []const u8) []const u8 {
    return comptime &(little_endian(u32, octets.len) ++ octets[0..octets.len].*);
}

/// A corpus entry that makes one `Smith` integer read return `value`, then `Smith.slice` return
/// exactly `octets`.
pub fn input_with_value(comptime value: u64, comptime octets: []const u8) []const u8 {
    return comptime &(little_endian(u64, value) ++ input(octets)[0 .. slice_length_octets + octets.len].*);
}

fn little_endian(comptime T: type, comptime value: u64) [@sizeOf(T)]u8 {
    var octets: [@sizeOf(T)]u8 = @splat(0);
    for (&octets, 0..) |*octet, index| octet.* = @truncate(value >> @intCast(8 * index));
    return octets;
}

/// Runs `property` once for every octet string of 0 to `sweep_len_max` octets, and, when `values`
/// is not null, once more for each value in `values` read before the string.
pub fn sweep(
    comptime property: fn (void, *Smith) anyerror!void,
    comptime values: ?struct { min: u64, max: u64 },
) anyerror!void {
    const range = values orelse .{ .min = 0, .max = 0 };
    assert(range.min <= range.max);
    for (range.min..range.max + 1) |value| {
        for (0..sweep_len_max + 1) |len| {
            try sweep_length(property, values != null, value, len);
        }
    }
}

fn sweep_length(
    comptime property: fn (void, *Smith) anyerror!void,
    with_value: bool,
    value: u64,
    len: usize,
) anyerror!void {
    var entry: [value_octets + slice_length_octets + sweep_len_max]u8 = @splat(0);
    const prefix_len: usize = if (with_value) value_octets else 0;
    if (with_value) write_little_endian(entry[0..value_octets], value);
    write_little_endian(entry[prefix_len..][0..slice_length_octets], len);
    const octets = entry[prefix_len + slice_length_octets ..][0..len];
    const count = @as(usize, 1) << @intCast(8 * len);
    for (0..count) |index| {
        write_little_endian(octets, index);
        var smith: Smith = .{ .in = entry[0 .. prefix_len + slice_length_octets + len] };
        try property({}, &smith);
    }
}

fn write_little_endian(octets: []u8, value: u64) void {
    for (octets, 0..) |*octet, index| octet.* = @truncate(value >> @intCast(8 * index));
}

const testing = std.testing;

fn expect_slice(context: []const u8, smith: *Smith) anyerror!void {
    var buffer: [16]u8 = @splat(0);
    const len = smith.slice(&buffer);
    try testing.expectEqualSlices(u8, context, buffer[0..len]);
}

test "a corpus entry reaches the property function as the octets it names" {
    const entry = input("\xc2\x19\x7c");
    var smith: Smith = .{ .in = entry };
    try expect_slice("\xc2\x19\x7c", &smith);
}

test "a corpus entry with a value reads the value first" {
    const entry = input_with_value(5, "\x1f\x9a");
    var smith: Smith = .{ .in = entry };
    try testing.expectEqual(5, smith.valueRangeAtMost(u4, 1, 8));
    var buffer: [4]u8 = @splat(0);
    try testing.expectEqualSlices(u8, "\x1f\x9a", buffer[0..smith.slice(&buffer)]);
}

var sweep_count: usize = 0;
var sweep_longest: usize = 0;

fn count_inputs(_: void, smith: *Smith) anyerror!void {
    var buffer: [sweep_len_max]u8 = @splat(0);
    const len = smith.slice(&buffer);
    sweep_count += 1;
    sweep_longest = @max(sweep_longest, len);
}

test "the sweep visits every string of up to two octets once per value" {
    sweep_count = 0;
    sweep_longest = 0;
    try sweep(count_inputs, null);
    try testing.expectEqual(1 + 256 + 65_536, sweep_count);
    try testing.expectEqual(sweep_len_max, sweep_longest);
    sweep_count = 0;
    try sweep(count_inputs, .{ .min = 2, .max = 4 });
    try testing.expectEqual(3 * (1 + 256 + 65_536), sweep_count);
}
