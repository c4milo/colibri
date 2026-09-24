//! Design §9's two QPACK command-line tools, for the QIF interop of step 11, over colibri's
//! encoder and decoder:
//!
//!     qif encode <input.qif> <output> <capacity> <blocked-streams> <acknowledgment>
//!     qif decode <input> <output.qif> <capacity> <blocked-streams>
//!
//! The capacity and the blocked streams are the decoder's two settings (RFC 9204 §5), which the
//! encoder and decoder of one interop run must share. `<acknowledgment>` is the "QPACK Offline
//! Interop" format's mode: 1 for immediate, 0 for none. The QIF text is `qif/qif_text.zig`'s, and
//! the encoded file `qif/qif_block.zig`'s.
//!
//! Exit status: 0 on success, 1 when the input could not be encoded or decoded, 2 on a usage error.
const std = @import("std");
const core = @import("core");
const qpack = @import("qpack");
const check_file = @import("tls/check_file.zig");
const constants = @import("qif/constants.zig");
pub const qif_text = @import("qif/qif_text.zig");
pub const qif_block = @import("qif/qif_block.zig");
pub const qif_encode = @import("qif/qif_encode.zig");
pub const qif_decode = @import("qif/qif_decode.zig");

const Writer = core.Writer;

pub const Command = union(enum) {
    encode: struct { input: []const u8, output: []const u8, settings: qif_encode.Settings },
    decode: struct { input: []const u8, output: []const u8, settings: qif_decode.Settings },
};

/// The words of the longer command, `encode`'s, and where each one is.
const encode_words = 6;
const decode_words = 5;
const word_input = 1;
const word_output = 2;
const word_capacity = 3;
const word_blocked = 4;
const word_acknowledgment = 5;
/// The acknowledgment mode's two values: none, and immediate.
const acknowledgment_immediate: u64 = 1;

/// The radix every number on the command line is written in.
const decimal: u8 = 10;

var input_storage: [constants.file_len_max]u8 = undefined;
var output_storage: [constants.file_len_max]u8 = undefined;

pub fn main(init: std.process.Init.Minimal) void {
    var iterator = std.process.Args.Iterator.init(init.args);
    _ = iterator.next();
    var words: [encode_words][]const u8 = undefined;
    var count: usize = 0;
    // Bounded by `words`: one more argument is a usage error.
    while (iterator.next()) |word| {
        if (count == words.len) usage();
        words[count] = word;
        count += 1;
    }
    const command = parse(words[0..count]) orelse usage();
    const input_path = switch (command) {
        inline else => |held| held.input,
    };
    const input = check_file.read_file(input_path, &input_storage) catch usage();
    if (input.len == input_storage.len) fail("{s} is larger than {d} octets", .{ input_path, input_storage.len });
    var output = Writer.init(&output_storage);
    switch (command) {
        .encode => |held| {
            const counts = qif_encode.encode(input, &output, held.settings) catch |failure| fail("cannot encode: {t}", .{failure});
            finish(held.output, output.written());
            std.debug.print("qif: encoded {d} sections, {d} lines, {d} inserts\n", .{ counts.sections, counts.lines, counts.inserts });
        },
        .decode => |held| {
            const counts = qif_decode.decode(input, &output, held.settings) catch |failure| fail("cannot decode: {t}", .{failure});
            finish(held.output, output.written());
            std.debug.print("qif: decoded {d} sections, {d} lines, {d} blocked\n", .{ counts.sections, counts.lines, counts.blocked });
        },
    }
}

/// The command `words`, the program name left out, asks for, or null.
pub fn parse(words: []const []const u8) ?Command {
    if (words.len == encode_words and std.mem.eql(u8, words[0], "encode")) {
        const acknowledgment = number(words[word_acknowledgment]) orelse return null;
        if (acknowledgment > acknowledgment_immediate) return null;
        return .{ .encode = .{ .input = words[word_input], .output = words[word_output], .settings = .{
            .max_table_capacity = number(words[word_capacity]) orelse return null,
            .blocked_streams = number(words[word_blocked]) orelse return null,
            .immediate_acknowledgment = acknowledgment == acknowledgment_immediate,
        } } };
    }
    if (words.len == decode_words and std.mem.eql(u8, words[0], "decode")) {
        const settings: qif_decode.Settings = .{
            .max_table_capacity = number(words[word_capacity]) orelse return null,
            .blocked_streams = number(words[word_blocked]) orelse return null,
        };
        // colibri's decoder holds at most these (decision 35 and decision 74).
        if (settings.max_table_capacity > qpack.constants.dynamic_table_capacity_max) return null;
        if (settings.blocked_streams > qpack.constants.blocked_streams_max) return null;
        return .{ .decode = .{ .input = words[word_input], .output = words[word_output], .settings = settings } };
    }
    return null;
}

fn number(word: []const u8) ?u64 {
    return std.fmt.parseUnsigned(u64, word, decimal) catch null;
}

fn finish(path: []const u8, octets: []const u8) void {
    if (!check_file.write_file(path, octets)) fail("cannot write {s}", .{path});
}

fn usage() noreturn {
    std.debug.print(
        "usage: qif encode <input.qif> <output> <capacity> <blocked-streams> <acknowledgment 0|1>\n" ++
            "       qif decode <input> <output.qif> <capacity up to {d}> <blocked-streams up to {d}>\n",
        .{ qpack.constants.dynamic_table_capacity_max, qpack.constants.blocked_streams_max },
    );
    std.process.exit(check_file.exit_usage);
}

fn fail(comptime format: []const u8, values: anytype) noreturn {
    std.debug.print("qif: " ++ format ++ "\n", values);
    std.process.exit(check_file.exit_failed);
}

const testing = std.testing;

test {
    std.testing.refAllDecls(@This());
    _ = qif_text;
    _ = qif_block;
    _ = qif_encode;
    _ = qif_decode;
}

test "the two commands and their settings are read, and anything else is refused" {
    const encode = parse(&.{ "encode", "in.qif", "out", "4096", "100", "1" }).?.encode;
    try testing.expectEqual(4096, encode.settings.max_table_capacity);
    try testing.expect(encode.settings.immediate_acknowledgment);
    const decode = parse(&.{ "decode", "in", "out.qif", "220", "0" }).?.decode;
    try testing.expectEqual(220, decode.settings.max_table_capacity);
    try testing.expectEqual(null, parse(&.{ "encode", "in.qif", "out", "4096", "100", "2" }));
    try testing.expectEqual(null, parse(&.{ "decode", "in", "out.qif", "16385", "0" }));
    try testing.expectEqual(null, parse(&.{ "decode", "in", "out.qif", "220", "101" }));
    try testing.expectEqual(null, parse(&.{ "decode", "in", "out.qif", "x", "0" }));
    try testing.expectEqual(null, parse(&.{"encode"}));
}

/// A QIF text with repeated lines, so a table has something to reference. Test-only.
const sample =
    "# stream 1\n:method\tGET\n:path\t/a\nx-a\tvalue\n\n" ++
    ":method\tGET\n:path\t/b\nx-a\tvalue\n\n" ++
    ":method\tPOST\nx-a\tvalue\ncookie\tc=1\n\n";

/// Room for the tests' files. Test-only.
const test_room: usize = 4096;
var test_encoded: [test_room]u8 = undefined;
var test_decoded: [test_room]u8 = undefined;
var test_expected: qpack.http.field_section.FieldSection = undefined;
var test_got: qpack.http.field_section.FieldSection = undefined;

/// Requires `decoded` to hold `sample`'s sets in order. Test-only.
fn expect_sample(decoded: []const u8) !void {
    var expected = qif_text.Reader.init(sample);
    var got = qif_text.Reader.init(decoded);
    // Bounded by the sample's sets.
    while (try expected.next(&test_expected)) {
        try testing.expect(try got.next(&test_got));
        try testing.expectEqual(test_expected.len(), test_got.len());
        for (0..test_expected.len()) |index| {
            try testing.expectEqualStrings(test_expected.get(@intCast(index)).name, test_got.get(@intCast(index)).name);
            try testing.expectEqualStrings(test_expected.get(@intCast(index)).value, test_got.get(@intCast(index)).value);
        }
    }
    try testing.expect(!try got.next(&test_got));
}

test "what encode writes, decode reads back, in both acknowledgment modes" {
    for ([_]bool{ false, true }) |immediate| {
        var encoded = Writer.init(&test_encoded);
        const written = try qif_encode.encode(sample, &encoded, .{ .max_table_capacity = 220, .blocked_streams = 1, .immediate_acknowledgment = immediate });
        try testing.expectEqual(3, written.sections);
        try testing.expect(written.inserts > 0);
        var decoded = Writer.init(&test_decoded);
        const read = try qif_decode.decode(encoded.written(), &decoded, .{ .max_table_capacity = 220, .blocked_streams = 1 });
        try testing.expectEqual(3, read.sections);
        // Each section's encoder stream octets come ahead of it, so nothing blocks.
        try testing.expectEqual(0, read.blocked);
        try expect_sample(decoded.written());
    }
}

test "immediate acknowledgment lets a stream that may not block reference what it inserted" {
    // With no blocked streams, an encoder that hears nothing never references its inserts, and
    // one that hears the acknowledgments does, so its file is shorter.
    var lengths: [2]usize = undefined;
    for ([_]bool{ false, true }, &lengths) |immediate, *len| {
        var encoded = Writer.init(&test_encoded);
        _ = try qif_encode.encode(sample, &encoded, .{ .max_table_capacity = 220, .blocked_streams = 0, .immediate_acknowledgment = immediate });
        len.* = encoded.written().len;
    }
    try testing.expect(lengths[1] < lengths[0]);
}

test "the offline format's table starts at its maximum capacity, with no instruction setting it" {
    // An insert of `a: b` and a section referencing it, and no Set Dynamic Table Capacity.
    var file_octets: [test_room]u8 = undefined;
    var file = Writer.init(&file_octets);
    try qif_block.write(&file, constants.encoder_stream_id, &.{ 0x41, 'a', 0x01, 'b' });
    try qif_block.write(&file, constants.first_request_stream_id, &.{ 0x02, 0x00, 0x80 });
    var decoded = Writer.init(&test_decoded);
    const read = try qif_decode.decode(file.written(), &decoded, .{ .max_table_capacity = 220, .blocked_streams = 0 });
    try testing.expectEqual(1, read.sections);
    try testing.expectEqualStrings("# stream 1\na\tb\n\n", decoded.written());
}

test "a section ahead of the encoder stream it needs blocks, and decodes once it arrives" {
    var encoded = Writer.init(&test_encoded);
    _ = try qif_encode.encode("x-a\tvalue\n\n", &encoded, .{ .max_table_capacity = 220, .blocked_streams = 1, .immediate_acknowledgment = false });
    // The file is the encoder stream block, then the section's; swap them.
    var reader = core.Reader.init(encoded.written());
    const instructions = try qif_block.read(&reader);
    const section = try qif_block.read(&reader);
    var swapped_octets: [test_room]u8 = undefined;
    var swapped = Writer.init(&swapped_octets);
    try qif_block.write(&swapped, section.stream_id, section.octets);
    try qif_block.write(&swapped, instructions.stream_id, instructions.octets);
    var decoded = Writer.init(&test_decoded);
    const read = try qif_decode.decode(swapped.written(), &decoded, .{ .max_table_capacity = 220, .blocked_streams = 1 });
    try testing.expectEqual(1, read.blocked);
    try testing.expectEqual(1, read.sections);
    // With no blocked stream allowed, the decoder refuses the file.
    decoded = Writer.init(&test_decoded);
    try testing.expectError(error.DecompressionFailed, qif_decode.decode(swapped.written(), &decoded, .{ .max_table_capacity = 220, .blocked_streams = 0 }));
    // And a file that ends before the entries arrive is refused too.
    decoded = Writer.init(&test_decoded);
    try testing.expectError(error.StillBlocked, qif_decode.decode(swapped.written()[0 .. constants.block_header_len + section.octets.len], &decoded, .{ .max_table_capacity = 220, .blocked_streams = 1 }));
}
