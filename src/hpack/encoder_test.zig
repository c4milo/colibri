//! The tests of `encoder.zig`: RFC 7541 Appendix C's examples byte for byte, the size updates,
//! the static index against a scan, and the blocks a caller abandons (decision 132). Test-only.
const std = @import("std");
const core = @import("core");
const constants = @import("constants.zig");
const static_table = @import("static_table.zig");
const dynamic_table = @import("dynamic_table.zig");
const encoder_file = @import("encoder.zig");

const Writer = core.Writer;
const Match = dynamic_table.Match;
const Encoder = encoder_file.Encoder;
const find_static = encoder_file.find_static;
const Indexing = encoder_file.Indexing;
const Decoder = @import("decoder.zig").Decoder;

const testing = std.testing;
const Field = dynamic_table.Field;

/// The encoder the tests run in, placed outside any stack frame.
threadlocal var test_encoder: Encoder align(@alignOf(Encoder)) = undefined;

/// Octets of block the tests write. Test-only.
const test_block_len_max = 256;

fn expect_block(lines: []const Field, expected: []const u8) !void {
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    for (lines) |line| try test_encoder.write_field(&output, line.name, line.value, .incremental);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, expected, output.written());
}

const example_request_lines = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "www.example.com" },
};

const second_request_lines = example_request_lines ++ [_]Field{
    .{ .name = "cache-control", .value = "no-cache" },
};

const third_request_lines = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = "custom-key", .value = "custom-value" },
};

test "RFC 7541 Appendix C.3: the encoder writes the three requests byte for byte, no Huffman" {
    test_encoder.init(4096, .never);
    try expect_block(&example_request_lines, "\x82\x86\x84\x41\x0fwww.example.com");
    try expect_block(&second_request_lines, "\x82\x86\x84\xbe\x58\x08no-cache");
    try expect_block(&third_request_lines, "\x82\x87\x85\xbf\x40\x0acustom-key\x0ccustom-value");
    try testing.expectEqual(164, test_encoder.table.size);
}

test "RFC 7541 Appendix C.4: with Huffman coding the encoder writes the same requests" {
    test_encoder.init(4096, .always);
    try expect_block(&example_request_lines, "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff");
    try expect_block(&second_request_lines, "\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf");
    try expect_block(&third_request_lines, "\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf");
}

const first_response_lines = [_]Field{
    .{ .name = ":status", .value = "302" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
};

const second_response_lines = [_]Field{
    .{ .name = ":status", .value = "307" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
};

const third_response_lines = [_]Field{
    .{ .name = ":status", .value = "200" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
};

test "RFC 7541 Appendix C.5: the responses at capacity 256, evictions included, no Huffman" {
    test_encoder.init(256, .never);
    try expect_block(&first_response_lines, "\x48\x03" ++ "302" ++ "\x58\x07private\x61\x1dMon, 21 Oct 2013 20:13:21 GMT\x6e\x17https://www.example.com");
    try expect_block(&second_response_lines, "\x48\x03" ++ "307" ++ "\xc1\xc0\xbf");
    try expect_block(&third_response_lines, "\x88\xc1\x61\x1dMon, 21 Oct 2013 20:13:22 GMT\xc0\x5a\x04gzip\x77\x38foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1");
    try testing.expectEqual(215, test_encoder.table.size);
}

test "RFC 7541 Appendix C.6: the same responses with Huffman coding" {
    test_encoder.init(256, .always);
    try expect_block(&first_response_lines, "\x48\x82\x64\x02\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3");
    try expect_block(&second_response_lines, "\x48\x83\x64\x0e\xff\xc1\xc0\xbf");
    try expect_block(&third_response_lines, "\x88\xc1\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x84\xa6\x2d\x1b\xff\xc0\x5a\x83\x9b\xd9\xab\x77\xad\x94\xe7\x82\x1d\xd7\xf2\xe6\xc7\xb3\x35\xdf\xdf\xcd\x5b\x39\x60\xd5\xaf\x27\x08\x7f\x36\x72\xc1\xab\x27\x0f\xb5\x29\x1f\x95\x87\x31\x60\x65\xc0\x03\xed\x4e\xe5\xb1\x06\x3d\x50\x07");
}

test "when_shorter codes 302 with Huffman, which saves an octet, and not 307, which saves none" {
    test_encoder.init(256, .when_shorter);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, ":status", "302", .without_indexing);
    try test_encoder.write_field(&output, ":status", "307", .without_indexing);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x08\x82\x64\x02\x08\x03" ++ "307", output.written());
}

test "never-indexed and without-indexing lines leave the table alone, and keep a name index" {
    test_encoder.init(4096, .never);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, "authorization", "secret", .never_indexed);
    try test_encoder.write_field(&output, "x-trace", "1", .without_indexing);
    try test_encoder.write_field(&output, ":method", "GET", .never_indexed);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x1f\x08\x06secret\x00\x07x-trace\x011\x12\x03GET", output.written());
    try testing.expectEqual(0, test_encoder.table.len());
}

test "a line too large for the table is sent without indexing rather than emptying it" {
    test_encoder.init(40, .never);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, "a", "b", .incremental);
    try test_encoder.write_field(&output, "c", "dddddddd", .incremental);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x40\x01a\x01b\x00\x01c\x08dddddddd", output.written());
    try testing.expectEqual(1, test_encoder.table.len());
}

test "a line that exactly fills the table is indexed" {
    test_encoder.init(34, .never);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, "a", "b", .incremental);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x40\x01a\x01b", output.written());
    try testing.expectEqual(1, test_encoder.table.len());
}

test "a lowered then raised limit opens the next block with the smallest size, then the final" {
    test_encoder.init(4096, .never);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, "a", "b", .incremental);
    try test_encoder.write_field(&output, "c", "d", .incremental);
    test_encoder.commit_block();
    test_encoder.set_capacity_limit(40);
    test_encoder.set_capacity_limit(100);
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x3f\x09\x3f\x45", output.written());
    try testing.expectEqual(100, test_encoder.table.capacity);
    try testing.expectEqual(1, test_encoder.table.len());
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqual(0, output.offset);
    test_encoder.set_capacity_limit(constants.dynamic_table_capacity_max * 2);
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x3f\xe1\x7f", output.written());
    try testing.expectEqual(constants.dynamic_table_capacity_max, test_encoder.table.capacity);
}

test "a field that does not fit the output is not written at all, and not inserted" {
    test_encoder.init(4096, .never);
    var buffer: [4]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try testing.expectError(error.NoSpaceLeft, test_encoder.write_field(&output, "a", "bcdef", .incremental));
    test_encoder.commit_block();
    try testing.expectEqual(0, output.offset);
    try testing.expectEqual(0, test_encoder.table.len());
}

test "a block the caller abandons owes its size update again" {
    test_encoder.init(4096, .never);
    test_encoder.set_capacity_limit(100);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try testing.expectEqualSlices(u8, "\x3f\x45", output.written());
    // The caller found no room for a field line and threw the block away, so the peer never read
    // the update. RFC 7541 §4.2: the decoder's table holds the capacity last declared to it, so
    // the next block owes the same update.
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x3f\x45", output.written());
    // A block that was committed does not repeat it.
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqual(0, output.offset);
}

/// The scan `find_static` replaced, kept as the reference its index must agree with. Test-only.
fn find_static_scan(name: []const u8, value: []const u8) Match {
    var match: Match = .{};
    for (static_table.entries, 1..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (match.name == null) match.name = @intCast(index);
        if (std.mem.eql(u8, entry.value, value)) {
            match.exact = @intCast(index);
            return match;
        }
    }
    return match;
}

/// Fails, naming the line, when the index and the scan differ on it. Test-only.
fn expect_same_match(name: []const u8, value: []const u8) !void {
    const indexed = find_static(name, value);
    const scanned = find_static_scan(name, value);
    if (std.meta.eql(indexed, scanned)) return;
    std.debug.print("first difference: name \"{s}\" value \"{s}\": index {any}, scan {any}\n", .{ name, value, indexed, scanned });
    return error.TestUnexpectedResult;
}

/// The longest name or value a test varies. Test-only.
const varied_len_max: usize = 64;

test "RFC 7541 Appendix A: the static index finds what the scan finds, for every name and value the table holds" {
    // Every name of the table with every value of the table, the empty value among them.
    for (static_table.entries) |named| {
        for (static_table.entries) |valued| try expect_same_match(named.name, valued.value);
        try expect_same_match(named.name, "not in the table");
    }
}

test "RFC 7541 Appendix A: the static index finds nothing for a name one octet away from the table's" {
    try expect_same_match("", "");
    try expect_same_match("x-forwarded-for", "");
    var varied: [varied_len_max + 1]u8 = undefined;
    for (static_table.entries) |entry| {
        const name = entry.name;
        // The name one octet shorter, one octet longer, and with each octet changed.
        if (name.len > 0) try expect_same_match(name[0 .. name.len - 1], entry.value);
        @memcpy(varied[0..name.len], name);
        varied[name.len] = 'x';
        try expect_same_match(varied[0 .. name.len + 1], entry.value);
        for (0..name.len) |position| {
            @memcpy(varied[0..name.len], name);
            varied[position] ^= 0x20;
            try expect_same_match(varied[0..name.len], entry.value);
        }
    }
}

/// The decoder of the tests below, as the peer: it reads the blocks the encoder committed and no
/// other. Placed outside any stack frame. Test-only.
threadlocal var peer_decoder: Decoder align(@alignOf(Decoder)) = undefined;

/// The field lines the tests below write, each one in a block of its own or with the others.
const abandon_lines = [_]Field{
    .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    .{ .name = "x-a", .value = "1" },
    .{ .name = "x-b", .value = "22" },
    .{ .name = "date", .value = "Thu, 29 Oct 2026 20:00:00 GMT" },
};

/// The size updates that empty both tables and declare the capacity again: 0 (RFC 7541 §6.3's
/// pattern 001), then 4,096 as 31 and 4,065 in a 5-bit prefix (§5.1).
const empty_then_4096 = "\x20\x3f\xe1\x1f";

/// Writes `lines` as one block with `indexing`, commits it, and requires the peer's decoder to
/// read the same lines and to hold as many entries as the encoder's mirror.
fn expect_committed(lines: []const Field, indexing: Indexing) ![]const u8 {
    const holder = struct {
        threadlocal var buffer: [test_block_len_max]u8 = undefined;
    };
    var output = Writer.init(&holder.buffer);
    try test_encoder.begin_block(&output);
    for (lines) |line| try test_encoder.write_field(&output, line.name, line.value, indexing);
    test_encoder.commit_block();
    var block = peer_decoder.block(output.written());
    for (lines) |line| {
        const decoded = (try block.next()) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(line.name, decoded.name);
        try testing.expectEqualStrings(line.value, decoded.value);
    }
    try testing.expectEqual(null, try block.next());
    try testing.expectEqual(test_encoder.table.len(), peer_decoder.table.len());
    try testing.expectEqual(test_encoder.table.size, peer_decoder.table.size);
    return output.written();
}

/// Writes `lines` into a block with `indexing`, and abandons it: the peer never reads it.
fn abandon(lines: []const Field, indexing: Indexing) !void {
    var buffer: [test_block_len_max]u8 = undefined;
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    for (lines) |line| try test_encoder.write_field(&output, line.name, line.value, indexing);
}

test "decision 132: a block abandoned after an insert makes the next one empty both tables" {
    test_encoder.init(4096, .never);
    peer_decoder.init(4096);
    _ = try expect_committed(abandon_lines[0..1], .incremental);
    // The peer never reads this block, whose insert the mirror holds.
    try abandon(abandon_lines[1..2], .incremental);
    const next = try expect_committed(abandon_lines[0..1], .incremental);
    // RFC 7541 §6.3: the block opens with the two updates, and the line the peer held before is a
    // literal again, since both tables are empty.
    try testing.expectStringStartsWith(next, empty_then_4096);
    try testing.expectEqual(0x40, next[empty_then_4096.len] & 0xc0);
    // The block after it owes nothing, and finds the line in both tables.
    const after = try expect_committed(abandon_lines[0..1], .incremental);
    try testing.expectEqual(1, after.len);
}

test "decision 132: a block abandoned with no insert, or committed, owes no update" {
    test_encoder.init(4096, .never);
    peer_decoder.init(4096);
    _ = try expect_committed(abandon_lines[0..2], .incremental);
    // A line both tables hold is an index, which inserts nothing.
    try abandon(abandon_lines[0..2], .incremental);
    try abandon(abandon_lines[2..3], .without_indexing);
    const next = try expect_committed(abandon_lines[0..2], .incremental);
    try testing.expectEqual(2, next.len);
}

/// What one fuzz step chooses: a line of `abandon_lines`, then a representation, then whether the
/// block commits. Test-only.
const representations = [_]Indexing{ .incremental, .without_indexing };
const endings = [_]bool{ true, false };
const step_choices = abandon_lines.len * representations.len * endings.len;

/// The steps of one fuzz input, at most, and the capacity the two tables hold: small, so that the
/// inserts also evict. Test-only.
const fuzz_steps_max = 32;
const fuzz_capacity = 128;

fn fuzz_abandon(_: void, smith: *testing.Smith) anyerror!void {
    var steps: [fuzz_steps_max]u8 = @splat(0);
    const len = smith.slice(&steps);
    test_encoder.init(fuzz_capacity, .when_shorter);
    peer_decoder.init(fuzz_capacity);
    for (steps[0..len]) |step| {
        const choice = step % step_choices;
        const at = choice % abandon_lines.len;
        const indexing = representations[(choice / abandon_lines.len) % representations.len];
        if (endings[choice / (abandon_lines.len * representations.len)]) {
            _ = try expect_committed(abandon_lines[at .. at + 1], indexing);
        } else {
            try abandon(abandon_lines[at .. at + 1], indexing);
        }
    }
    // A last block reads the same lines whatever the steps left owed.
    _ = try expect_committed(&abandon_lines, .incremental);
}

test "fuzz: the peer decodes each committed block, and its table matches the mirror, after any abandoned blocks" {
    try testing.fuzz({}, fuzz_abandon, .{ .corpus = &.{
        core.fuzz.input("\x00\x08\x01"),
        core.fuzz.input("\x01\x09\x02\x0a\x03\x0b"),
        core.fuzz.input("\x08\x08\x08\x00"),
    } });
    try core.fuzz.sweep(fuzz_abandon, null);
}
