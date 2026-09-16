//! Tests for the peer-index rule: one fixture per shape its header names.

const std = @import("std");
const testing = std.testing;
const pepegrillo = @import("pepegrillo");
const harness = pepegrillo.lint.harness;
const peer_index = @import("peer_index.zig");

fn expect_findings(path: []const u8, source: [:0]const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), peer_index, path, source);
    try harness.expect_messages(findings, expected);
}

fn message(comptime read: []const u8) []const u8 {
    return "index reads " ++ read ++ ", which a Reader produced; take the octets through" ++
        " core.Reader, which checks the bound (invariant 3)";
}

const length_fixture: [:0]const u8 =
    \\pub fn parse(reader: *Reader, buffer: []u8) !void {
    \\    const len = try reader.read_int(u16);
    \\    _ = buffer[0..len];
    \\}
;

test "peer-index passes literal indexes, lengths, and values no Reader produced" {
    try expect_findings("src/wire/varint.zig",
        \\pub fn decode(reader: *core.Reader, output: *Writer, buffer: []u8) !u64 {
        \\    const octets = try reader.take(4);
        \\    var value: u64 = octets[0];
        \\    for (octets[1..]) |octet| value = (value << 8) | octet;
        \\    _ = buffer[0..octets.len];
        \\    const written = output.written();
        \\    _ = buffer[written.len - 1];
        \\    for (buffer, 0..) |_, index| _ = buffer[index];
        \\    _ = buffer[Writer.init(buffer).offset];
        \\    return value;
        \\}
        \\pub fn encode(buffer: []u8, len: usize) void {
        \\    _ = buffer[0..len];
        \\}
        \\test "a test slices as it likes" {
        \\    var reader = Reader.init(&bytes);
        \\    const len = try reader.read_int(u8);
        \\    _ = bytes[0..len];
        \\}
    , &.{});
}

test "peer-index flags a length a Reader parameter produced, at a slice end" {
    try expect_findings("src/h2/frame.zig", length_fixture, &.{message("len")});
}

test "peer-index flags an index, a slice start and a sentinel" {
    try expect_findings("src/h2/frame.zig",
        \\pub fn parse(cursor: Reader, buffer: [:0]u8) !void {
        \\    const at = try cursor.read_int(u8);
        \\    _ = buffer[at];
        \\    _ = buffer[at..];
        \\    _ = buffer[0..1 :at];
        \\}
    , &.{ message("at"), message("at"), message("at") });
}

test "peer-index follows a local Reader, an assignment and each kind of capture" {
    try expect_findings("src/h3/frame.zig",
        \\pub fn parse(bytes: []const u8, table: []const u8) !void {
        \\    var reader = Reader.init(bytes);
        \\    var total: usize = 0;
        \\    total += try varint.decode(&reader);
        \\    _ = table[total];
        \\    var cursor: core.Reader = undefined;
        \\    const octets = try cursor.take(2);
        \\    for (octets, 0..) |octet, index| _ = table[index..octet];
        \\    for (octets) |*slot| _ = table[slot.*];
        \\    for (table, octets) |_, second| _ = table[second];
        \\    if (reader.peek()) |next| _ = table[next];
        \\    while (reader.next()) |*item| _ = table[item.*];
        \\    _ = table[Reader.init(bytes).offset];
        \\}
    , &.{
        message("total"),
        message("octet"),
        message("slot"),
        message("second"),
        message("next"),
        message("item"),
        message("Reader.init"),
    });
}

test "peer-index reads each function, a nested one too, with only its own names" {
    try expect_findings("src/h2/frame.zig",
        \\pub fn parse(reader: *Reader, table: []u8) !u16 {
        \\    const len = try reader.read_int(u16);
        \\    const Local = struct {
        \\        fn fill(buffer: []u8, len: usize) void {
        \\            _ = buffer[0..len];
        \\        }
        \\    };
        \\    _ = Local;
        \\    _ = table[len];
        \\    return len;
        \\}
        \\pub fn fill(buffer: []u8, len: usize) void {
        \\    _ = buffer[0..len];
        \\}
    , &.{message("len")});
}

test "peer-index reads src/ but not the reader, the writer or the tools" {
    try expect_findings("src/testing/endpoint.zig", length_fixture, &.{message("len")});
    try expect_findings("src/core/fuzz.zig", length_fixture, &.{message("len")});
    try expect_findings("src/core/reader.zig", length_fixture, &.{});
    try expect_findings("src/core/writer.zig", length_fixture, &.{});
    try expect_findings("tools/golden.zig", length_fixture, &.{});
    try expect_findings("build/modules.zig", length_fixture, &.{});
}
