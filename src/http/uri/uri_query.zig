//! The `name=value` pairs of a request's query (decision 127, design §8 step 24). A program places
//! one `QueryParameters`, passes `Request.query` and a buffer of its own to `read`, and reads a
//! value by its name with `get`.
//!
//! `read` follows the WHATWG URL Standard's `application/x-www-form-urlencoded` parser
//! (`urlencoded-parsing`, in `docs/rfcs/whatwg/url.bs`): it splits the query on "&", skips each
//! empty piece, splits each piece on its first "=", turns "+" into a space, and percent-decodes
//! (RFC 3986 §2.1). A "%" that two hex digits do not follow stays as written, as the URL
//! Standard's percent-decode keeps it. The decoded bytes are handed back as they are: colibri checks
//! no UTF-8 (the owner's ruling of 2026-10-25). Each name and value is a slice of the buffer that
//! `read` was given, valid until the program writes into that buffer again.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const percent = @import("uri_percent.zig");

pub const ReadError = error{
    /// The query holds more pairs than `constants.query_parameters_max`: the table is full.
    Full,
    /// The decoded names and values do not fit the buffer `read` was given.
    NoSpaceLeft,
};

/// The pairs that one `read` wrote: a name and a value for each, in the order of the query.
/// `read` sets `count` to 0 first, so a pair of an earlier read is never read.
pub const QueryParameters = struct {
    names: [constants.query_parameters_max][]const u8 = @splat(""),
    values: [constants.query_parameters_max][]const u8 = @splat(""),
    /// How many entries of `names` and `values` the last `read` wrote.
    count: std.math.IntFittingRange(0, constants.query_parameters_max) = 0,

    /// Reads the pairs of `query`, the bytes after a target's "?", decoding each name and value
    /// into `storage`. A query whose decoded pairs do not fit `storage`, or that holds more than
    /// `constants.query_parameters_max` pairs, is refused, and `count` stays 0.
    pub fn read(parameters: *QueryParameters, query: []const u8, storage: []u8) ReadError!void {
        parameters.count = 0;
        var writer = core.Writer.init(storage);
        var count: usize = 0;
        // URL Standard `urlencoded-parsing` step 1: the sequences between the "&" bytes.
        var pieces = std.mem.splitScalar(u8, query, '&');
        // Bounded: each piece holds at least one byte of the query, or is empty and skipped.
        while (pieces.next()) |piece| {
            // Step 3.1: an empty sequence adds no pair.
            if (piece.len == 0) continue;
            if (count == constants.query_parameters_max) return error.Full;
            // Steps 3.2 and 3.3: the name runs to the first "=", and the value after it.
            const mark = std.mem.indexOfScalar(u8, piece, '=');
            const name = if (mark) |at| piece[0..at] else piece;
            const value = if (mark) |at| piece[at + 1 ..] else "";
            parameters.names[count] = try decode(&writer, name);
            parameters.values[count] = try decode(&writer, value);
            count += 1;
        }
        assert(count <= constants.query_parameters_max);
        parameters.count = @intCast(count);
    }

    /// The value of the first pair named `name`, as URLSearchParams' `get` returns it, or null
    /// when no pair has that name. The names compare byte for byte, after decoding.
    pub fn get(parameters: *const QueryParameters, name: []const u8) ?[]const u8 {
        assert(parameters.count <= constants.query_parameters_max);
        const count = parameters.count;
        for (parameters.names[0..count], parameters.values[0..count]) |held, value| {
            if (std.mem.eql(u8, held, name)) return value;
        }
        return null;
    }
};

/// Writes `encoded` decoded into `writer`, and returns the bytes it wrote: "+" as a space (URL
/// Standard `urlencoded-parsing` step 3.4), and "%" with two hex digits as the byte they name
/// (RFC 3986 §2.1). A "%" that two hex digits do not follow stays as written.
fn decode(writer: *core.Writer, encoded: []const u8) ReadError![]const u8 {
    const first = writer.written().len;
    var index: usize = 0;
    // Bounded: each pass takes one byte of `encoded`, or three for a decoded "%".
    while (index < encoded.len) {
        if (percent.decoded_at(encoded, index)) |value| {
            writer.write_byte(value) catch return error.NoSpaceLeft;
            index += percent.encoded_len;
            continue;
        }
        const byte = encoded[index];
        writer.write_byte(if (byte == '+') ' ' else byte) catch return error.NoSpaceLeft;
        index += 1;
    }
    return writer.written()[first..];
}

const testing = std.testing;

test "decision 127: QueryParameters exports read and get alone" {
    try @import("core").public_names.expect(QueryParameters, &.{ "read", "get" });
}

test "decision 127: read splits on & and on the first =, skips empty pieces, and keeps the order" {
    var parameters: QueryParameters = .{};
    var storage: [64]u8 = undefined;
    try parameters.read("a=1&&b=2=3&c&=4", &storage);
    try testing.expectEqual(4, parameters.count);
    try testing.expectEqualStrings("1", parameters.get("a").?);
    try testing.expectEqualStrings("2=3", parameters.get("b").?);
    try testing.expectEqualStrings("", parameters.get("c").?);
    try testing.expectEqualStrings("4", parameters.get("").?);
    try testing.expectEqual(null, parameters.get("d"));
}

test "decision 127: + is a space, and %XX the byte it names, after the split" {
    var parameters: QueryParameters = .{};
    var storage: [64]u8 = undefined;
    try parameters.read("q=a+b%2Bc&n%61me=%26%3d&x=%E2%82%AC", &storage);
    try testing.expectEqualStrings("a b+c", parameters.get("q").?);
    // An encoded "&" or "=" is decoded after the split, so it stays inside its value.
    try testing.expectEqualStrings("&=", parameters.get("name").?);
    try testing.expectEqualStrings("\xe2\x82\xac", parameters.get("x").?);
}

test "decision 127: a % that two hex digits do not follow stays as written, and no UTF-8 is checked" {
    var parameters: QueryParameters = .{};
    var storage: [64]u8 = undefined;
    try parameters.read("a=50%&b=%zz&c=%4&d=%ff%fe", &storage);
    try testing.expectEqualStrings("50%", parameters.get("a").?);
    try testing.expectEqualStrings("%zz", parameters.get("b").?);
    try testing.expectEqualStrings("%4", parameters.get("c").?);
    try testing.expectEqualStrings("\xff\xfe", parameters.get("d").?);
}

test "decision 127: get returns the first value of a name" {
    var parameters: QueryParameters = .{};
    var storage: [16]u8 = undefined;
    try parameters.read("a=1&a=2", &storage);
    try testing.expectEqualStrings("1", parameters.get("a").?);
}

test "decision 127: too many pairs, or a buffer too small, is refused and leaves no pair" {
    var parameters: QueryParameters = .{};
    var storage: [4 * constants.query_parameters_max]u8 = undefined;
    const pair = "a=1&";
    var query: [pair.len * (constants.query_parameters_max + 1)]u8 = undefined;
    for (0..constants.query_parameters_max + 1) |index| @memcpy(query[index * pair.len ..][0..pair.len], pair);
    try testing.expectError(error.Full, parameters.read(&query, &storage));
    try testing.expectEqual(0, parameters.count);
    try parameters.read(query[0 .. pair.len * constants.query_parameters_max], &storage);
    try testing.expectEqual(constants.query_parameters_max, parameters.count);
    var small: [3]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, parameters.read("ab=cd", &small));
    try testing.expectEqual(0, parameters.count);
}

/// Most bytes a fuzz input carries: enough for one pair more than `query_parameters_max`.
/// Test-only.
const fuzz_input_len_max = 80;
/// The short buffer each input is read into a second time, so `NoSpaceLeft` is reached. Test-only.
const fuzz_storage_short_len = 8;

/// The pairs `read` must write, from a parser written apart from `read`: one pass over the
/// query, byte by byte. Test-only.
const Reference = struct {
    names: [constants.query_parameters_max][]const u8 = @splat(""),
    values: [constants.query_parameters_max][]const u8 = @splat(""),
    count: usize = 0,
    storage: [fuzz_input_len_max]u8 = undefined,
    len: usize = 0,
    limit: usize,

    fn parse(reference: *Reference, query: []const u8) ReadError!void {
        var first: usize = 0;
        for (0..query.len + 1) |index| {
            if (index < query.len and query[index] != '&') continue;
            if (index > first) try reference.pair(query[first..index]);
            first = index + 1;
        }
    }

    fn pair(reference: *Reference, piece: []const u8) ReadError!void {
        if (reference.count == constants.query_parameters_max) return error.Full;
        var mark = piece.len;
        for (piece, 0..) |byte, index| {
            if (byte == '=') {
                mark = index;
                break;
            }
        }
        reference.names[reference.count] = try reference.decode(piece[0..mark]);
        reference.values[reference.count] = try reference.decode(piece[@min(mark + 1, piece.len)..]);
        reference.count += 1;
    }

    fn decode(reference: *Reference, encoded: []const u8) ReadError![]const u8 {
        const first = reference.len;
        var index: usize = 0;
        while (index < encoded.len) {
            const byte, const taken = reference_byte(encoded[index..]);
            if (reference.len == reference.limit) return error.NoSpaceLeft;
            reference.storage[reference.len] = byte;
            reference.len += 1;
            index += taken;
        }
        return reference.storage[first..reference.len];
    }
};

/// The first byte that `encoded` decodes to, and how many bytes of `encoded` it takes. Test-only.
fn reference_byte(encoded: []const u8) struct { u8, usize } {
    const radix = 16;
    const digits = 2;
    if (encoded[0] == '%' and encoded.len > digits) {
        const high = std.fmt.charToDigit(encoded[1], radix) catch null;
        const low = std.fmt.charToDigit(encoded[digits], radix) catch null;
        if (high != null and low != null) return .{ high.? * radix + low.?, digits + 1 };
    }
    return .{ if (encoded[0] == '+') ' ' else encoded[0], 1 };
}

fn fuzz_read(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const query = input[0..smith.slice(&input)];
    var storage: [fuzz_input_len_max]u8 = undefined;
    try expect_read(query, &storage);
    try expect_read(query, storage[0..fuzz_storage_short_len]);
}

fn expect_read(query: []const u8, storage: []u8) !void {
    var reference: Reference = .{ .limit = storage.len };
    const expected = reference.parse(query);
    var parameters: QueryParameters = .{};
    parameters.count = 1;
    const result = parameters.read(query, storage);
    if (expected) |_| try result else |failure| {
        try testing.expectError(failure, result);
        try testing.expectEqual(0, parameters.count);
        return;
    }
    try testing.expectEqual(reference.count, parameters.count);
    const storage_end = @intFromPtr(storage.ptr) + storage.len;
    for (0..reference.count) |index| {
        try testing.expectEqualStrings(reference.names[index], parameters.names[index]);
        try testing.expectEqualStrings(reference.values[index], parameters.values[index]);
        // Each name and value is a slice of the buffer `read` was given.
        inline for (.{ parameters.names[index], parameters.values[index] }) |slice| {
            if (slice.len > 0) try testing.expect(@intFromPtr(slice.ptr) >= @intFromPtr(storage.ptr) and
                @intFromPtr(slice.ptr) + slice.len <= storage_end);
        }
    }
}

test "fuzz: read writes the pairs of a parser written apart, or refuses and leaves no pair" {
    try testing.fuzz({}, fuzz_read, .{ .corpus = &.{
        core.fuzz.input("a=1&b=2"),
        core.fuzz.input("&&a&=&=b&"),
        core.fuzz.input("a+b=%2B%26%3D"),
        core.fuzz.input("%%4%zz%4g=%"),
        core.fuzz.input("abcdefgh=i"),
        core.fuzz.input("a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a&a"),
    } });
}

test "fuzz: the sweep of read over every query of up to two bytes" {
    try core.fuzz.sweep(fuzz_read, null);
}
