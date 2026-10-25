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
const constants = @import("constants.zig");

pub const ReadError = error{
    /// The query holds more pairs than `constants.query_parameters_max`.
    TooManyParameters,
    /// The decoded names and values do not fit the buffer `read` was given.
    StorageFull,
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
            if (count == constants.query_parameters_max) return error.TooManyParameters;
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
        const byte = encoded[index];
        if (byte == '%' and index + 2 < encoded.len) {
            if (hex_pair(encoded[index + 1 ..][0..2])) |value| {
                writer.write_byte(value) catch return error.StorageFull;
                index += 3;
                continue;
            }
        }
        writer.write_byte(if (byte == '+') ' ' else byte) catch return error.StorageFull;
        index += 1;
    }
    return writer.written()[first..];
}

/// The byte two hex digits name, or null when either is not a hex digit (RFC 3986 §2.1).
fn hex_pair(digits: *const [2]u8) ?u8 {
    const high = std.fmt.charToDigit(digits[0], 16) catch return null;
    const low = std.fmt.charToDigit(digits[1], 16) catch return null;
    return high * 16 + low;
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
    try testing.expectError(error.TooManyParameters, parameters.read(&query, &storage));
    try testing.expectEqual(0, parameters.count);
    try parameters.read(query[0 .. pair.len * constants.query_parameters_max], &storage);
    try testing.expectEqual(constants.query_parameters_max, parameters.count);
    var small: [3]u8 = undefined;
    try testing.expectError(error.StorageFull, parameters.read("ab=cd", &small));
    try testing.expectEqual(0, parameters.count);
}
