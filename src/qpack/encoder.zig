//! The QPACK encoder of RFC 9204, static table only. Part of design §8 step 11.
//!
//! **Static-only is a complete encoder, not a stub.** RFC 9204 §5 gives both QPACK settings a
//! default of zero: `SETTINGS_QPACK_MAX_TABLE_CAPACITY` zero means the decoder permits no dynamic
//! table, and `SETTINGS_QPACK_BLOCKED_STREAMS` zero means it will not wait for one. An encoder
//! that uses neither is conformant against every decoder, needs no encoder stream, and can never
//! block a request stream. The dynamic table is the optimisation on top, and it lands after this.
//!
//! What it writes per field line: the static entry's index where the table holds the name and
//! the value (§4.5.2), the index of the name with the value as a literal where it holds only the
//! name (§4.5.4), and both as literals otherwise (§4.5.6). A field line the caller marks as
//! never indexed is always a literal, which is §7.1.3's protection for a value that must not be
//! put at risk by compression.
//!
//! It writes no dynamic reference, so the field section prefix it emits is always §4.5.1's
//! zero-zero: Required Insert Count zero, Sign clear, Delta Base zero.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const wire = @import("wire");
const constants = @import("constants.zig");
const representation = @import("representation.zig");
const representation_write = @import("representation_write.zig");
const static_table = @import("static_table.zig");

const Writer = core.Writer;
const FieldSection = http.field_section.FieldSection;
const Representation = representation.Representation;

pub const Error = core.writer.Error;

/// When a string is Huffman coded (RFC 9204 §4.1.2). `when_shorter` is what §7.2 leaves an
/// implementation to decide: coding a string that does not shrink costs octets and cycles.
pub const HuffmanUse = enum { never, always, when_shorter };

/// Whether a field line may be compressed against a table at all (RFC 9204 §7.1.3).
pub const Indexing = enum {
    /// The encoder may use whatever representation is shortest.
    ordinary,
    /// The field line MUST be a literal and MUST carry the `N` bit, so no intermediary puts it
    /// in a table on a later hop (§4.5.4, §7.1.3).
    never_indexed,
};

pub const Encoder = struct {
    huffman: HuffmanUse,

    pub fn init(encoder: *Encoder, huffman: HuffmanUse) void {
        encoder.huffman = huffman;
    }

    /// Writes a whole encoded field section: §4.5.1's prefix, then one representation per field
    /// line. All of the octets are written, or none.
    pub fn write_section(encoder: *const Encoder, output: *Writer, section: *const FieldSection) Error!void {
        var cursor = output.*;
        try representation.write_prefix(&cursor, representation.Prefix.static_only);
        var walk = section.iterator();
        // Bounded by the section, whose line count is a named limit of `http`.
        while (walk.next()) |line| {
            try encoder.write_field(&cursor, line.name, line.value, .ordinary);
        }
        output.* = cursor;
    }

    /// Writes one field line in the shortest representation `indexing` allows.
    pub fn write_field(
        encoder: *const Encoder,
        output: *Writer,
        name: []const u8,
        value: []const u8,
        indexing: Indexing,
    ) Error!void {
        const match = find_static(name, value);
        const held = encoder.choose(match, name, value, indexing);
        try representation_write.write(output, held);
    }

    /// Picks the representation for one field line (RFC 9204 §4.5).
    fn choose(
        encoder: *const Encoder,
        match: Match,
        name: []const u8,
        value: []const u8,
        indexing: Indexing,
    ) Representation {
        const never_indexed = indexing == .never_indexed;
        // §4.5.2: a line the static table holds whole is its index, which is one octet for the
        // first 63 entries.
        //
        // A line the caller marked never indexed does not take that path, even where the static
        // table holds it whole. An index carries no `N` bit, so the signal §7.1.3 asks the
        // encoder to send would be dropped, and §4.5.4 requires a literal on every hop that
        // forwards one. The static reference itself would leak nothing — the table is public —
        // but the next hop is what the bit is for.
        if (!never_indexed) {
            if (match.exact) |index| return .{ .indexed = .{ .table = .static, .index = index } };
        }
        if (match.name) |index| return .{ .literal_name_reference = .{
            .never_indexed = never_indexed,
            .table = .static,
            .name_index = index,
            .value = value,
            .value_coding = encoder.coding(value),
        } };
        return .{ .literal = .{
            .never_indexed = never_indexed,
            .name = name,
            .name_coding = encoder.coding(name),
            .value = value,
            .value_coding = encoder.coding(value),
        } };
    }

    fn coding(encoder: *const Encoder, octets: []const u8) representation.Coding {
        return switch (encoder.huffman) {
            .never => .raw,
            .always => .huffman,
            // RFC 9204 §7.2: coding a string that does not shrink spends octets to save none.
            .when_shorter => if (wire.huffman.encoded_len(octets) < octets.len) .huffman else .raw,
        };
    }
};

/// The static indices holding the field line and its name (RFC 9204 Appendix A).
const Match = struct {
    exact: ?u64 = null,
    name: ?u64 = null,
};

/// The lowest static index holding the whole line, and the lowest holding its name. Appendix A
/// orders the entries so the commonest field lines take the fewest octets, and the lowest index
/// is the shortest to encode, so the first match of each is the one to take.
fn find_static(name: []const u8, value: []const u8) Match {
    var match: Match = .{};
    // Bounded by Appendix A's entry count, which is a named limit.
    for (static_table.entries, 0..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (match.name == null) match.name = index;
        if (std.mem.eql(u8, entry.value, value)) {
            match.exact = index;
            return match;
        }
    }
    return match;
}

const testing = std.testing;

/// The encoder the tests drive, and room for what they write. Test-only.
var test_encoder: Encoder = undefined;
const test_room: usize = 256;
var test_octets: [test_room]u8 = undefined;

/// Writes one field line and returns the octets. Test-only.
fn write_one(name: []const u8, value: []const u8, indexing: Indexing) ![]const u8 {
    var writer = Writer.init(&test_octets);
    try test_encoder.write_field(&writer, name, value, indexing);
    return writer.written();
}

test "B.1: the encoder produces the RFC's own octets for its own example" {
    test_encoder.init(.never);
    // RFC 9204 Appendix B.1: `:path: /index.html` is a Literal Field Line with Name Reference
    // into static index 1, because Appendix A's entry 1 is `:path` with the value `/` and only
    // the name matches. The prefix is §4.5.1's zero-zero.
    var section: FieldSection = undefined;
    section.init();
    try section.append(":path", "/index.html");
    var writer = Writer.init(&test_octets);
    try test_encoder.write_section(&writer, &section);
    const expected = [_]u8{ 0x00, 0x00, 0x51, 0x0b } ++ "/index.html".*;
    try testing.expectEqualSlices(u8, &expected, writer.written());
}

test "§4.5.2: a line the static table holds whole is one octet" {
    test_encoder.init(.never);
    // Appendix A entry 17 is `:method GET`, so the whole line is `1T` and the index.
    try testing.expectEqualSlices(u8, &.{0xd1}, try write_one(":method", "GET", .ordinary));
    // Entry 1 is `:path /`, and entry 0 is `:authority` with an empty value.
    try testing.expectEqualSlices(u8, &.{0xc1}, try write_one(":path", "/", .ordinary));
    try testing.expectEqualSlices(u8, &.{0xc0}, try write_one(":authority", "", .ordinary));
}

test "§4.5.4: a name the table holds with another value is a name reference" {
    test_encoder.init(.never);
    // Appendix A holds `:method` at 15 through 21, and the lowest is the one to reference: a
    // 4-bit prefix carries 0 to 14 in the first octet, so 15 is `0x5f 0x00` and 21 would be
    // `0x5f 0x06`. The whole encoding is pinned, continuation octet included, because the first
    // octet alone cannot tell the two apart.
    const octets = try write_one(":method", "PATCH", .ordinary);
    const expected = [_]u8{ 0x5f, 0x00, 0x05 } ++ "PATCH".*;
    try testing.expectEqualSlices(u8, &expected, octets);
    // A name the table does not hold at all is a literal on both halves: `001N` with N clear.
    // The name's length prefix is three bits, so a name of nine octets fills it and continues:
    // 0x27 is `001` with the prefix at its maximum, and 0x02 is the two past it.
    const literal = try write_one("x-colibri", "1", .ordinary);
    try testing.expectEqual(0x27, literal[0]);
    try testing.expectEqual(0x02, literal[1]);
    try testing.expectEqualStrings("x-colibri", literal[2..11]);
}

test "§7.1.3: a never-indexed line is a literal carrying the N bit" {
    test_encoder.init(.never);
    // `:method GET` is an exact static match, but marking it never indexed must not drop the
    // signal: §4.5.4's N bit only exists on a literal, so a literal is what is written.
    const octets = try write_one(":method", "GET", .never_indexed);
    try testing.expectEqual(0x7f, octets[0]);
    try testing.expectEqualStrings("GET", octets[3..]);
    // With no static name to reference it is a literal name too, with N set.
    const both = try write_one("x-secret", "s", .never_indexed);
    try testing.expectEqual(0x37, both[0]);
    try testing.expectEqual(0x01, both[1]);
    try testing.expectEqualStrings("x-secret", both[2..10]);
}

test "§7.2: a string is Huffman coded only where the coding is shorter" {
    // `never` writes the octets as they are.
    test_encoder.init(.never);
    const raw = try write_one("x-colibri", "aaaaaaaa", .ordinary);
    try testing.expectEqualStrings("aaaaaaaa", raw[raw.len - 8 ..]);
    // `always` codes both halves, and the H bit of the name literal's prefix is set.
    test_encoder.init(.always);
    const coded = try write_one("x-colibri", "aaaaaaaa", .ordinary);
    try testing.expect(coded.len < raw.len);
    try testing.expect(coded[0] & 0x08 != 0);
    // `when_shorter` takes the shorter of the two per string. A single octet Huffman codes to
    // one octet or more, so it stays raw while the long run is coded.
    test_encoder.init(.when_shorter);
    const mixed = try write_one("x-colibri", "aaaaaaaa", .ordinary);
    try testing.expect(mixed.len < raw.len);
    const short = try write_one("x-colibri", "!", .ordinary);
    try testing.expectEqualStrings("!", short[short.len - 1 ..]);
}

test "§4.5.1: a static-only section always carries the zero-zero prefix" {
    test_encoder.init(.never);
    var section: FieldSection = undefined;
    section.init();
    var writer = Writer.init(&test_octets);
    try test_encoder.write_section(&writer, &section);
    // An empty section is the prefix and nothing else, which is what §4.5.1 says a field section
    // with no lines encodes to.
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, writer.written());
    // Every line after it is a representation, and the prefix is written once.
    try section.append(":method", "GET");
    try section.append(":scheme", "https");
    var again = Writer.init(&test_octets);
    try test_encoder.write_section(&again, &section);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0xd1, 0xd7 }, again.written());
}

test "a section that does not fit writes nothing" {
    test_encoder.init(.never);
    var section: FieldSection = undefined;
    section.init();
    try section.append(":method", "GET");
    // Three octets are needed: two of prefix and one of representation. Two are not enough, and
    // a writer that ran out must leave nothing half-written behind it.
    var room: [3]u8 = undefined;
    var tight = Writer.init(room[0..2]);
    try testing.expectError(error.NoSpaceLeft, test_encoder.write_section(&tight, &section));
    try testing.expectEqual(0, tight.written().len);
    var exact = Writer.init(&room);
    try test_encoder.write_section(&exact, &section);
    try testing.expectEqual(3, exact.written().len);
}
