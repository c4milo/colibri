//! The QPACK decoder of RFC 9204, static table only. Part of design §8 step 11.
//!
//! It reads §4.5.1's field section prefix and then one representation per field line, resolving
//! each against RFC 9204 Appendix A's static table and appending the result to a field section
//! the caller owns.
//!
//! **Every reference to a dynamic entry is refused, and that is correct rather than temporary.**
//! A decoder that advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY` of zero — RFC 9204 §5's default
//! — permits no dynamic table, so its Required Insert Count is always zero, and §2.2.3 makes a
//! reference to an entry at or above that count a connection error of QPACK_DECOMPRESSION_FAILED.
//! When the dynamic table lands, what changes is the capacity this holds, not this rule.
//!
//! Because the capacity is zero the decoder never blocks: §2.1.2's blocked streams cannot arise
//! when there is nothing to wait for, so nothing here holds a partly decoded section.
//!
//! A decoded name or value is written into a buffer the caller owns and the field section points
//! into it (decision 35), so the buffer must outlive the section.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const constants = @import("constants.zig");
const representation = @import("representation.zig");
const static_table = @import("static_table.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const FieldSection = http.field_section.FieldSection;
const Representation = representation.Representation;

pub const Error = representation.Error || http.field_section.AppendError || error{
    /// RFC 9204 §6's QPACK_DECOMPRESSION_FAILED: the decoder cannot interpret the field section
    /// and cannot continue decoding it. §2.2.3 names the references that produce it, and §3.1
    /// the static index that does.
    DecompressionFailed,
};

/// What RFC 9204 §6 has HTTP/3 send for an error from here.
pub fn error_code(failure: Error) u64 {
    return switch (failure) {
        // Everything this decoder refuses is a failure to interpret one field section.
        else => constants.error_decompression_failed,
    };
}

pub const Decoder = struct {
    /// RFC 9204 §3.2.3's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, which this decoder advertises as
    /// zero: it permits no dynamic table. It is held rather than assumed so the rule that reads
    /// it stays the rule when the dynamic table lands.
    max_table_capacity: u64,

    pub fn init(decoder: *Decoder) void {
        decoder.max_table_capacity = 0;
    }

    /// Reads a whole encoded field section into `section`, with the names and values it decodes
    /// written into `strings`.
    pub fn read_section(
        decoder: *const Decoder,
        reader: *Reader,
        strings: *Writer,
        section: *FieldSection,
    ) Error!void {
        const prefix = try representation.read_prefix(reader);
        // RFC 9204 §4.5.1.1: a Required Insert Count of zero is encoded as zero. With no dynamic
        // table there is nothing else it can be, and §2.2.3 makes anything else a decompression
        // failure rather than something to wait for.
        if (prefix.encoded_insert_count != 0) return Error.DecompressionFailed;
        // §4.5.1.2: with a Required Insert Count of zero the Base is the Delta Base, and a Sign
        // bit of 1 would put it below zero, which the same paragraph forbids.
        _ = prefix.base(0) catch return Error.DecompressionFailed;
        // Bounded by the octets the caller gave, since every representation consumes at least one.
        while (reader.remaining_len() > 0) {
            const line = try representation.read(reader, strings);
            try decoder.append(section, line);
        }
    }

    /// Resolves one representation and appends the field line it names.
    fn append(decoder: *const Decoder, section: *FieldSection, line: Representation) Error!void {
        switch (line) {
            .indexed => |held| {
                const entry = try decoder.static_entry(held.table, held.index);
                try section.append(entry.name, entry.value);
            },
            .literal_name_reference => |held| {
                const entry = try decoder.static_entry(held.table, held.name_index);
                try section.append(entry.name, held.value);
            },
            .literal => |held| try section.append(held.name, held.value),
            // RFC 9204 §3.2.6: a post-Base index is a dynamic entry at or above the Base. With no
            // dynamic table the Base is zero and §2.2.3 makes every such reference an error.
            .indexed_post_base, .literal_post_base_name_reference => return Error.DecompressionFailed,
        }
    }

    /// The static entry an index names (RFC 9204 §3.1).
    fn static_entry(decoder: *const Decoder, table: representation.Table, index: u64) Error!static_table.Entry {
        // RFC 9204 §2.2.3: a reference into a dynamic table this decoder does not permit is a
        // reference at or above a Required Insert Count of zero.
        if (table == .dynamic) {
            assert(decoder.max_table_capacity == 0);
            return Error.DecompressionFailed;
        }
        // RFC 9204 §3.1: the static table has 99 entries numbered from 0, and §2.2.3 makes a
        // reference past the end a decompression failure.
        if (index >= constants.static_table_entries) return Error.DecompressionFailed;
        return static_table.entries[@intCast(index)];
    }
};

const testing = std.testing;
const encoder_module = @import("encoder.zig");

/// The decoder the tests drive, the section it fills, and room for the strings it decodes.
/// Test-only.
var test_decoder: Decoder = undefined;
var test_section: FieldSection = undefined;
const test_room: usize = 1024;
var test_strings: [test_room]u8 = undefined;
var test_octets: [test_room]u8 = undefined;

/// Decodes one field section into `test_section`. Test-only.
fn decode(octets: []const u8) Error!void {
    test_decoder.init();
    test_section.init();
    var reader = Reader.init(octets);
    var strings = Writer.init(&test_strings);
    return test_decoder.read_section(&reader, &strings, &test_section);
}

test "B.1: the RFC's own field section decodes to the field line it names" {
    const octets = [_]u8{ 0x00, 0x00, 0x51, 0x0b } ++ "/index.html".*;
    try decode(&octets);
    try testing.expectEqual(1, test_section.len());
    try testing.expectEqualStrings(":path", test_section.get(0).name);
    try testing.expectEqualStrings("/index.html", test_section.get(0).value);
}

test "§3.1: an indexed line resolves against Appendix A, and past its end is refused" {
    // 0xd1 is static index 17, Appendix A's `:method GET`; 0xd7 is 23, `:scheme https`.
    try decode(&.{ 0x00, 0x00, 0xd1, 0xd7 });
    try testing.expectEqual(2, test_section.len());
    try testing.expectEqualStrings(":method", test_section.get(0).name);
    try testing.expectEqualStrings("GET", test_section.get(0).value);
    try testing.expectEqualStrings(":scheme", test_section.get(1).name);
    // Entry 98 is the last, so 98 resolves and 99 does not.
    try decode(&.{ 0x00, 0x00, 0xff, 0x23 });
    try testing.expectEqualStrings("x-frame-options", test_section.get(0).name);
    // RFC 9204 §2.2.3: a reference the decoder cannot resolve is QPACK_DECOMPRESSION_FAILED.
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0xff, 0x24 }));
}

test "§2.2.3: every reference into a dynamic table is refused" {
    // The T bit clear makes an indexed line a relative dynamic index, and this decoder permits
    // no dynamic table, so its Required Insert Count is zero and §2.2.3 refuses the reference.
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0x81 }));
    // The same for a name reference with the T bit clear.
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0x41, 0x01, 'a' }));
    // §3.2.6's post-Base representations are dynamic by construction, both of them.
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0x11 }));
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0x01, 0x01, 'a' }));
    // A literal names no table at all, so it decodes.
    try decode(&.{ 0x00, 0x00, 0x23, 'a', 'b', 'c', 0x01, 'd' });
    try testing.expectEqualStrings("abc", test_section.get(0).name);
    try testing.expectEqualStrings("d", test_section.get(0).value);
}

test "§4.5.1: a prefix naming any dynamic state is refused" {
    // RFC 9204 §4.5.1.1: with no dynamic table the Required Insert Count can only be zero, and
    // §2.2.3 makes a section that needs one a decompression failure rather than a wait.
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x01, 0x00, 0xd1 }));
    // §4.5.1.2: a Sign bit of 1 with a Required Insert Count of zero puts the Base below zero,
    // which the same paragraph forbids.
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x80, 0xd1 }));
    // A Sign bit of 0 with any Delta Base is fine: §4.5.1.2 lets a section that references no
    // dynamic entry use any Base at all.
    try decode(&.{ 0x00, 0x7f, 0x00, 0xd1 });
    try testing.expectEqualStrings(":method", test_section.get(0).name);
}

test "§6: everything this decoder refuses is one error code" {
    // RFC 9204 §6: QPACK_DECOMPRESSION_FAILED is what HTTP/3 carries for a field section this
    // decoder could not interpret, whichever of its rules refused it.
    try testing.expectEqual(constants.error_decompression_failed, error_code(Error.DecompressionFailed));
    try testing.expectEqual(constants.error_decompression_failed, error_code(Error.Truncated));
    try testing.expectEqual(0x0200, constants.error_decompression_failed);
}

test "what the encoder writes is what the decoder reads, coded and not" {
    for ([_]encoder_module.HuffmanUse{ .never, .always, .when_shorter }) |use| {
        var held: encoder_module.Encoder = undefined;
        held.init(use);
        var section: FieldSection = undefined;
        section.init();
        try section.append(":method", "GET");
        try section.append(":scheme", "https");
        try section.append(":path", "/index.html");
        try section.append("x-colibri", "a value that is long enough to be worth coding");
        var writer = Writer.init(&test_octets);
        try held.write_section(&writer, &section);
        try decode(writer.written());
        try testing.expectEqual(section.len(), test_section.len());
        var walk = section.iterator();
        var index: u32 = 0;
        // Bounded by the section, whose line count is a named limit of `http`.
        while (walk.next()) |line| : (index += 1) {
            try testing.expectEqualStrings(line.name, test_section.get(index).name);
            try testing.expectEqualStrings(line.value, test_section.get(index).value);
        }
    }
}

test "a field section cut short is refused rather than half accepted" {
    // The prefix alone is a section with no lines, which is what an empty one encodes to.
    try decode(&.{ 0x00, 0x00 });
    try testing.expectEqual(0, test_section.len());
    // A representation whose octets run out is a failure, not a section ending early.
    try testing.expectError(Error.Truncated, decode(&.{ 0x00, 0x00, 0xd1, 0x51 }));
    try testing.expectError(Error.Truncated, decode(&.{0x00}));
}
