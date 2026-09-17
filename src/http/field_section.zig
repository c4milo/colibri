//! The field section of one message, holding its field lines in the order they arrived, for both
//! h2 and h3 (decision 15). RFC 9110 §5.3 makes the order of field lines that share a name
//! significant, so the section is a list and never a map, and this is the one model both
//! protocols fill and read.
//!
//! The section owns no memory (decision 35, invariant 1). Every line's name and value are copied
//! into a fixed buffer of `field_section_size_max` octets, and every line record into a fixed
//! array of `field_count_max`. The caller places the struct where it chooses.
//!
//! `size` is the size both protocols measure a section by: the sum over its lines of the name
//! length, the value length and `field_line_overhead`, on the unencoded octets. That is the
//! measure of `SETTINGS_MAX_HEADER_LIST_SIZE` (RFC 9113 §6.5.2) and of
//! `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2), and the arithmetic is shared while the
//! setting is not. `size` never exceeds `field_section_size_max`: an append that would take it
//! past that limit, or take `count` past `field_count_max`, is refused whole and the section is
//! left as it was.
//!
//! Nothing here validates a name or a value: `field.zig` does, and the protocol module calls it
//! before it appends (invariant 7). Nothing here knows a pseudo-header from any other line: h2 and
//! h3 read those differently (RFC 9113 §8.3, RFC 9114 §4.3), so each does it in its own module.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const field = @import("field.zig");

const limits = core.constants;

/// One field line as `get`, `find` and `Iterator.next` return it. The slices point into the
/// section and stay valid until its next `append`, `clear` or `init`.
pub const Field = field.Field;

/// Why `append` refused a line. Both are colibri's limits, not a protocol's: RFC 9110 §5.4 places
/// no predefined limit on a field section and requires a server that cannot accept one to answer
/// 4xx rather than truncate it.
pub const AppendError = error{
    /// The line would take `size` past `field_section_size_max`.
    SectionTooLarge,
    /// The section already holds `field_count_max` lines.
    TooManyLines,
};

/// Where one line's octets are in `FieldSection.octets`: its name, then its value, at `offset`.
const Line = struct {
    offset: u32,
    name_len: u16,
    value_len: u16,
};

comptime {
    // A line record keeps its two lengths in u16, so both limits must fit one.
    assert(limits.field_name_len_max <= std.math.maxInt(u16));
    assert(limits.field_value_len_max <= std.math.maxInt(u16));
    // `append` adds one line's cost to `size` in u32 before it compares against the limit, so the
    // largest sum the comparison can see must fit.
    const cost_max: u64 = @as(u64, limits.field_name_len_max) + limits.field_value_len_max + limits.field_line_overhead;
    assert(limits.field_section_size_max + cost_max <= std.math.maxInt(u32));
}

/// One message's field lines, in arrival order, in storage the caller places.
pub const FieldSection = struct {
    /// Every line's name then value, in arrival order; `octets[0..octets_len]` is in use.
    octets: [limits.field_section_size_max]u8,
    /// One record per line, in arrival order; `lines[0..count]` is in use.
    lines: [limits.field_count_max]Line,
    /// Lines held, at most `field_count_max`.
    count: u32,
    /// Octets of `octets` in use: the sum over the lines of name length and value length.
    octets_len: u32,
    /// The sum over the lines of name length, value length and `field_line_overhead`
    /// (RFC 9113 §6.5.2, RFC 9114 §4.2.2), at most `field_section_size_max`.
    size: u32,

    /// Makes `section` empty. The unused parts of `octets` and `lines` are never read, so they are
    /// left as they were.
    pub fn init(section: *FieldSection) void {
        section.count = 0;
        section.octets_len = 0;
        section.size = 0;
        assert(section.len() == 0);
        assert(section.size == 0 and section.octets_len == 0);
    }

    /// Empties `section`, the same as `init`. Every `Field` it handed out before is invalid after.
    pub fn clear(section: *FieldSection) void {
        section.init();
    }

    /// Lines held.
    pub fn len(section: *const FieldSection) u32 {
        return section.count;
    }

    /// Adds a line after every line the section holds, or refuses it and changes nothing.
    ///
    /// The caller guarantees that `name` and `value` are within `field_name_len_max` and
    /// `field_value_len_max`: either it validated them (`field.validate_name`,
    /// `field.validate_value`), or a decoder whose own limits are these refused anything longer,
    /// as h2's field block does before it validates the section whole. The two assertions state
    /// that contract; they check the caller, never the peer (invariant 24). Nothing here checks
    /// the octets, so a section is read only after its protocol module validated it.
    pub fn append(section: *FieldSection, name: []const u8, value: []const u8) AppendError!void {
        assert(name.len <= limits.field_name_len_max);
        assert(value.len <= limits.field_value_len_max);
        // RFC 9110 §5.4: no predefined limit on a field section, and a server that cannot accept
        // one answers 4xx rather than truncating it, which is what makes a local limit on the
        // number of lines conformant.
        if (section.count == limits.field_count_max) return error.TooManyLines;
        const name_len: u16 = @intCast(name.len);
        const value_len: u16 = @intCast(value.len);
        const cost = line_size(name_len, value_len);
        // RFC 9113 §6.5.2 and RFC 9114 §4.2.2: a section's size is the sum over its lines of name
        // length, value length and the overhead, on the unencoded octets, and the endpoint refuses
        // a section larger than the size it advertises.
        if (section.size + cost > limits.field_section_size_max) return error.SectionTooLarge;
        const name_end = section.octets_len + name_len;
        const value_end = name_end + value_len;
        // `octets_len` never exceeds `size`, and `size + cost` fits under the limit, so the
        // buffer holds both strings.
        assert(value_end <= section.octets.len);
        @memcpy(section.octets[section.octets_len..name_end], name);
        @memcpy(section.octets[name_end..value_end], value);
        section.lines[section.count] = .{
            .offset = section.octets_len,
            .name_len = name_len,
            .value_len = value_len,
        };
        section.count += 1;
        section.octets_len = value_end;
        section.size += cost;
        assert(section.count <= limits.field_count_max);
        section.check_accounting();
    }

    /// The line at `index`: 0 for the first line that arrived and `len() - 1` for the last. The
    /// index is the caller's, so it is asserted, never checked.
    pub fn get(section: *const FieldSection, index: u32) Field {
        assert(index < section.count);
        return section.field_at(&section.lines[index]);
    }

    /// Walks the lines in arrival order, from the first.
    pub fn iterator(section: *const FieldSection) Iterator {
        return .{ .section = section, .index = 0 };
    }

    /// The first line, in arrival order, whose name equals `name` the way RFC 9110 §5.1 compares
    /// field names, case-insensitively; or null when no line does. It is the first because
    /// RFC 9110 §5.3 makes the order of same-name lines significant.
    pub fn find(section: *const FieldSection, name: []const u8) ?Field {
        assert(section.count <= limits.field_count_max);
        for (section.lines[0..section.count]) |*line| {
            const candidate = section.field_at(line);
            if (field.names_equal(candidate.name, name)) return candidate;
        }
        return null;
    }

    fn field_at(section: *const FieldSection, line: *const Line) Field {
        const name_end = line.offset + line.name_len;
        const value_end = name_end + line.value_len;
        assert(line.offset <= name_end and name_end <= value_end);
        assert(value_end <= section.octets_len);
        return .{
            .name = section.octets[line.offset..name_end],
            .value = section.octets[name_end..value_end],
        };
    }

    /// The accounting the header states, recomputed from the lines: `size` is the sum of
    /// `line_size` over them and `octets_len` the sum of their name and value lengths, and both
    /// stay under their limits.
    fn check_accounting(section: *const FieldSection) void {
        assert(section.count <= limits.field_count_max);
        var size: u32 = 0;
        var octets_len: u32 = 0;
        for (section.lines[0..section.count]) |line| {
            size += line_size(line.name_len, line.value_len);
            octets_len += @as(u32, line.name_len) + line.value_len;
        }
        assert(size == section.size);
        assert(octets_len == section.octets_len);
        assert(section.size <= limits.field_section_size_max);
        assert(section.octets_len <= section.size);
    }
};

/// Walks a section's lines in arrival order (RFC 9110 §5.3). Made by `FieldSection.iterator`.
pub const Iterator = struct {
    section: *const FieldSection,
    /// The next line to return.
    index: u32,

    /// The next line, or null once every line has been returned; null again after that.
    pub fn next(self: *Iterator) ?Field {
        assert(self.index <= self.section.count);
        if (self.index == self.section.count) return null;
        const line = self.section.get(self.index);
        self.index += 1;
        return line;
    }
};

/// The size one line adds to a section: its name length, its value length and the overhead
/// (RFC 9113 §6.5.2, RFC 9114 §4.2.2).
fn line_size(name_len: u16, value_len: u16) u32 {
    const size = @as(u32, name_len) + value_len + limits.field_line_overhead;
    assert(size >= limits.field_line_overhead);
    return size;
}

const testing = std.testing;

/// The section the tests run in, placed outside any stack frame.
var test_section: FieldSection = undefined;

/// A value as long as a value may be, for the tests that fill a section.
const test_value: [limits.field_value_len_max]u8 = @splat('v');

fn expect_line(index: u32, name: []const u8, value: []const u8) !void {
    const line = test_section.get(index);
    try testing.expectEqualStrings(name, line.name);
    try testing.expectEqualStrings(value, line.value);
}

fn expect_state(count: u32, size: u32, octets_len: u32) !void {
    try testing.expectEqual(count, test_section.len());
    try testing.expectEqual(size, test_section.size);
    try testing.expectEqual(octets_len, test_section.octets_len);
}

test "append keeps lines in arrival order and get reads each back" {
    test_section.init();
    try expect_state(0, 0, 0);
    try test_section.append(":authority", "www.example.com");
    // 10 + 15 + 32: name, value and the overhead.
    try expect_state(1, 57, 25);
    try test_section.append("cache-control", "no-cache");
    try test_section.append("custom-key", "custom-value");
    try expect_state(3, 57 + 53 + 54, 25 + 21 + 22);
    try expect_line(0, ":authority", "www.example.com");
    try expect_line(1, "cache-control", "no-cache");
    try expect_line(2, "custom-key", "custom-value");
}

test "two lines sharing a name both stay, in order, and find returns the first (RFC 9110 §5.3)" {
    test_section.init();
    try test_section.append("set-cookie", "a=1");
    try test_section.append("content-type", "text/plain");
    try test_section.append("set-cookie", "b=2");
    try testing.expectEqual(3, test_section.len());
    try expect_line(0, "set-cookie", "a=1");
    try expect_line(1, "content-type", "text/plain");
    try expect_line(2, "set-cookie", "b=2");
    const found = test_section.find("set-cookie") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("a=1", found.value);
    try testing.expectEqual(null, test_section.find("absent"));
}

test "a line that brings the size exactly to the limit is accepted, and one octet more is refused" {
    test_section.init();
    try test_section.append("a", &test_value);
    const first_size = 1 + limits.field_value_len_max + limits.field_line_overhead;
    const first_octets_len = 1 + limits.field_value_len_max;
    try expect_state(1, first_size, first_octets_len);
    // The second value is sized so the section lands exactly on the limit.
    const fitting_len = limits.field_section_size_max - first_size - 1 - limits.field_line_overhead;
    const too_long = test_section.append("b", test_value[0 .. fitting_len + 1]);
    try testing.expectError(error.SectionTooLarge, too_long);
    try expect_state(1, first_size, first_octets_len);
    try test_section.append("b", test_value[0..fitting_len]);
    try expect_state(2, limits.field_section_size_max, first_octets_len + 1 + fitting_len);
    try expect_line(1, "b", test_value[0..fitting_len]);
    // Even an empty value costs its name and the overhead, so nothing more fits.
    try testing.expectError(error.SectionTooLarge, test_section.append("c", ""));
    try expect_state(2, limits.field_section_size_max, first_octets_len + 1 + fitting_len);
    try expect_line(0, "a", &test_value);
}

test "the line after field_count_max is refused and changes nothing" {
    test_section.init();
    for (0..limits.field_count_max) |_| try test_section.append("n", "v");
    const size = limits.field_count_max * (1 + 1 + limits.field_line_overhead);
    const octets_len = limits.field_count_max * 2;
    try expect_state(limits.field_count_max, size, octets_len);
    try testing.expectError(error.TooManyLines, test_section.append("n", "v"));
    try expect_state(limits.field_count_max, size, octets_len);
    try expect_line(limits.field_count_max - 1, "n", "v");
}

test "find compares names case-insensitively (RFC 9110 §5.1)" {
    test_section.init();
    try test_section.append("Content-Length", "42");
    const found = test_section.find("content-length") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("Content-Length", found.name);
    try testing.expectEqualStrings("42", found.value);
    const upper = test_section.find("CONTENT-LENGTH") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("42", upper.value);
    try testing.expectEqual(null, test_section.find("content-lengt"));
    try testing.expectEqual(null, test_section.find("content-length2"));
}

test "the iterator yields every line in order and then null, and an empty section yields none" {
    test_section.init();
    var empty = test_section.iterator();
    try testing.expectEqual(null, empty.next());
    try test_section.append("a", "1");
    try test_section.append("b", "2");
    var lines = test_section.iterator();
    const first = lines.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("a", first.name);
    try testing.expectEqualStrings("1", first.value);
    const second = lines.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("b", second.name);
    try testing.expectEqualStrings("2", second.value);
    try testing.expectEqual(null, lines.next());
    try testing.expectEqual(null, lines.next());
}

test "clear empties the section, and it accepts lines again" {
    test_section.init();
    try test_section.append("a", "1");
    try test_section.append("b", "2");
    test_section.clear();
    try expect_state(0, 0, 0);
    try testing.expectEqual(null, test_section.find("a"));
    var lines = test_section.iterator();
    try testing.expectEqual(null, lines.next());
    try test_section.append("c", "3");
    try expect_state(1, 1 + 1 + limits.field_line_overhead, 2);
    try expect_line(0, "c", "3");
}
