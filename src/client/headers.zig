//! A response's header section and trailer section, each held in a buffer the program gives
//! (decision 152). The client copies each field line of a section into its buffer, and a program
//! reads them with `get` and `iterator`. `Headers` and `Trailers` are two types, so that a program
//! cannot pass one where the other goes, with one layout and the same calls.
//!
//! Each field line takes `line_overhead_len` octets in the buffer beside its name and its value:
//! the name's length and the value's length, each in two octets, in network byte order.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");

/// One header or trailer: a field line's name and value (RFC 9110 §5.2).
pub const Header = http.Field;

/// Which section a type holds.
const Section = enum { header, trailer };

/// The octets each field line takes beside its name and its value: two lengths of two octets.
pub const line_overhead_len: usize = length_len + length_len;
const length_len: usize = @sizeOf(Length);
const Length = u16;

comptime {
    // A name and a value as long as colibri reads each fit their two octets.
    assert(core.constants.limits.field_name_len_max <= std.math.maxInt(Length));
    assert(core.constants.limits.field_value_len_max <= std.math.maxInt(Length));
}

/// The header section of a response (RFC 9110 §6.3).
pub const Headers = FieldLines(.header);
/// The trailer section of a response (RFC 9110 §6.5).
pub const Trailers = FieldLines(.trailer);

fn FieldLines(comptime section: Section) type {
    return struct {
        const Lines = @This();
        comptime {
            assert(section == .header or section == .trailer);
        }

        /// The program's memory for the section's field lines. Empty: the client drops the
        /// section.
        buffer: []u8 = &.{},
        /// Octets of `buffer` the field lines filled.
        len: usize = 0,

        /// What `iterator` returns.
        pub const Iterator = LineIterator;

        /// The value of the first field line named `name`, compared case-insensitively (RFC 9110
        /// §5.1), or null when the section has none.
        pub fn get(lines: *const Lines, name: []const u8) ?[]const u8 {
            var each = lines.iterator();
            // Bounded: `next` returns each stored line once, and each takes octets of `len`.
            for (0..lines_max(lines.len)) |_| {
                const line = each.next() orelse return null;
                if (std.ascii.eqlIgnoreCase(line.name, name)) return line.value;
            }
            return null;
        }

        /// Each field line in the order it arrived, for a field that cannot be joined into one
        /// value, such as Set-Cookie (RFC 9110 §5.3).
        pub fn iterator(lines: *const Lines) Iterator {
            assert(lines.len <= lines.buffer.len);
            return .{ .reader = core.Reader.init(lines.buffer[0..lines.len]) };
        }
    };
}

/// Walks the field lines of a `Headers` or a `Trailers`, as `Headers.Iterator` and
/// `Trailers.Iterator`.
const LineIterator = struct {
    reader: core.Reader,

    /// The next field line, or null after the last.
    pub fn next(each: *LineIterator) ?Header {
        if (each.reader.remaining_len() == 0) return null;
        // The client wrote every line whole (`append`), so a short read is a broken buffer.
        const name_len = each.reader.take_int_big(Length) catch unreachable;
        const value_len = each.reader.take_int_big(Length) catch unreachable;
        const name = each.reader.take(name_len) catch unreachable;
        const value = each.reader.take(value_len) catch unreachable;
        return .{ .name = name, .value = value };
    }
};

/// The most field lines `len` octets can hold, which bounds each walk over them.
fn lines_max(len: usize) usize {
    return len / line_overhead_len;
}

/// Copies each field line of `from`, from index `first`, after the lines `lines` holds. A section
/// that does not fit is refused whole, and `lines` keeps what it held. An empty buffer drops the
/// section. The client calls it; a program does not, because the root does not export it.
pub fn record(lines: anytype, from: *const http.FieldSection, first: u32) core.Writer.Error!void {
    assert(first <= from.len());
    if (lines.buffer.len == 0) return;
    const start = lines.len;
    errdefer lines.len = start;
    var each: http.FieldSection.Iterator = .{ .slice = from.slice(), .index = first };
    // Bounded: the section holds `len()` lines.
    for (0..from.len()) |_| {
        const line = each.next() orelse break;
        try append(lines, line.name, line.value);
    }
}

fn append(lines: anytype, name: []const u8, value: []const u8) core.Writer.Error!void {
    assert(name.len <= core.constants.limits.field_name_len_max);
    assert(value.len <= core.constants.limits.field_value_len_max);
    var writer = core.Writer.init(lines.buffer[lines.len..]);
    try writer.write_int_big(Length, @intCast(name.len));
    try writer.write_int_big(Length, @intCast(value.len));
    try writer.write_bytes(name);
    try writer.write_bytes(value);
    lines.len += writer.written().len;
    assert(lines.len <= lines.buffer.len);
}

/// Empties `lines`, so an exchange sent again writes them anew, and keeps the buffer.
pub fn clear(lines: anytype) void {
    lines.len = 0;
}

const testing = std.testing;

/// A section the tests fill, outside any stack frame. Test-only.
threadlocal var test_section: http.FieldSection align(@alignOf(http.FieldSection)) = undefined;

test "decision 152: Headers and Trailers each have two calls, get and iterator" {
    // Decision 158 ruling 6 adds `Iterator`, which `iterator` returns.
    const public_names = core.public_names;
    try public_names.expect(Headers, &.{ "Iterator", "get", "iterator" });
    try public_names.expect(Trailers, &.{ "Iterator", "get", "iterator" });
    try public_names.expect(Headers.Iterator, &.{"next"});
    try testing.expect(Headers.Iterator == Trailers.Iterator);
    try testing.expect(Headers != Trailers);
}

test "RFC 9110 §5.1: get finds the first line of a name in any case, and null for none" {
    test_section.init();
    try test_section.append(":status", "200");
    try test_section.append("set-cookie", "a=1");
    try test_section.append("Content-Type", "text/plain");
    try test_section.append("Set-Cookie", "b=2");
    var buffer: [128]u8 = undefined;
    var headers: Headers = .{ .buffer = &buffer };
    try record(&headers, &test_section, 1);
    try testing.expectEqualStrings("text/plain", headers.get("content-type").?);
    try testing.expectEqualStrings("a=1", headers.get("SET-COOKIE").?);
    try testing.expectEqual(null, headers.get(":status"));
    try testing.expectEqual(null, headers.get("age"));
}

test "RFC 9110 §5.3: the iterator returns each line in the order it arrived" {
    test_section.init();
    try test_section.append("set-cookie", "a=1");
    try test_section.append("set-cookie", "b=2");
    var buffer: [64]u8 = undefined;
    var trailers: Trailers = .{ .buffer = &buffer };
    try record(&trailers, &test_section, 0);
    var each = trailers.iterator();
    try testing.expectEqualStrings("a=1", each.next().?.value);
    try testing.expectEqualStrings("b=2", each.next().?.value);
    try testing.expectEqual(null, each.next());
}

test "a section past the buffer is refused whole, and an empty buffer drops it" {
    test_section.init();
    try test_section.append("grpc-status", "0");
    try test_section.append("grpc-message", "a message too long for the buffer");
    var buffer: [24]u8 = undefined;
    var trailers: Trailers = .{ .buffer = &buffer };
    try testing.expectError(error.NoSpaceLeft, record(&trailers, &test_section, 0));
    try testing.expectEqual(0, trailers.len);
    try testing.expectEqual(null, trailers.get("grpc-status"));
    var dropped: Trailers = .{};
    try record(&dropped, &test_section, 0);
    try testing.expectEqual(0, dropped.len);
}

test "a line takes line_overhead_len octets beside its name and value" {
    test_section.init();
    try test_section.append("grpc-status", "0");
    var buffer: [line_overhead_len + "grpc-status".len + "0".len]u8 = undefined;
    var trailers: Trailers = .{ .buffer = &buffer };
    try record(&trailers, &test_section, 0);
    try testing.expectEqual(buffer.len, trailers.len);
    try testing.expectEqualStrings("0", trailers.get("grpc-status").?);
    clear(&trailers);
    try testing.expectEqual(0, trailers.len);
}
