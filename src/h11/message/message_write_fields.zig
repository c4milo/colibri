//! The one pass over the field lines of a head that colibri writes (design §8 step 17). The pass,
//! `Checked.add`, validates each line, and compares its name with each name that a rule of the
//! head writers or of the connection reads. The rules then read the record, and no rule reads the
//! lines again.
//!
//! The pass keeps the error of the first line that is not valid, and compares the names of every
//! line after it too. A rule that a connection applies before validation, such as no framing
//! field in a 2xx to CONNECT, reads those later lines.
//!
//! The caller holds the record and the pass writes into it, so the record is not copied when the
//! pass returns.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");

const Field = http.Field;

/// The names the pass compares. Names compare case-insensitively (RFC 9110 §5.1).
const host_name = "Host";
const connection_name = "Connection";
const content_length_name = http.content_length.name;
const transfer_encoding_name = "Transfer-Encoding";

comptime {
    // The pass picks the one name it compares by the length of a line's name, so no two of the
    // names have one length.
    const lengths = [_]usize{ host_name.len, connection_name.len, content_length_name.len, transfer_encoding_name.len };
    for (lengths, 0..) |length, index| {
        for (lengths[index + 1 ..]) |other| assert(length != other);
    }
}

/// The error of a field line that is not valid.
const Invalid = error{
    /// A field name that is not a token (RFC 9110 §5.1).
    FieldNameInvalid,
    /// A field value holding a control, or leading or trailing whitespace (RFC 9110 §5.5).
    FieldValueInvalid,
};

/// The first value of one field name in a section, and whether a second line has the name.
const Named = struct {
    value: ?[]const u8 = null,
    repeated: bool = false,

    fn add(named: *Named, value: []const u8) void {
        if (named.value == null) {
            named.value = value;
        } else {
            named.repeated = true;
        }
    }
};

/// The field lines of one head, after the pass.
pub const Checked = struct {
    /// The error of the first line that is not valid, or null when each line is valid.
    invalid: ?Invalid = null,
    host: Named = .{},
    content_length: Named = .{},
    transfer_encoding: Named = .{},
    /// The first Content-Length value as a u64, or null when there is none or `parseUnsigned`
    /// refuses it.
    content_length_octets: ?u64 = null,
    /// A Connection line carries the close option (RFC 9110 §7.6.1).
    close: bool = false,

    /// Reads each line of `fields` once, and records what the rules read. The record of a head
    /// starts as `.{}`.
    pub fn add(checked: *Checked, fields: []const Field) void {
        for (fields) |line| {
            if (checked.invalid == null) checked.invalid = check_line(line);
            name_line(checked, line);
        }
        if (checked.content_length.value) |value| {
            // RFC 9110 §8.6: Content-Length = 1*DIGIT, and colibri counts a length a u64 holds.
            checked.content_length_octets = std.fmt.parseUnsigned(u64, value, http.constants.protocol.content_length_radix) catch null;
        }
        assert(checked.content_length_octets == null or checked.content_length.value != null);
    }

    /// Whether a line names Content-Length or Transfer-Encoding.
    pub fn names_framing(checked: *const Checked) bool {
        return checked.content_length.value != null or checked.transfer_encoding.value != null;
    }
};

/// The error of `line`, or null when it is valid.
fn check_line(line: Field) ?Invalid {
    // RFC 9110 §5.1: field-name = token.
    http.field.validate_name(line.name) catch return error.FieldNameInvalid;
    // RFC 9110 §5.5: no NUL, CR, LF or other control, and RFC 9112 §5.2: no obs-fold, which a
    // value without CR and LF cannot hold.
    http.field.validate_value(line.value) catch return error.FieldValueInvalid;
    return null;
}

/// Records `line` under the name it has, when a rule reads that name.
fn name_line(checked: *Checked, line: Field) void {
    switch (line.name.len) {
        host_name.len => if (http.field.names_equal(line.name, host_name)) checked.host.add(line.value),
        connection_name.len => if (line_asks_close(line)) {
            checked.close = true;
        },
        content_length_name.len => if (http.field.names_equal(line.name, content_length_name)) checked.content_length.add(line.value),
        transfer_encoding_name.len => if (http.field.names_equal(line.name, transfer_encoding_name)) checked.transfer_encoding.add(line.value),
        else => {},
    }
}

/// Connection = #connection-option, and an option is a token compared case-insensitively
/// (RFC 9110 §7.6.1). A connection reads the lines of a head it receives with this too.
pub fn line_asks_close(line: Field) bool {
    if (!http.field.names_equal(line.name, connection_name)) return false;
    var options = std.mem.splitScalar(u8, line.value, ',');
    // Bounded: a value of n octets holds at most n + 1 members.
    for (0..line.value.len + 1) |_| {
        const option = options.next() orelse return false;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, option, " \t"), "close")) return true;
    }
    return false;
}

const testing = std.testing;

fn checked_of(fields: []const Field) Checked {
    var checked: Checked = .{};
    checked.add(fields);
    return checked;
}

test "each name a rule reads is found in any case, and a name of the same length is not" {
    const checked = checked_of(&.{
        .{ .name = "hOST", .value = "a" },
        .{ .name = "content-lengtx", .value = "x" },
        .{ .name = "CONTENT-LENGTH", .value = "7" },
        .{ .name = "Transfer-Encodinx", .value = "gzip" },
        .{ .name = "transfer-encoding", .value = "chunked" },
        .{ .name = "Connectiox", .value = "close" },
        .{ .name = "Hosx", .value = "b" },
    });
    try testing.expect(checked.invalid == null);
    try testing.expectEqualStrings("a", checked.host.value.?);
    try testing.expectEqualStrings("7", checked.content_length.value.?);
    try testing.expectEqualStrings("chunked", checked.transfer_encoding.value.?);
    try testing.expectEqual(7, checked.content_length_octets.?);
    try testing.expect(!checked.host.repeated and !checked.content_length.repeated and !checked.transfer_encoding.repeated);
    try testing.expect(!checked.close);
}

test "the first value of a name is kept, and a second line of it is counted" {
    const checked = checked_of(&.{
        .{ .name = "Content-Length", .value = "1_0" },
        .{ .name = "Host", .value = "a" },
        .{ .name = "Content-Length", .value = "x" },
        .{ .name = "Transfer-Encoding", .value = "gzip" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    });
    try testing.expectEqualStrings("1_0", checked.content_length.value.?);
    try testing.expect(checked.content_length.repeated and checked.transfer_encoding.repeated and !checked.host.repeated);
    try testing.expectEqualStrings("gzip", checked.transfer_encoding.value.?);
    // parseUnsigned reads an underscore between digits, and the head writer refuses it later.
    try testing.expectEqual(10, checked.content_length_octets.?);
    try testing.expect(checked_of(&.{.{ .name = "Content-Length", .value = "+5" }}).content_length_octets == null);
    try testing.expect(checked_of(&.{.{ .name = "Content-Length", .value = "18446744073709551616" }}).content_length_octets == null);
}

test "RFC 9110 §7.6.1: the close option is found in any Connection line, in any case, and nowhere else" {
    try testing.expect(checked_of(&.{
        .{ .name = "Connection", .value = "keep-alive" },
        .{ .name = "connection", .value = "Keep-Alive, CLOSE" },
    }).close);
    try testing.expect(!checked_of(&.{.{ .name = "Connection", .value = "keep-alive, closed" }}).close);
    try testing.expect(!checked_of(&.{.{ .name = "Proxy-Close", .value = "close" }}).close);
}

test "RFC 9110 §5.1 and §5.5: the first line that is not valid is kept, and the names after it are read" {
    const checked = checked_of(&.{
        .{ .name = "a", .value = " b" },
        .{ .name = "a b", .value = "c" },
        .{ .name = "Content-Length", .value = "0" },
        .{ .name = "Connection", .value = "close" },
    });
    try testing.expectEqual(error.FieldValueInvalid, checked.invalid.?);
    try testing.expectEqualStrings("0", checked.content_length.value.?);
    try testing.expect(checked.close and checked.names_framing());
    // A line's name is checked before its value.
    try testing.expectEqual(error.FieldNameInvalid, checked_of(&.{.{ .name = "a b", .value = " c" }}).invalid.?);
    try testing.expect(!checked_of(&.{}).names_framing());
}
