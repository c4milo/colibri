//! A final response's field lines as decision 101 has them (design §8 step 17e): the caller's,
//! less Content-Length and with a strong ETag made weak when the representation is coded, then
//! Content-Encoding and Vary. A caller's own Content-Encoding stays before the server's, which
//! names the coding applied last (RFC 9110 §8.4).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const coding_rules = @import("coding_rules.zig");

const Field = http.Field;

pub const Error = error{
    /// More field lines than `field_count_max`, or an ETag too long to make weak.
    SectionTooLarge,
    /// A second ETag line.
    FieldLineInvalid,
};

/// Where `rewrite` writes the lines, and the weak ETag's value.
pub const Rewritten = struct {
    lines: [core.constants.field_count_max]Field,
    etag: [core.constants.field_value_len_max]u8,
};

/// The lines `fields` become under `plan`, in `into`, or `fields` itself when the plan changes
/// nothing.
pub fn rewrite(fields: []const Field, plan: coding_rules.Plan, into: *Rewritten) Error![]const Field {
    assert(!plan.names_coding or plan.coding != null);
    if (plan.coding == null and !plan.vary) return fields;
    var len: usize = 0;
    var etag_seen = false;
    for (fields) |field| {
        const kept = if (plan.coding == null) field else try recode(field, into, &etag_seen) orelse continue;
        len = try append(into, len, kept);
    }
    if (plan.names_coding) len = try append(into, len, .{ .name = content_encoding, .value = plan.coding.?.name() });
    if (plan.vary) len = try append(into, len, .{ .name = vary, .value = accept_encoding });
    return into.lines[0..len];
}

/// The line `field` becomes in a coded representation's section, or null for a line it loses.
fn recode(field: Field, into: *Rewritten, etag_seen: *bool) Error!?Field {
    // RFC 9110 §8.6: Content-Length counts the coded octets, which are not known when the head
    // goes out, and those of a HEAD's or a 304's coded 200 are never known.
    if (http.field.names_equal(field.name, content_length)) return null;
    if (!http.field.names_equal(field.name, etag)) return field;
    // RFC 9110 §8.8.3: ETag = entity-tag, a single one.
    if (etag_seen.*) return error.FieldLineInvalid;
    etag_seen.* = true;
    // RFC 9110 §8.8.3: a weak tag starts with "W/", case-sensitively, and stays as it is.
    if (std.mem.startsWith(u8, field.value, weak_prefix)) return field;
    // RFC 9110 §8.8.3.3: a coded representation's strong tag has to differ from the uncoded one's,
    // and decision 101 makes it weak (§8.8.1). colibri's limit on a value covers the weak one.
    if (weak_prefix.len + field.value.len > into.etag.len) return error.SectionTooLarge;
    @memcpy(into.etag[0..weak_prefix.len], weak_prefix);
    @memcpy(into.etag[weak_prefix.len..][0..field.value.len], field.value);
    return .{ .name = field.name, .value = into.etag[0 .. weak_prefix.len + field.value.len] };
}

fn append(into: *Rewritten, len: usize, field: Field) Error!usize {
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    if (len == into.lines.len) return error.SectionTooLarge;
    into.lines[len] = field;
    return len + 1;
}

const content_length = "content-length";
const content_encoding = "content-encoding";
const etag = "etag";
const vary = "vary";
const accept_encoding = "accept-encoding";
const weak_prefix = "W/";

const testing = std.testing;

/// Where the tests rewrite, outside any stack frame. Test-only.
threadlocal var test_rewritten: Rewritten align(@alignOf(Rewritten)) = undefined;

const test_coded: coding_rules.Plan = .{ .vary = true, .coding = .gzip, .names_coding = true, .encodes = true };

fn expect_lines(expected: []const Field, actual: []const Field) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
    }
}

test "decision 101: a coded response loses Content-Length, its ETag turns weak, and it names the coding" {
    const fields = [_]Field{
        .{ .name = "Content-Length", .value = "70" },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "ETag", .value = "\"123-a\"" },
    };
    try expect_lines(&.{
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "ETag", .value = "W/\"123-a\"" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "vary", .value = "accept-encoding" },
    }, try rewrite(&fields, test_coded, &test_rewritten));
    // A weak tag stays as it is, and a caller's own coding comes first (RFC 9110 §8.4).
    const weak = [_]Field{ .{ .name = "etag", .value = "W/\"7\"" }, .{ .name = "content-encoding", .value = "br" } };
    try expect_lines(&.{
        .{ .name = "etag", .value = "W/\"7\"" },
        .{ .name = "content-encoding", .value = "br" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "vary", .value = "accept-encoding" },
    }, try rewrite(&weak, test_coded, &test_rewritten));
}

test "RFC 9110 §8.8.3: weak = %s\"W/\", which matches only as written, so w/ marks no tag weak" {
    // RFC 7405 §2.1: a string with the %s prefix is case-sensitive.
    const lower = [_]Field{.{ .name = "etag", .value = "w/\"7\"" }};
    try expect_lines(&.{
        .{ .name = "etag", .value = "W/w/\"7\"" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "vary", .value = "accept-encoding" },
    }, try rewrite(&lower, test_coded, &test_rewritten));
}

test "decision 101: an uncoded response keeps its lines, and one Accept-Encoding chose gains Vary" {
    const fields = [_]Field{ .{ .name = "content-length", .value = "5" }, .{ .name = "etag", .value = "\"1\"" } };
    try testing.expectEqual(@as([*]const Field, &fields), (try rewrite(&fields, .{}, &test_rewritten)).ptr);
    try expect_lines(&.{
        fields[0],
        fields[1],
        .{ .name = "vary", .value = "accept-encoding" },
    }, try rewrite(&fields, .{ .vary = true }, &test_rewritten));
    // RFC 9110 §15.4.5: a 304 gets the Vary and the weak ETag, and names no coding.
    try expect_lines(&.{
        .{ .name = "etag", .value = "W/\"1\"" },
        .{ .name = "vary", .value = "accept-encoding" },
    }, try rewrite(&fields, .{ .vary = true, .coding = .deflate }, &test_rewritten));
}

test "decision 101: a second ETag, an ETag past the limit and a section past it are refused" {
    const two = [_]Field{ .{ .name = "etag", .value = "\"1\"" }, .{ .name = "etag", .value = "\"2\"" } };
    try testing.expectError(error.FieldLineInvalid, rewrite(&two, test_coded, &test_rewritten));
    const long_value: [core.constants.field_value_len_max - 1]u8 = @splat('a');
    const long = [_]Field{.{ .name = "etag", .value = &long_value }};
    try testing.expectError(error.SectionTooLarge, rewrite(&long, test_coded, &test_rewritten));
    const full: [core.constants.field_count_max]Field = @splat(.{ .name = "x", .value = "y" });
    try testing.expectError(error.SectionTooLarge, rewrite(&full, .{ .vary = true }, &test_rewritten));
}
