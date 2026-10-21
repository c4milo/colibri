//! The agreement of the head writers with the writers they replaced (design §8 step 17). Before
//! `message_write_fields.Checked.add`, each rule scanned the field lines itself. `reference` keeps
//! that code, test-only, and the tests require the same octets or the same error from both, over
//! every list of up to three lines from `atoms`.
//!
//! `connection_fields_test.zig` reads `reference` too, for a connection's rules.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const message_start = @import("message_start.zig");
const message_target = @import("message_target.zig");
const message_write = @import("message_write.zig");

const testing = std.testing;
const Field = http.Field;
const Writer = core.Writer;
const Error = message_write.Error;
const Code = http.status.Code;

/// The head writers as they were before the pass, each rule with its own scan.
pub const reference = struct {
    const version = "HTTP/1.1";
    const host_name = "Host";
    const content_length_name = "Content-Length";
    const transfer_encoding_name = "Transfer-Encoding";

    pub fn write_request_head(output: []u8, method: []const u8, target: []const u8, fields: []const Field) Error!usize {
        // RFC 9110 §9.1: method = token.
        http.method.validate(method) catch return error.MethodInvalid;
        const line: message_start.RequestLine = .{ .method = method, .target = target, .version = .{ .major = 1, .minor = 1 } };
        // RFC 9112 §3.2: a request-target of one of the four forms, as its method takes it.
        _ = message_target.target_form(line) catch return error.TargetInvalid;
        try check_fields(fields);
        // RFC 9110 §9.3.6: a CONNECT request message does not have content.
        if (http.method.standard(method) == .connect and declares_content(fields)) return error.FramingInvalid;
        // RFC 9112 §3.2: a client MUST send one Host in every HTTP/1.1 request.
        if (count_named(fields, host_name) != 1) return error.HostInvalid;
        // RFC 9110 §7.2: Host = uri-host [ ":" port ].
        if (!http.uri.is_host_port(find(fields, host_name).?)) return error.HostInvalid;
        var writer = Writer.init(output);
        // RFC 9112 §2.1: a buffer that holds less than the whole head holds no head at all.
        write_head(&writer, fields, .{ method, " ", target, " ", version }) catch return error.OutputTooSmall;
        return writer.written().len;
    }

    pub fn write_response_head(output: []u8, status: u16, reason: []const u8, fields: []const Field) Error!usize {
        // RFC 9110 §15: a status code is three digits from 100 to 599.
        const code = http.Status.from_code(status) catch return error.StatusInvalid;
        // RFC 9112 §4: reason-phrase = 1*( HTAB / SP / VCHAR / obs-text ).
        message_start.check_reason(reason) catch return error.ReasonInvalid;
        try check_fields(fields);
        const forbids_framing = code.is_interim() or status == @intFromEnum(http.status.Code.no_content);
        const framed = find(fields, content_length_name) != null or find(fields, transfer_encoding_name) != null;
        // RFC 9112 §6.1 and RFC 9110 §8.6: no Transfer-Encoding or Content-Length in a 1xx or 204.
        if (forbids_framing and framed) return error.FramingInvalid;
        var digits: [http.constants.status_digits_len]u8 = undefined;
        var writer = Writer.init(output);
        // RFC 9112 §2.1: a buffer that holds less than the whole head holds no head at all.
        write_head(&writer, fields, .{ version, " ", code.write_digits(&digits), " ", reason }) catch return error.OutputTooSmall;
        return writer.written().len;
    }

    fn check_fields(fields: []const Field) Error!void {
        for (fields) |line| {
            // RFC 9110 §5.1: field-name = token.
            http.field.validate_name(line.name) catch return error.FieldNameInvalid;
            // RFC 9110 §5.5: no NUL, CR, LF or other control.
            http.field.validate_value(line.value) catch return error.FieldValueInvalid;
        }
        const both = find(fields, content_length_name) != null and find(fields, transfer_encoding_name) != null;
        // RFC 9112 §6.2: a sender MUST NOT send Content-Length in a message with Transfer-Encoding.
        if (both) return error.FramingInvalid;
        try check_framing(fields);
    }

    fn check_framing(fields: []const Field) Error!void {
        // RFC 9110 §8.6: one Content-Length value; colibri writes no list of repeats.
        if (count_named(fields, content_length_name) > 1) return error.FramingInvalid;
        if (find(fields, content_length_name)) |value| {
            // RFC 9110 §8.6: Content-Length = 1*DIGIT.
            if (value.len == 0 or !http.uri.is_port(value)) return error.FramingInvalid;
            // RFC 9110 §8.6: a length colibri can count, which a u64 holds.
            _ = std.fmt.parseUnsigned(u64, value, http.constants.content_length_radix) catch return error.FramingInvalid;
        }
        // RFC 9112 §6.1: colibri applies chunked, once, as the only coding it writes.
        if (count_named(fields, transfer_encoding_name) > 1) return error.FramingInvalid;
        if (find(fields, transfer_encoding_name)) |value| {
            // RFC 9112 §7.1: the chunked coding's name, compared case-insensitively (§7).
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.FramingInvalid;
        }
    }

    const start_line_parts = 5;

    fn write_head(writer: *Writer, fields: []const Field, start_line: [start_line_parts][]const u8) core.writer.Error!void {
        for (start_line) |part| try writer.write_bytes(part);
        try writer.write_bytes("\r\n");
        for (fields) |line| {
            try writer.write_bytes(line.name);
            try writer.write_bytes(": ");
            try writer.write_bytes(line.value);
            try writer.write_bytes("\r\n");
        }
        try writer.write_bytes("\r\n");
    }

    fn count_named(fields: []const Field, name: []const u8) usize {
        var count: usize = 0;
        for (fields) |line| {
            if (http.field.names_equal(line.name, name)) count += 1;
        }
        return count;
    }

    fn declares_content(fields: []const Field) bool {
        if (find(fields, transfer_encoding_name) != null) return true;
        const length = find(fields, content_length_name) orelse return false;
        return (std.fmt.parseUnsigned(u64, length, http.constants.content_length_radix) catch unreachable) > 0;
    }

    pub fn find(fields: []const Field, name: []const u8) ?[]const u8 {
        for (fields) |line| {
            if (http.field.names_equal(line.name, name)) return line.value;
        }
        return null;
    }
};

/// The lines the lists are made of: one of each fault, each name a rule reads in more than one
/// case, and names one octet away from those names.
pub const atom = struct {
    pub const plain: Field = .{ .name = "Content-Type", .value = "text/plain" };
    pub const content_length: Field = .{ .name = "Content-Length", .value = "8" };
    pub const content_length_zero: Field = .{ .name = "content-length", .value = "0" };
    pub const content_length_letter: Field = .{ .name = "CONTENT-LENGTH", .value = "x" };
    pub const content_length_empty: Field = .{ .name = "Content-Length", .value = "" };
    pub const content_length_underscore: Field = .{ .name = "Content-Length", .value = "1_0" };
    pub const content_length_sign: Field = .{ .name = "Content-Length", .value = "+5" };
    pub const content_length_overflow: Field = .{ .name = "Content-Length", .value = "18446744073709551616" };
    pub const chunked: Field = .{ .name = "Transfer-Encoding", .value = "chunked" };
    pub const chunked_lowercase: Field = .{ .name = "transfer-encoding", .value = "Chunked" };
    pub const gzip: Field = .{ .name = "TRANSFER-ENCODING", .value = "gzip" };
    pub const close: Field = .{ .name = "Connection", .value = "close" };
    pub const keep_alive: Field = .{ .name = "CONNECTION", .value = "keep-alive" };
    pub const close_listed: Field = .{ .name = "connection", .value = "Keep-Alive, CLOSE" };
    pub const name_invalid: Field = .{ .name = "a b", .value = "c" };
    pub const value_invalid: Field = .{ .name = "a", .value = " b" };
    pub const name_empty: Field = .{ .name = "", .value = "v" };
    pub const content_length_near: Field = .{ .name = "content-lengtx", .value = "x" };
    pub const transfer_encoding_near: Field = .{ .name = "Transfer-Encodinx", .value = "gzip" };
    pub const connection_near: Field = .{ .name = "Connectiox", .value = "close" };
    pub const host: Field = .{ .name = "Host", .value = "a" };
    pub const host_port: Field = .{ .name = "host", .value = "a:1" };
    pub const host_invalid: Field = .{ .name = "HOST", .value = "u@a" };
    pub const host_near: Field = .{ .name = "Hosx", .value = "a" };
    pub const upgrade: Field = .{ .name = "Upgrade", .value = "h2c" };
};

pub const atoms = [_]Field{
    atom.plain,                  atom.content_length,          atom.content_length_zero,
    atom.content_length_letter,  atom.content_length_empty,    atom.content_length_underscore,
    atom.content_length_sign,    atom.content_length_overflow, atom.chunked,
    atom.chunked_lowercase,      atom.gzip,                    atom.close,
    atom.keep_alive,             atom.close_listed,            atom.name_invalid,
    atom.value_invalid,          atom.name_empty,              atom.content_length_near,
    atom.transfer_encoding_near, atom.connection_near,         atom.host,
    atom.host_port,              atom.host_invalid,            atom.host_near,
    atom.upgrade,
};

/// The longest list a test builds.
pub const list_len_max = 3;

/// The count of lists of `len_max` lines or fewer from a set of `set_len` lines.
pub fn lists_len(set_len: usize, len_max: usize) usize {
    var count: usize = 0;
    for (0..len_max + 1) |len| count += std.math.pow(usize, set_len, len);
    return count;
}

/// The list at `index` in the order `lists_len` counts: the empty list, then each list of one line
/// from `set`, then of two, and so on.
pub fn list_at(set: []const Field, index: usize, lines: *[list_len_max]Field) []const Field {
    var rest = index;
    for (0..list_len_max + 1) |len| {
        const count = std.math.pow(usize, set.len, len);
        if (rest >= count) {
            rest -= count;
            continue;
        }
        for (lines[0..len]) |*line| {
            line.* = set[rest % set.len];
            rest /= set.len;
        }
        return lines[0..len];
    }
    unreachable;
}

/// Requires the same octets from both writers, or the same error.
pub fn expect_same(new: anytype, new_output: []const u8, old: @TypeOf(new), old_output: []const u8) !void {
    const old_len = old catch |failure| return testing.expectError(failure, new);
    try testing.expectEqualStrings(old_output[0..old_len], new_output[0..try new]);
}

/// The two buffers the writers write into.
var test_output_new: [test_output_len]u8 = undefined;
var test_output_old: [test_output_len]u8 = undefined;
const test_output_len = 512;

/// A buffer too short for most heads of two or three lines, so each writer refuses them.
const test_output_short = 40;

/// A status below 100, and 103 (Early Hints, RFC 8297 §2), which `http.status.Code` does not name.
const status_below_min: u16 = 99;
const status_early_hints: u16 = 103;
const statuses = [_]u16{
    status_below_min,             @intFromEnum(Code.@"continue"), status_early_hints,
    @intFromEnum(Code.ok),        @intFromEnum(Code.no_content),  @intFromEnum(Code.not_modified),
    @intFromEnum(Code.not_found),
};
const reasons = [_][]const u8{ "OK", "", "O\r\nK" };

fn expect_same_response(status: u16, reason: []const u8, fields: []const Field, output_len: usize) !void {
    errdefer std.debug.print("status {d}, reason \"{s}\", fields {any}\n", .{ status, reason, fields });
    const new = message_write.write_response_head(test_output_new[0..output_len], status, reason, fields);
    const old = reference.write_response_head(test_output_old[0..output_len], status, reason, fields);
    try expect_same(new, &test_output_new, old, &test_output_old);
}

test "every response head of up to three lines is written as the scans wrote it, or refused with their error" {
    var lines: [list_len_max]Field = undefined;
    for (0..lists_len(atoms.len, list_len_max)) |index| {
        const fields = list_at(&atoms, index, &lines);
        for (statuses) |status| {
            for (reasons) |reason| try expect_same_response(status, reason, fields, test_output_len);
        }
        try expect_same_response(@intFromEnum(Code.ok), "OK", fields, test_output_short);
    }
}

const methods = [_][]const u8{ "GET", "CONNECT", "G T" };
const targets = [_][]const u8{ "/", "a:1" };

fn expect_same_request(method: []const u8, target: []const u8, fields: []const Field, output_len: usize) !void {
    errdefer std.debug.print("method \"{s}\", target \"{s}\", fields {any}\n", .{ method, target, fields });
    const new = message_write.write_request_head(test_output_new[0..output_len], method, target, fields);
    const old = reference.write_request_head(test_output_old[0..output_len], method, target, fields);
    try expect_same(new, &test_output_new, old, &test_output_old);
}

test "every request head of up to three lines is written as the scans wrote it, or refused with their error" {
    var lines: [list_len_max]Field = undefined;
    for (0..lists_len(atoms.len, list_len_max)) |index| {
        const fields = list_at(&atoms, index, &lines);
        for (methods) |method| {
            for (targets) |target| try expect_same_request(method, target, fields, test_output_len);
        }
        try expect_same_request("GET", "/", fields, test_output_short);
    }
}

test "the lists hold each line alone, each pair and each three, in each order" {
    var lines: [list_len_max]Field = undefined;
    try testing.expectEqual(0, list_at(&atoms, 0, &lines).len);
    try testing.expectEqualStrings(atoms[atoms.len - 1].name, list_at(&atoms, atoms.len, &lines)[0].name);
    const last = list_at(&atoms, lists_len(atoms.len, list_len_max) - 1, &lines);
    try testing.expectEqual(list_len_max, last.len);
    for (last) |line| try testing.expectEqualStrings(atoms[atoms.len - 1].name, line.name);
    // A list of two: the second atom, then the first.
    const pair = list_at(&atoms, 1 + atoms.len + 1, &lines);
    try testing.expectEqualStrings(atoms[1].value, pair[0].value);
    try testing.expectEqualStrings(atoms[0].value, pair[1].value);
}
