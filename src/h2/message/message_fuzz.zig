//! The fuzz property of message.zig's three entry points, and the sweep that runs it over every
//! input of up to two octets. It shows that no field section reaches an assertion (invariant 24),
//! and that whatever an entry point accepts keeps the rules it checks. The property reads those
//! rules again here, without `walk`, `check` or `http.content_length`.
//!
//! An input is a list of lines, one pick octet at a time:
//!   - a pick below `fuzz_raw_value_pick` appends one line of `fuzz_lines`;
//!   - a pick from `fuzz_raw_value_pick` to below `fuzz_raw_name_pick` ends the list with one line
//!     whose name is a name of `fuzz_lines` and whose value is every remaining octet;
//!   - a pick at or above `fuzz_raw_name_pick` ends the list with one line whose name is every
//!     remaining octet and whose value is a value of `fuzz_lines`.
//! So arbitrary octets arrive in every name and every value check, after any sequence of lines
//! the table holds. Everything in this file is test-only.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const message = @import("message.zig");
const message_lines = @import("message_lines.zig");

const Field = http.field.Field;
const FieldSection = http.FieldSection;
const Kind = message_lines.Kind;

/// Most octets one fuzz input carries: room for a few table lines and a 20-digit content-length.
const fuzz_input_len_max = 32;

/// The first pick octet that ends the input with a raw value.
const fuzz_raw_value_pick = 0x80;

/// The first pick octet that ends the input with a raw name.
const fuzz_raw_name_pick = 0xc0;

/// The base the property reads a content-length member in, independent of `http.content_length`.
const fuzz_decimal_radix = 10;

/// Most members the property splits one content-length value into: one more than its octets, and
/// one more call to find the end.
const fuzz_member_calls_max = fuzz_input_len_max + fuzz_member_calls_past_len;
const fuzz_member_calls_past_len = 2;

/// The lines a fuzz input picks from: for each check of steps 1 to 4, a line that passes it and a
/// line that breaks it.
const fuzz_lines = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "GE T" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":scheme", .value = "ftp" },
    .{ .name = ":authority", .value = "example.org:443" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "20x" },
    .{ .name = ":protocol", .value = "websocket" },
    .{ .name = "x-test", .value = "ok" },
    .{ .name = "x-test", .value = "ok\r" },
    .{ .name = "X-TEST", .value = "ok" },
    .{ .name = "te", .value = "trailers" },
    .{ .name = "te", .value = "trailers, deflate" },
    .{ .name = "connection", .value = "close" },
    .{ .name = "content-length", .value = "4" },
    .{ .name = "content-length", .value = "5" },
    .{ .name = "content-length", .value = "x" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":path", .value = "*" },
};

/// The section the property fills, placed outside any stack frame.
var fuzz_section: FieldSection = undefined;

/// Builds `fuzz_section` from the fuzz input and runs all three entry points over it.
fn fuzz_message(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    try fill_section(input[0..smith.slice(&input)]);
    if (message.validate_request(&fuzz_section)) |request| {
        try expect_legal_lines(.request);
        try expect_request_shape(request);
        try expect_content_length(request.content_length);
    } else |_| {}
    for ([_]bool{ false, true }) |end_stream| {
        const response = message.validate_response(&fuzz_section, end_stream) catch continue;
        try expect_legal_lines(.response);
        try std.testing.expect(!end_stream or !response.status.is_interim());
        try expect_content_length(response.content_length);
    }
    message.validate_trailers(&fuzz_section) catch return;
    try expect_legal_lines(.trailers);
}

/// Fills `fuzz_section` from `octets` as the header describes.
fn fill_section(octets: []const u8) !void {
    fuzz_section.init();
    for (octets, 0..) |pick, index| {
        const rest = octets[index + 1 ..];
        if (pick >= fuzz_raw_name_pick) {
            return fuzz_section.append(rest, fuzz_lines[(pick - fuzz_raw_name_pick) % fuzz_lines.len].value);
        }
        if (pick >= fuzz_raw_value_pick) {
            return fuzz_section.append(fuzz_lines[(pick - fuzz_raw_value_pick) % fuzz_lines.len].name, rest);
        }
        const line = fuzz_lines[pick % fuzz_lines.len];
        try fuzz_section.append(line.name, line.value);
    }
}

/// Every line of `fuzz_section`, which an entry point accepted as `kind`, against steps 1 and 2.
fn expect_legal_lines(kind: Kind) !void {
    var regular_seen = false;
    for (0..fuzz_section.len()) |index| {
        const line = fuzz_section.get(@intCast(index));
        try http.field.validate_value(line.value);
        if (message_lines.is_pseudo_header(line.name)) {
            try std.testing.expect(!regular_seen and defined_for(kind, line.name));
            try std.testing.expectEqual(1, count_named(line.name));
            continue;
        }
        regular_seen = true;
        try http.field.validate_name(line.name);
        for (line.name) |octet| try std.testing.expect(octet < 'A' or octet > 'Z');
        const which = http.connection_specific.classify(line.name) orelse continue;
        try std.testing.expect(which == .te and kind == .request);
        try std.testing.expect(http.connection_specific.te_is_trailers(line.value));
    }
}

/// True when message_lines.zig defines `name` for `kind`. Nothing is defined for trailers.
fn defined_for(kind: Kind, name: []const u8) bool {
    for (message_lines.definitions) |definition| {
        if (definition.kind == kind and std.mem.eql(u8, definition.name, name)) return true;
    }
    return false;
}

/// How many lines of `fuzz_section` carry exactly `name`.
fn count_named(name: []const u8) u32 {
    var count: u32 = 0;
    for (0..fuzz_section.len()) |index| {
        if (std.mem.eql(u8, fuzz_section.get(@intCast(index)).name, name)) count += 1;
    }
    return count;
}

/// The step 3 rules, on a request an entry point accepted.
fn expect_request_shape(request: message.Request) !void {
    try http.method.validate(request.method);
    try std.testing.expectEqual(std.mem.eql(u8, request.method, "CONNECT"), request.is_connect);
    if (request.is_connect) {
        try std.testing.expect(request.scheme == null and request.path == null);
        return expect_connect_authority(request.authority orelse return error.TestUnexpectedResult);
    }
    const scheme = request.scheme orelse return error.TestUnexpectedResult;
    const path = request.path orelse return error.TestUnexpectedResult;
    try std.testing.expect(scheme.len > 0);
    if (std.mem.eql(u8, path, "*")) return std.testing.expectEqualStrings("OPTIONS", request.method);
    const is_http = std.ascii.eqlIgnoreCase(scheme, "http") or std.ascii.eqlIgnoreCase(scheme, "https");
    try std.testing.expect(!is_http or std.mem.startsWith(u8, path, "/"));
}

/// A CONNECT `:authority` an entry point accepted: a host, a colon, and a port of digits.
fn expect_connect_authority(authority: []const u8) !void {
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse return error.TestUnexpectedResult;
    try std.testing.expect(colon > 0 and colon + 1 < authority.len);
    for (authority[colon + 1 ..]) |octet| try std.testing.expect(std.ascii.isDigit(octet));
}

/// The step 4 rule, on a content-length an entry point accepted: every member of every
/// content-length line is the digits of `content_length`.
fn expect_content_length(content_length: ?u64) !void {
    for (0..fuzz_section.len()) |index| {
        const line = fuzz_section.get(@intCast(index));
        if (!std.ascii.eqlIgnoreCase(line.name, "content-length")) continue;
        const expected = content_length orelse return error.TestUnexpectedResult;
        var members = std.mem.splitScalar(u8, line.value, ',');
        for (0..fuzz_member_calls_max) |_| {
            const member = members.next() orelse break;
            const digits = std.mem.trim(u8, member, " \t");
            for (digits) |octet| try std.testing.expect(octet >= '0' and octet <= '9');
            try std.testing.expectEqual(expected, try std.fmt.parseUnsigned(u64, digits, fuzz_decimal_radix));
        } else return error.TestUnexpectedResult;
    }
}

test "fuzz: a section an entry point accepts keeps the rules it checks, and no input reaches an assertion" {
    try std.testing.fuzz({}, fuzz_message, .{
        .corpus = &.{
            // :method GET, :scheme https, :authority, :path /, x-test, content-length 4.
            core.fuzz.input("\x00\x03\x05\x06\x0c\x12"),
            // :method CONNECT, :authority.
            core.fuzz.input("\x01\x05"),
            // :status 200, x-test, content-length 4 twice.
            core.fuzz.input("\x08\x0c\x12\x12"),
            // x-test, te trailers, :path.
            core.fuzz.input("\x0c\x0f\x06"),
            // :method OPTIONS, :scheme https, :path *.
            core.fuzz.input("\x15\x03\x16"),
            // :method GET, :scheme https, then :path with the raw value /a?b.
            core.fuzz.input("\x00\x03\x86/a?b"),
            // :status 200, then content-length with the raw value 18446744073709551616.
            core.fuzz.input("\x08\x92" ++ "18446744073709551616"),
            // :method CONNECT, then :authority with the raw value [::1]:443.
            core.fuzz.input("\x01\x85[::1]:443"),
            // :status 200, then a raw name X-Y with the value ok.
            core.fuzz.input("\x08\xccX-Y"),
        },
    });
}

test "sweep: every section of up to two octets keeps the rules its entry point checks" {
    try core.fuzz.sweep(fuzz_message, null);
}
