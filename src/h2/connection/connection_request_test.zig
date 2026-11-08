//! Tests of `connection_request.zig`, split off that file for length.
//!
//! Most of them hold `validate_field_line` to the code it replaced. That code read a name twice:
//! once for uppercase letters, then through `http.field.validate_name`. It stays here as the
//! reference: `validate_field_line` must accept every line the reference accepts and refuse every
//! line it refuses.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const hpack = @import("hpack");
const constants = @import("../constants.zig");
const connection_request = @import("connection_request.zig");
const support = @import("connection_test_support.zig");

const Error = connection_request.Error;

/// The reference: `validate_field_line` as it was.
fn validate_field_line_by_two_passes(line: hpack.Field) Error!void {
    for (line.name) |octet| {
        // RFC 9113 §8.2.1: a field name containing an octet in the range 0x41 to 0x5a is malformed.
        if (octet >= 'A' and octet <= 'Z') return error.FieldLineInvalid;
    }
    // RFC 9113 §8.2.1: a field name that is not a token is malformed, so colibri sends none.
    http.field.validate_name(line.name) catch return error.FieldLineInvalid;
    // RFC 9113 §8.2.1: a value carrying NUL, CR or LF, or surrounded by whitespace, is malformed.
    http.field.validate_value(line.value) catch return error.FieldLineInvalid;
    // RFC 9113 §8.2.2: no connection-specific field line but TE.
    const kind = http.connection_specific.classify(line.name) orelse return;
    // RFC 9113 §8.2.2: TE is the one such name a request may carry.
    if (kind != .te) return error.FieldLineInvalid;
    // RFC 9113 §8.2.2: a TE field value MUST NOT contain any value other than "trailers".
    if (!http.connection_specific.te_is_trailers(line.value)) return error.FieldLineInvalid;
}

/// Fails, printing both verdicts, when `validate_field_line` and the reference differ on `name`.
fn expect_same_verdict(name: []const u8) !void {
    const line: hpack.Field = .{ .name = name, .value = "trailers" };
    const changed = if (connection_request.validate_field_line(line)) true else |_| false;
    const reference = if (validate_field_line_by_two_passes(line)) true else |_| false;
    if (changed == reference) return;
    std.debug.print("first difference: name {x}: validate_field_line accepts {}, reference {}\n", .{ name, changed, reference });
    return error.TestUnexpectedResult;
}

/// The octet values, 0 to 255.
const octet_values = std.math.maxInt(u8) + 1;
/// The longest name the tests vary one octet of.
const varied_len_max = 40;
const name_len_max = core.constants.limits.field_name_len_max;

test "validate_field_line gives every name of up to two octets the reference's verdict" {
    var name: [2]u8 = undefined;
    try expect_same_verdict(name[0..0]);
    for (0..octet_values) |first| {
        name[0] = @intCast(first);
        try expect_same_verdict(name[0..1]);
        for (0..octet_values) |second| {
            name[1] = @intCast(second);
            try expect_same_verdict(&name);
        }
    }
}

test "validate_field_line gives the reference's verdict with every octet at every position" {
    var name: [varied_len_max]u8 = @splat('a');
    for (1..name.len + 1) |len| {
        for (0..len) |position| {
            for (0..octet_values) |octet| {
                name[position] = @intCast(octet);
                try expect_same_verdict(name[0..len]);
            }
            name[position] = 'a';
        }
    }
}

test "validate_field_line gives the reference's verdict at the longest name and one octet past it" {
    var name: [name_len_max + 1]u8 = @splat('a');
    try expect_same_verdict(name[0..name_len_max]);
    try expect_same_verdict(&name);
    // The names RFC 9113 §8.2.2 makes connection-specific, and TE, which it lets through.
    for ([_][]const u8{ "connection", "keep-alive", "te", "upgrade", "transfer-encoding" }) |special| {
        try expect_same_verdict(special);
    }
}

test "validate_field_line gives the reference's verdict with every octet at every position of the longest name" {
    var name: [name_len_max]u8 = @splat('a');
    for (0..name.len) |position| {
        for (0..octet_values) |octet| {
            name[position] = @intCast(octet);
            try expect_same_verdict(&name);
        }
        name[position] = 'a';
    }
}

test "RFC 7541 §4.2: a table-size change is declared once and not repeated on the next request" {
    try support.start_client();
    const request: connection_request.Request = .{ .method = "GET", .scheme = "https", .path = "/", .authority = "example.com" };
    const output = &support.test_output;
    // RFC 9113 §6.5.2: SETTINGS_HEADER_TABLE_SIZE is the limit the peer sets on colibri's encoder.
    const settings = try support.frame_bytes(&support.test_input, constants.protocol.frame_type_settings, 0, 0, "\x00\x01\x00\x00\x00\x64");
    _ = try support.feed(settings);
    _ = try support.test_connection.write_request(output, &request, &.{}, &.{}, true);
    // RFC 7541 §4.2: the block opens with the size update the change owes.
    try std.testing.expectEqual(0x3f, output[constants.protocol.frame_header_len]);
    try std.testing.expectEqual(0x45, output[constants.protocol.frame_header_len + 1]);
    _ = try support.test_connection.write_request(output, &request, &.{}, &.{}, true);
    // The first block reached the peer, so the second owes nothing.
    try std.testing.expect(output[constants.protocol.frame_header_len] != 0x3f);
}
