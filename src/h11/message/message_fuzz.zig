//! The fuzz properties of h11's parsers, and the sweeps that run them over every input of up to
//! two octets (decision 29, design §8 step 15a). They show that no input reaches an assertion
//! (invariant 24), and that what a parser accepts keeps the rules it checks. The properties read
//! those rules again here, without the parsers' own helpers. Everything in this file is test-only.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const message = @import("message.zig");
const chunked = @import("../chunked/chunked.zig");

const Smith = std.testing.Smith;
const FieldSection = http.FieldSection;

/// Most octets one fuzz input carries: room for a start line, a few field lines and a body.
const fuzz_input_len_max = 96;

/// The empty line that ends a head (RFC 9112 §2.1).
const head_end = "\r\n\r\n";

/// The sections the properties fill, placed outside any stack frame.
var fuzz_section: FieldSection = undefined;
var fuzz_trailers: FieldSection = undefined;

/// Reads the input as a request head and as a response head, and checks what each accepts.
fn fuzz_head(_: void, smith: *Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const octets = input[0..smith.slice(&input)];
    var scanner: message.Scanner = .{};
    if (message.read_request(&scanner, octets, &fuzz_section)) |read| {
        if (read) |request| {
            try expect_head(octets, request.head_len);
            try std.testing.expect(request.line.method.len > 0);
            for (request.line.method) |octet| try std.testing.expect(http.field.is_tchar(octet));
        }
    } else |_| {}
    scanner = .{};
    if (message.read_response(&scanner, .other, octets, &fuzz_section)) |read| {
        if (read) |response| {
            try expect_head(octets, response.head_len);
            _ = try http.status.Status.from_code(response.line.status.code);
        }
    } else |_| {}
}

/// A head that was accepted: it ends with its empty line, and every field line is a token name and
/// a value with no CR, LF or NUL and no whitespace at either end.
fn expect_head(octets: []const u8, head_len: u32) !void {
    try std.testing.expect(head_len <= octets.len);
    try std.testing.expect(std.mem.endsWith(u8, octets[0..head_len], head_end));
    for (0..fuzz_section.len()) |index| {
        const line = fuzz_section.get(@intCast(index));
        try std.testing.expect(line.name.len > 0);
        for (line.name) |octet| try std.testing.expect(http.field.is_tchar(octet));
        for (line.value) |octet| try std.testing.expect(octet != '\r' and octet != '\n' and octet != 0);
        if (line.value.len > 0) {
            try std.testing.expect(line.value[0] != ' ' and line.value[0] != '\t');
            try std.testing.expect(line.value[line.value.len - 1] != ' ' and line.value[line.value.len - 1] != '\t');
        }
    }
}

/// Decodes the input as a chunked body, and checks that each call stays inside what it was given.
fn fuzz_chunked(_: void, smith: *Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const octets = input[0..smith.slice(&input)];
    var decoder: chunked.Decoder = .{};
    var offset: usize = 0;
    for (0..octets.len + 1) |_| {
        const decoded = decoder.decode(.request, octets[offset..], &fuzz_trailers) catch return;
        try std.testing.expect(decoded.consumed <= octets.len - offset);
        try std.testing.expect(decoded.data.len <= decoded.consumed);
        offset += decoded.consumed;
        if (decoded.done or decoded.consumed == 0) return;
    }
    return error.TestUnexpectedResult;
}

test "fuzz: no head reaches an assertion, and an accepted head keeps its rules" {
    try std.testing.fuzz({}, fuzz_head, .{
        .corpus = &.{
            core.fuzz.input("GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
            core.fuzz.input("POST /p HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"),
            core.fuzz.input("HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n"),
            core.fuzz.input("\r\nCONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"),
            core.fuzz.input("HTTP/1.0 204 \r\n\r\n"),
        },
    });
}

test "fuzz: no chunked body reaches an assertion, and every call stays inside its input" {
    try std.testing.fuzz({}, fuzz_chunked, .{
        .corpus = &.{
            core.fuzz.input("5;e=\"v\"\r\nhello\r\n0\r\nT: x\r\n\r\n"),
            core.fuzz.input("ffffffffffffffff\r\nab"),
            core.fuzz.input("0\r\n\r\n"),
        },
    });
}

test "sweep: no head or chunked body of up to two octets reaches an assertion" {
    try core.fuzz.sweep(fuzz_head, null);
    try core.fuzz.sweep(fuzz_chunked, null);
}
