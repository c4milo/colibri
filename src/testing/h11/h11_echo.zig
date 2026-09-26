//! The echo of the test-only server's `--echo` mode (design §8 step 15d): each request the h11
//! session reads, returned as the content of its 200 response, in the JSON the HTTP Garden reads
//! from its origin servers (decision 88). The Garden compares what several servers say they read
//! from one request, so the echo is what h11 parsed and nothing the session chose.
//!
//! The JSON is one object: the method, the target, the version, the field lines in arrival order
//! and the content, each value base64-encoded as the Garden decodes it:
//!
//!     {"method":"R0VU","uri":"Lw==","version":"SFRUUC8xLjE=","headers":[["SG9zdA==","YQ=="]],"body":""}
//!
//! `begin` writes everything up to the content when the head arrives, because the head's octets
//! and its field section are valid only until the connection reads again. `add` keeps the content
//! as it arrives, and `finish` writes it once the request has ended.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const constants = @import("../constants.zig");

const Encoder = std.base64.standard.Encoder;

comptime {
    // The digits hold the longest echo the server's `--echo` mode answers with, whose length it
    // writes as the Content-Length (RFC 9110 §8.6).
    assert(std.math.pow(u64, constants.port_radix, constants.content_length_digits_max) > constants.echo_json_len_max);
    assert(constants.echo_json_len_max > constants.echo_body_len_max);
}

pub const Echo = struct {
    json: [constants.echo_json_len_max]u8,
    json_len: usize,
    body: [constants.echo_body_len_max]u8,
    body_len: usize,
    /// The content was longer than `echo_body_len_max`, which the session answers with 413.
    body_too_long: bool,

    /// Writes the request's head: every key but the content's, and the content's key.
    pub fn begin(echo: *Echo, line: h11.message.RequestLine, section: *const h11.http.FieldSection) void {
        echo.json_len = 0;
        echo.body_len = 0;
        echo.body_too_long = false;
        // RFC 9112 §2.3: the minor version is one DIGIT, which h11's parser read.
        var version: [version_len]u8 = "HTTP/1.1".*;
        version[version_len - 1] = std.fmt.digitToChar(line.version.minor, .lower);
        assert(line.version.major == 1 and std.ascii.isDigit(version[version_len - 1]));
        echo.put("{\"method\":\"");
        echo.put_base64(line.method);
        echo.put("\",\"uri\":\"");
        echo.put_base64(line.target);
        echo.put("\",\"version\":\"");
        echo.put_base64(&version);
        echo.put("\",\"headers\":[");
        for (0..section.len()) |index| {
            const field = section.get(@intCast(index));
            if (index > 0) echo.put(",");
            echo.put("[\"");
            echo.put_base64(field.name);
            echo.put("\",\"");
            echo.put_base64(field.value);
            echo.put("\"]");
        }
        echo.put("],\"body\":\"");
    }

    /// Keeps content octets as they arrive, or notes that there are too many to keep.
    pub fn add(echo: *Echo, data: []const u8) void {
        if (data.len > echo.body.len - echo.body_len) {
            echo.body_too_long = true;
            return;
        }
        @memcpy(echo.body[echo.body_len..][0..data.len], data);
        echo.body_len += data.len;
    }

    /// Writes the content and closes the object, once the request has ended.
    pub fn finish(echo: *Echo) void {
        echo.put_base64(echo.body[0..echo.body_len]);
        echo.put("\"}");
    }

    /// The JSON written so far.
    pub fn written(echo: *const Echo) []const u8 {
        return echo.json[0..echo.json_len];
    }

    fn put(echo: *Echo, octets: []const u8) void {
        // `echo_json_len_max` holds what any request h11 accepts can produce (`constants.zig`).
        assert(octets.len <= echo.json.len - echo.json_len);
        @memcpy(echo.json[echo.json_len..][0..octets.len], octets);
        echo.json_len += octets.len;
    }

    fn put_base64(echo: *Echo, octets: []const u8) void {
        const len = Encoder.calcSize(octets.len);
        assert(len <= echo.json.len - echo.json_len);
        _ = Encoder.encode(echo.json[echo.json_len..][0..len], octets);
        echo.json_len += len;
    }
};

/// Octets of "HTTP/1.1", the version as the request line spells it (RFC 9112 §2.3).
const version_len = "HTTP/1.1".len;

const testing = std.testing;

/// An echo and a section the tests fill, outside any stack frame. Test-only.
var test_echo: Echo = undefined;
var test_section: h11.http.FieldSection = undefined;

test "a request is echoed as the Garden's JSON, every value base64-encoded" {
    test_section.init();
    try test_section.append("Host", "a");
    try test_section.append("Transfer-Encoding", "chunked");
    test_echo.begin(.{ .method = "POST", .target = "/p?q", .version = .{ .major = 1, .minor = 1 } }, &test_section);
    test_echo.add("he");
    test_echo.add("llo");
    test_echo.finish();
    try testing.expectEqualStrings("{\"method\":\"UE9TVA==\",\"uri\":\"L3A/cQ==\",\"version\":\"SFRUUC8xLjE=\"," ++
        "\"headers\":[[\"SG9zdA==\",\"YQ==\"],[\"VHJhbnNmZXItRW5jb2Rpbmc=\",\"Y2h1bmtlZA==\"]]," ++
        "\"body\":\"aGVsbG8=\"}", test_echo.written());
    try testing.expect(!test_echo.body_too_long);
}

test "an HTTP/1.0 request with no field lines, and content past the limit" {
    test_section.init();
    test_echo.begin(.{ .method = "GET", .target = "/", .version = .{ .major = 1, .minor = 0 } }, &test_section);
    test_echo.finish();
    try testing.expectEqualStrings("{\"method\":\"R0VU\",\"uri\":\"Lw==\",\"version\":\"SFRUUC8xLjA=\",\"headers\":[],\"body\":\"\"}", test_echo.written());
    test_echo.begin(.{ .method = "POST", .target = "/", .version = .{ .major = 1, .minor = 1 } }, &test_section);
    test_echo.add(&(@as([constants.echo_body_len_max]u8, @splat('x'))));
    try testing.expect(!test_echo.body_too_long);
    test_echo.add("y");
    try testing.expect(test_echo.body_too_long);
}
