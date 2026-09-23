//! hq-interop, the protocol the QUIC Interop Runner's transfer cases speak: HTTP/0.9 over QUIC.
//! Part of design §8 step 9e, piece 11.
//!
//! A client opens one bidirectional stream per file, writes one request line and ends its side of
//! the stream (RFC 9000 §3.1). The server answers on the same stream with the file's octets and
//! ends its side. There is no status and no field section: a missing file is a stream the server
//! resets. The runner sets the ALPN token "hq-interop" (RFC 9001 §8.1).
//!
//! The request line is `GET /path` and CRLF. This file reads it and writes it, and refuses a path
//! that could name a file outside the served directory.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../../constants.zig");

/// The ALPN token both endpoints offer.
pub const alpn = "hq-interop";

const method = "GET ";
const line_end = "\r\n";

pub const Error = error{
    /// The request is not `GET /path` and CRLF.
    RequestMalformed,
    /// The path could name a file outside the served directory.
    PathRefused,
    /// The request line is longer than `hq_request_len_max`.
    RequestTooLong,
};

/// Reads the path out of a whole request, which is what the client wrote before it ended its
/// side of the stream. The path keeps its leading slash.
pub fn read_request(request: []const u8) Error![]const u8 {
    if (request.len > constants.hq_request_len_max) return error.RequestTooLong;
    if (!std.mem.startsWith(u8, request, method)) return error.RequestMalformed;
    // HTTP/0.9 clients end the line with CRLF, and some with LF alone.
    const trimmed = std.mem.trimEnd(u8, request[method.len..], line_end);
    if (trimmed.len == 0 or trimmed[0] != '/') return error.RequestMalformed;
    try check_path(trimmed);
    return trimmed;
}

/// Refuses a path with an empty, a "." or a ".." segment, a backslash, or an octet that is not
/// visible ASCII, so joining it to the served directory names a file inside it.
fn check_path(path: []const u8) Error!void {
    assert(path.len > 0 and path[0] == '/');
    for (path) |octet| {
        if (!std.ascii.isGraphical(octet) or octet == '\\') return error.PathRefused;
    }
    var segments = std.mem.splitScalar(u8, path[1..], '/');
    // Bounded by the path, which `hq_request_len_max` bounds.
    while (segments.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return error.PathRefused;
    }
}

/// Writes `GET /path` and CRLF into `output` and returns it.
pub fn write_request(path: []const u8, output: []u8) Error![]const u8 {
    if (path.len == 0 or path[0] != '/') return error.RequestMalformed;
    try check_path(path);
    const len = method.len + path.len + line_end.len;
    if (len > output.len or len > constants.hq_request_len_max) return error.RequestTooLong;
    @memcpy(output[0..method.len], method);
    @memcpy(output[method.len..][0..path.len], path);
    @memcpy(output[method.len + path.len ..][0..line_end.len], line_end);
    return output[0..len];
}

const testing = std.testing;

test "hq-interop: a request line written is read back to the same path" {
    var buffer: [constants.hq_request_len_max]u8 = undefined;
    const request = try write_request("/files/one.bin", &buffer);
    try testing.expectEqualStrings("GET /files/one.bin\r\n", request);
    try testing.expectEqualStrings("/files/one.bin", try read_request(request));
    // Some clients end the line with LF alone.
    try testing.expectEqualStrings("/a", try read_request("GET /a\n"));
}

test "hq-interop: a request that is not GET /path is refused" {
    try testing.expectError(error.RequestMalformed, read_request("POST /a\r\n"));
    // A method as long as GET's, so only the method itself tells the two apart.
    try testing.expectError(error.RequestMalformed, read_request("PUT /a\r\n"));
    try testing.expectError(error.RequestMalformed, read_request("GET a\r\n"));
    try testing.expectError(error.RequestMalformed, read_request("GET \r\n"));
}

test "hq-interop: a path that could leave the served directory is refused" {
    try testing.expectError(error.PathRefused, read_request("GET /../secret\r\n"));
    try testing.expectError(error.PathRefused, read_request("GET /a/./b\r\n"));
    try testing.expectError(error.PathRefused, read_request("GET /a//b\r\n"));
    try testing.expectError(error.PathRefused, read_request("GET /a\\b\r\n"));
    try testing.expectError(error.PathRefused, read_request("GET /a b\r\n"));
    var buffer: [constants.hq_request_len_max]u8 = undefined;
    try testing.expectError(error.PathRefused, write_request("/../x", &buffer));
}

test "hq-interop: a request past the limit is refused" {
    var long: [constants.hq_request_len_max + 1]u8 = @splat('a');
    @memcpy(long[0..method.len], method);
    long[method.len] = '/';
    try testing.expectError(error.RequestTooLong, read_request(&long));
}
