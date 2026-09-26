//! The h11 cases of the golden corpus (design §8 step 15a): whole HTTP/1.1 messages, and the
//! verdict h11 must return for each. A case's head is read by `h11.message`, and its body framed
//! by the length RFC 9112 §6.3 gives it, through `h11.chunked` when the body is chunked. A case is
//! accepted when every octet belongs to the message, and refused with the error h11 returns.
//!
//! The refusals are the shapes RFC 9112 §11.2 traces request smuggling to, one case each:
//! Content-Length with Transfer-Encoding, chunked hidden or repeated, whitespace before a colon,
//! obs-fold, a lone LF, a bare CR, and a chunk size that overflows.
//!
//! A server case (design §8 step 15b) is a stream of requests read by an h11 server connection,
//! which answers each with a 204 once it is read whole. Its verdict is the error response the
//! connection owes, named for its status (decision 92), or `Truncated` when the stream ends inside
//! a request. A 414 and a 431 need a head longer than `case_len_max`, so the connection's tests
//! hold those two.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const h11 = @import("h11");
const cases = @import("corpus_cases.zig");

const Case = cases.Case;
const Length = h11.message.Length;
const Code = http.status.Code;

pub const Error = h11.message.Error || h11.chunked.Error || ServerError || error{
    /// The message ended before its head, or before the body its length names.
    Truncated,
    /// Octets follow the message's end.
    TrailingOctets,
};

/// The error response a server case's connection owes, named for its status (decision 92).
pub const ServerError = error{
    /// 400 (RFC 9110 §15.5.1).
    BadRequest,
    /// 414 (RFC 9110 §15.5.15).
    UriTooLong,
    /// 431 (RFC 6585 §5).
    RequestHeaderFieldsTooLarge,
    /// 501 (RFC 9110 §15.6.2).
    NotImplemented,
    /// 505 (RFC 9110 §15.6.6).
    HttpVersionNotSupported,
};

fn accept(name: []const u8, octets: []const u8) Case {
    return .{ .name = name, .construction = .{ .literal = octets } };
}

fn reject(name: []const u8, octets: []const u8, rejection: Error) Case {
    return .{ .name = name, .construction = .{ .literal = octets }, .rejection = rejection };
}

pub const request = [_]Case{
    accept("h11_request_get", "GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
    accept("h11_request_leading_empty_line", "\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"),
    accept("h11_request_length", "POST /p?q HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello"),
    accept("h11_request_chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5;e=\"v\"\r\nhello\r\n0\r\nChecksum: 1\r\n\r\n"),
    accept("h11_request_gzip_chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n"),
    accept("h11_request_absolute_form", "GET http://a.example/p HTTP/1.1\r\nHost: a.example\r\n\r\n"),
    accept("h11_request_connect", "CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n"),
    accept("h11_request_options_asterisk", "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n"),
    accept("h11_request_http10_no_host", "GET / HTTP/1.0\r\n\r\n"),
    // RFC 9112 §6.1 and §6.3 rule 3.
    reject("h11_request_length_and_chunked", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", error.TransferEncodingWithContentLength),
    // RFC 9112 §6.3 rule 4: chunked not final, or twice.
    reject("h11_request_chunked_then_gzip", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", error.ChunkedNotLast),
    reject("h11_request_gzip_alone", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n", error.ChunkedNotLast),
    reject("h11_request_chunked_twice", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", error.ChunkedNotLast),
    // RFC 9112 §5.1 and §5.2: chunked hidden behind whitespace before the colon, or folded.
    reject("h11_request_space_before_colon", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n", error.WhitespaceBeforeColon),
    reject("h11_request_obs_fold", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n chunked\r\n\r\n", error.ObsFold),
    reject("h11_request_quoted_chunked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \"chunked\"\r\n\r\n", error.TransferEncodingInvalid),
    // RFC 9112 §6.3 rule 4 before §6.1: a coding h11 does not know, with no chunked after it, is
    // unframeable first (decision 92 as amended).
    reject("h11_request_unknown_coding", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n", error.ChunkedNotLast),
    reject("h11_request_length_disagrees", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 6\r\n\r\nhello", error.ContentLengthInvalid),
    reject("h11_request_length_signed", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\nhello", error.ContentLengthInvalid),
    reject("h11_request_http10_chunked", "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", error.TransferEncodingInHttp10),
    // RFC 9112 §7.1: an overflowing size, and a lone LF inside the coding.
    reject("h11_request_chunk_size_overflow", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "10000000000000000\r\n", error.ChunkSizeTooLarge),
    reject("h11_request_chunk_lone_lf", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n", error.BareLineFeed),
    reject("h11_request_chunk_data_long", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabc\r\n0\r\n\r\n", error.ChunkDataEndInvalid),
    // RFC 9112 §2.2: a bare CR and a lone LF in the head.
    reject("h11_request_bare_cr", "GET / HTTP/1.1\r\nHost: a\rX: b\r\n\r\n", error.BareCarriageReturn),
    reject("h11_request_lone_lf", "GET / HTTP/1.1\nHost: a\n\n", error.BareLineFeed),
    // RFC 9112 §3.2: Host.
    reject("h11_request_no_host", "GET / HTTP/1.1\r\n\r\n", error.HostMissing),
    reject("h11_request_host_twice", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", error.HostRepeated),
    reject("h11_request_host_userinfo", "GET / HTTP/1.1\r\nHost: u@a\r\n\r\n", error.HostInvalid),
    // RFC 9112 §2.3 and §3.
    reject("h11_request_version_lowercase", "GET / http/1.1\r\nHost: a\r\n\r\n", error.VersionInvalid),
    reject("h11_request_two_spaces", "GET  / HTTP/1.1\r\nHost: a\r\n\r\n", error.TargetInvalid),
    // The message ends before its body, or octets follow it.
    reject("h11_request_body_short", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhell", error.Truncated),
    reject("h11_request_trailing_octets", "GET / HTTP/1.1\r\nHost: a\r\n\r\nG", error.TrailingOctets),
};

pub const response = [_]Case{
    accept("h11_response_length", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
    accept("h11_response_no_content", "HTTP/1.1 204 \r\n\r\n"),
    accept("h11_response_not_modified_length", "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n"),
    accept("h11_response_chunked_trailer", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX: y\r\n\r\n"),
    accept("h11_response_until_close", "HTTP/1.0 200 OK\r\n\r\neverything until the close"),
    accept("h11_response_obs_fold_joined", "HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n"),
    reject("h11_response_length_and_chunked", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n", error.TransferEncodingWithContentLength),
    reject("h11_response_http10_chunked", "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", error.TransferEncodingInHttp10),
    reject("h11_response_status_short", "HTTP/1.1 20 OK\r\n\r\n", error.StatusInvalid),
    reject("h11_response_no_space_after_status", "HTTP/1.1 200\r\n\r\n", error.StartLineInvalid),
    reject("h11_response_lone_lf", "HTTP/1.1 200 OK\n\n", error.BareLineFeed),
    reject("h11_response_leading_empty_line", "\r\nHTTP/1.1 200 OK\r\n\r\n", error.StartLineEmpty),
};

pub const server = [_]Case{
    accept("h11_server_pipelined", "GET /a HTTP/1.1\r\nHost: a\r\n\r\nPOST /b HTTP/1.1\r\nHost: a\r\n" ++
        "Content-Length: 2\r\n\r\nhiGET /c HTTP/1.1\r\nHost: a\r\n\r\n"),
    accept("h11_server_chunked_then_get", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "2\r\nhi\r\n0\r\nT: v\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"),
    // RFC 9112 §2.2: an empty line before a request line is skipped.
    accept("h11_server_empty_line_between", "GET / HTTP/1.1\r\nHost: a\r\n\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"),
    // RFC 9112 §9.6: nothing after a request with the close option is read, here a request
    // without Host.
    accept("h11_server_close_stops_reading", "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n" ++
        "GET / HTTP/1.1\r\n\r\n"),
    // Decision 92: colibri honours no HTTP/1.0 keep-alive, so an HTTP/1.0 request is the last.
    accept("h11_server_http10_stops_reading", "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.1\r\n\r\n"),
    // RFC 9112 §3.2: the second request lacks Host, after the first is answered.
    reject("h11_server_second_without_host", "GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\n\r\n", error.BadRequest),
    // RFC 9112 §6.1: Content-Length with Transfer-Encoding.
    reject("h11_server_length_and_chunked", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", error.BadRequest),
    // RFC 9112 §5.2: a server refuses obs-fold.
    reject("h11_server_obs_fold", "GET / HTTP/1.1\r\nHost: a\r\nX: b\r\n c\r\n\r\n", error.BadRequest),
    // RFC 9112 §7.1: a chunk size that is not hexadecimal, inside the body.
    reject("h11_server_chunk_size_invalid", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", error.BadRequest),
    // RFC 9112 §6.1: a transfer coding the server does not implement, and two stacked.
    reject("h11_server_coding_unknown", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: br, chunked\r\n\r\n", error.NotImplemented),
    reject("h11_server_codings_stacked", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, deflate, chunked\r\n\r\n", error.NotImplemented),
    // RFC 9110 §15.6.6: a major version the server does not support.
    reject("h11_server_version_two", "GET / HTTP/2.0\r\nHost: a\r\n\r\n", error.HttpVersionNotSupported),
    // RFC 9112 §8: the stream ends inside a body, and inside a head.
    reject("h11_server_body_short", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhel", error.Truncated),
    .{
        .name = "h11_server_head_short",
        .construction = .{ .truncated = .{ .case_name = "h11_server_pipelined", .drop = line_end.len } },
        .rejection = error.Truncated,
    },
};

/// The empty line that ends a head (RFC 9112 §2.1), which the truncated case drops.
const line_end = "\r\n";

/// The storage a case decodes in, placed outside any stack frame and reset per case.
var section: http.FieldSection = undefined;
var trailers: http.FieldSection = undefined;
var connection: h11.connection.Connection = undefined;
var response_octets: [response_len_max]u8 = undefined;

/// The octets of the 204 a server case answers each request with, at most.
const response_len_max = 64;

/// Passes of the server's read loop per octet: one that consumes it, and one that ends a request.
const passes_per_octet = 2;

/// 431 Request Header Fields Too Large (RFC 6585 §5), which RFC 9110 §15 does not define.
const status_fields_too_large: u16 = 431;

/// A server case: requests read in order and each answered once it is read whole, until the
/// stream ends, the connection closes, or it refuses a request.
pub fn decode_server(octets: []const u8) Error!void {
    connection.init(.server, .{});
    var reader = core.reader.Reader.init(octets);
    serve(&reader) catch |failure| switch (failure) {
        error.ConnectionFailed => return refusal(connection.reply_status orelse unreachable),
    };
    // RFC 9112 §8: a stream that ends inside a request leaves it incomplete.
    if (connection.transport_closed().incomplete) return error.Truncated;
}

fn serve(reader: *core.reader.Reader) h11.connection.Error!void {
    // Every pass consumes an octet or ends a request, and a request takes at least one octet, so
    // n octets take at most 2n passes, and one more finds them short.
    for (0..passes_per_octet * reader.remaining_len() + 1) |_| {
        const received = try connection.receive(reader.peek_rest());
        _ = reader.take(received.consumed) catch unreachable;
        const event = received.event orelse return;
        // The request is read whole once the server waits, and its `end` is not still owed.
        if (connection.phase == .waiting and event != .data) {
            _ = connection.write_response(&response_octets, @intFromEnum(Code.no_content), "", &.{}) catch unreachable;
        }
    }
    unreachable;
}

/// The verdict naming the error response `status` (decision 92).
fn refusal(status: u16) ServerError {
    return switch (status) {
        @intFromEnum(Code.bad_request) => error.BadRequest,
        @intFromEnum(Code.uri_too_long) => error.UriTooLong,
        status_fields_too_large => error.RequestHeaderFieldsTooLarge,
        @intFromEnum(Code.not_implemented) => error.NotImplemented,
        @intFromEnum(Code.http_version_not_supported) => error.HttpVersionNotSupported,
        else => unreachable,
    };
}

/// A request case: its head, then the body its length names.
pub fn decode_request(octets: []const u8) Error!void {
    var scanner: h11.message.Scanner = .{};
    const head = try h11.message.read_request(&scanner, octets, &section) orelse return error.Truncated;
    assert(head.head_len <= octets.len);
    try consume_body(.request, head.body.length, octets[head.head_len..]);
}

/// A response case, answering a request that asked nothing special (RFC 9112 §6.3).
pub fn decode_response(octets: []const u8) Error!void {
    var scanner: h11.message.Scanner = .{};
    const head = try h11.message.read_response(&scanner, .other, octets, &section) orelse return error.Truncated;
    assert(head.head_len <= octets.len);
    try consume_body(.response, head.body.length, octets[head.head_len..]);
}

/// Requires `body` to be exactly the body `length` names.
fn consume_body(role: h11.message.Role, length: Length, body: []const u8) Error!void {
    switch (length) {
        .none, .tunnel => if (body.len > 0) return error.TrailingOctets,
        .close_delimited => {},
        .fixed => |octets| {
            if (body.len < octets) return error.Truncated;
            if (body.len > octets) return error.TrailingOctets;
        },
        .chunked => try consume_chunked(role, body),
    }
}

fn consume_chunked(role: h11.message.Role, body: []const u8) Error!void {
    var decoder: h11.chunked.Decoder = .{};
    var reader = core.reader.Reader.init(body);
    // Bounded: each call consumes an octet at least, or the coding stops.
    for (0..body.len + 1) |_| {
        const decoded = try decoder.decode(role, reader.peek_rest(), &trailers);
        _ = reader.take(decoded.consumed) catch unreachable;
        if (decoded.done) {
            if (reader.remaining_len() > 0) return error.TrailingOctets;
            return;
        }
        if (decoded.consumed == 0) return error.Truncated;
    }
    unreachable;
}
