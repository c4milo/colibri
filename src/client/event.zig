//! What a client connection takes and reports, the same for h11 and h2 (decision 100): a request
//! and a response the caller places in its own memory (decision 124), and the events each
//! connection's `receive` returns to the pool. A request and its response are one exchange.
//!
//! The caller keeps the request and the response in place, and every slice they name, from
//! `request` until the exchange's `finished` event, or until `cancel` returns. The client reads
//! the request and writes the response, and the caller reads the response once the event arrives.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const headers_module = @import("headers.zig");

/// One header: a field line's name and value (RFC 9110 §5.2).
pub const Header = http.Field;

/// A request's id. A pool numbers its requests from 1, in the order `request` took them.
pub const RequestId = u64;

/// The protocol serving a connection: h11 or h2 over TCP, or h3 over QUIC.
pub const Protocol = enum { h11, h2, h3 };

/// How an exchange ended.
pub const Result = enum {
    /// It has not ended.
    pending,
    /// The final response arrived whole: `status`, `body[0..body_len]` and each wanted value.
    response,
    /// The server processed none of the request, so it may be sent again on another connection:
    /// a GOAWAY left its stream unprocessed or came before it opened (RFC 9113 §6.8), the server
    /// refused its stream (§8.7), or h11's connection closed before the request was written.
    refused,
    /// The server reset the stream (RFC 9113 §6.4). `error_code` names why.
    reset,
    /// The connection ended before the response was whole: it failed, or it closed with the
    /// request written and unanswered, which the server may have processed (RFC 9112 §9.3.1).
    /// The pool first sends an idempotent request again once, when its connection closed before
    /// any of the response arrived (RFC 9110 §9.2.2). A request sent again that is then refused,
    /// or that no connection takes, ends `closed` too: the first server may have processed it.
    closed,
    /// colibri refused the response: the protocol's rules make it malformed (RFC 9113 §8.1.1,
    /// RFC 9112 §8), or the content coding the client removes is corrupt or ends early (decision
    /// 101).
    malformed,
    /// The request is one the protocol refuses to send, such as a method that is not a token or
    /// a field line RFC 9110 §5.5 forbids.
    invalid,
    /// The response's body did not fit `body`, or its headers or trailers did not fit their buffer. A
    /// Content-Length larger than `body` ends the exchange at its head, and over h11 the
    /// connection with it (decision 124 as amended for
    /// https://github.com/c4milo/colibri/issues/106).
    too_large,
};

/// A request the program sends, in its own memory (decision 124). The client only reads it.
pub const Request = struct {
    /// The request method (RFC 9110 §9).
    method: []const u8,
    /// The target's path and query in origin form (RFC 9112 §3.2.1), which h2 sends as `:path`
    /// (RFC 9113 §8.3.1).
    path: []const u8,
    /// The request's own headers. The client adds Host in h11 and Content-Length, so these name
    /// neither, nor anything that frames the message (RFC 9110 §6.1).
    headers: []const Header = &.{},
    /// The path and the headers no intermediary may add to a compression table, such as a
    /// credential: never-indexed literals in h2 (RFC 7541 §6.2.3, §7.1.3) and h3 (RFC 9204
    /// §4.5.4). h11 compresses nothing, and writes them as it writes any other.
    never_indexed: NeverIndexed = .{},
    /// The request's body, sent whole. Empty for none, and for a body that goes in pieces.
    body: []const u8 = "",
    /// Which body goes in pieces (decision 153 ruling 7).
    streamed: Streamed = .{},
    /// The request's trailer section (RFC 9110 §6.5), sent after the whole body, after the last
    /// piece of a streamed one (decision 152). Empty for none. Over h11 such a request goes
    /// chunked (RFC 9112 §7.1.2), and over h2 and h3 the section ends the stream (RFC 9113 §8.1,
    /// RFC 9114 §4.1). The client names each field in a Trailer header field (RFC 9110 §6.6.2),
    /// and `request` refuses a field RFC 9110 §6.5.1 forbids here with `InvalidTrailer`.
    trailers: []const Header = &.{},
};

/// Whether a piece that `ConnectionPool.write_body` hands is the last of the request body
/// (decision 158 ruling 9).
pub const PieceEnd = enum { more, last };

/// Which body of an exchange goes in pieces (decision 153 ruling 3). A streamed request body goes
/// out through `ConnectionPool.write_body`, one piece at a time, and `Request.body` is empty. A
/// streamed response body comes into `Response.body` one piece at a time, each reported by a
/// `body` event and given back with `ConnectionPool.release_body`.
pub const Streamed = struct {
    /// The request body goes in pieces.
    request: bool = false,
    /// The response body comes in pieces. `Response.body` holds one piece at a time, so it is not
    /// empty. The client offers no content coding for such a response (decision 101), and passes
    /// its body on as it came.
    response: bool = false,
    /// The length of the whole request body, which the request then states (RFC 9110 §8.6), or
    /// null for none. With none, h11 sends the body chunked (RFC 9112 §7.1), and h2 and h3 end it
    /// with the stream (RFC 9113 §8.1, RFC 9114 §4.1). The pieces add up to the length stated.
    request_len: ?u64 = null,
};

/// Where the response to a request goes, and what arrived, in the program's memory (decision
/// 123). The client writes it from `request` until the exchange's `finished` event.
pub const Response = struct {
    /// The response's header section, copied into a buffer the program gives (decision 152).
    /// Each field line takes its name, its value and four octets. An empty buffer drops it.
    headers: headers_module.Headers = .{},
    /// The response's trailer section (RFC 9110 §6.5), kept apart from its headers (§6.5.1), in
    /// the same way. With a buffer, the request says it accepts trailers with `te: trailers`
    /// (RFC 9110 §10.1.4), unless its own headers name TE (decision 152).
    trailers: headers_module.Trailers = .{},
    /// Where the response's body is copied.
    body: []u8 = &.{},

    /// How the exchange ended, set once it has.
    result: Result = .pending,
    /// The final response's status code (RFC 9110 §15). The client sets it at the final head, so
    /// it also holds the status when the outcome is `too_large`. Before the final head it holds no
    /// status code, so a program reads `result` to know whether a final status arrived (decision
    /// 158 ruling 5).
    status: http.Status = undefined,
    /// Interim responses read before the final one (RFC 9110 §15.2).
    interims: u32 = 0,
    /// Bytes of `body` the response body filled. For a streamed response, the bytes of the piece
    /// `body` holds, from its `body` event until `release_body`, and 0 otherwise.
    body_len: usize = 0,
    /// Bytes of the request's `body` written, or of its pieces for a streamed request. Fewer than
    /// all when the response ended first (RFC 9113 §8.1, RFC 9112 §9.5) or the exchange ended
    /// another way.
    body_sent: usize = 0,
    /// The code of the RST_STREAM that reset the stream (RFC 9113 §7), for `reset`.
    error_code: u32 = 0,
    /// The content coding the client removed from the response's content (decision 101), or null
    /// when the content arrived uncoded or in a coding the client passes on as it came.
    coding: ?http.content_coding.Coding = null,

    /// The response's body, once the outcome is `response`.
    pub fn body_received(response: *const Response) []const u8 {
        assert(response.result == .response);
        return response.body[0..response.body_len];
    }
};

/// Which parts of a request go out as never-indexed literals.
pub const NeverIndexed = struct {
    /// The path, which carries the query, as a DoH GET's does (RFC 8484 §4.1).
    path: bool = false,
    /// The headers that go out never-indexed, after `Request.headers`, as std's
    /// `privileged_headers` do (decision 158 ruling 9). Empty for none.
    headers: []const Header = &.{},
};

/// An exchange that ended: its id, the request, and the response, whose outcome says how. The
/// program may reuse the memory of both.
pub const Finished = struct {
    id: RequestId,
    request: *const Request,
    response: *Response,
};

/// An exchange a connection ended, as it reports it to its pool: what `Finished` holds, and
/// whether any of the response arrived before the end. The pool reads `response_began` to decide
/// whether it sends the request again (decision 124), and a program never sees it.
pub const Ended = struct {
    id: RequestId,
    request: *const Request,
    response: *Response,
    /// Some of the response arrived: an octet of it over h11, or the header of a HEADERS frame on
    /// its stream over h2 and h3.
    response_began: bool,
};

/// A piece of a streamed response that `Response.body` holds (decision 153 ruling 7): the
/// exchange's id, and the bytes of the piece, `body[0..len]`.
pub const Piece = struct {
    id: RequestId,
    len: usize,
};

pub const Event = union(enum) {
    /// The connection speaks `Protocol`: over TLS once the handshake completes, as ALPN selected
    /// (RFC 7301 §3.2), and in cleartext from the start. Reported once, before any `finished`.
    connected: Protocol,
    /// The server issued a resumption ticket (RFC 9846 §4.7.1), which `take_ticket` hands over.
    ticket,
    /// The connection reads the exchange's request piece no more, and the caller may reuse its
    /// memory (decision 153 ruling 3).
    body_taken: RequestId,
    /// A streamed response's final status and header section arrived in the exchange's `Response`
    /// (decision 153 ruling 7).
    headers: RequestId,
    /// `Response.body` holds a piece of a streamed response, which the caller gives back with
    /// `release_body`. The connection reads no more of the response until then.
    body: Piece,
    /// An exchange ended. Its slot is free, and the caller may reuse its memory.
    finished: Ended,
    /// The connection takes no new request: the server sent a GOAWAY (RFC 9113 §6.8) or said it
    /// closes (RFC 9112 §9.6), the stream identifiers ran out (RFC 9113 §5.1.1), or the caller
    /// shut it down. The exchanges it holds go on.
    draining,
    /// The connection is over, and every exchange it held has finished. The caller closes the
    /// transport once `should_close` says so.
    closed,
};

/// What one `receive` call took and reported.
pub const ReceiveResult = struct {
    /// Octets of the caller's input taken.
    consumed: usize,
    event: ?Event,
};

test "decision 115: a Request has no call, and a Response has one, body_received" {
    // CLAUDE.md: a struct's `pub fn`s are a program's calls. What the client's own files call on
    // the two lives in `event_internal.zig`, which the root does not export.
    const public_names = @import("core").public_names;
    try public_names.expect(Request, &.{});
    try public_names.expect(Response, &.{"body_received"});
}
