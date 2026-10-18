//! What a client connection takes and reports, the same for h11 and h2 (decision 100): a request
//! and a response the caller places in its own memory (decision 124), and the events each
//! connection's `receive` returns to the channel. A request and its response are one exchange.
//!
//! The caller keeps the request and the response in place, and every slice they name, from
//! `request` until the exchange's `finished` event, or until `cancel` returns. The client reads
//! the request and writes the response, and the caller reads the response once the event arrives.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");

pub const Field = http.Field;

/// An exchange's id on its connection, counting from 1 in the order `request` took them.
pub const Id = u64;

/// The protocol serving a connection: h11 or h2 over TCP, or h3 over QUIC.
pub const Protocol = enum { h11, h2, h3 };

/// A response field the caller reads: it names the field, and the client sets the value.
pub const Wanted = struct {
    /// Compared case-insensitively (RFC 9110 §5.1).
    name: []const u8,
    /// The value of every field line of the response's header section with this name, joined by
    /// ", " (RFC 9110 §5.3), in the response's `values`. Null when the section has none.
    value: ?[]const u8 = null,
};

/// How an exchange ended.
pub const Outcome = enum {
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
    /// The channel first sends an idempotent request again once, when its connection closed before
    /// any of the response arrived (RFC 9110 §9.2.2). A request sent again that is then refused,
    /// or that no connection takes, ends `closed` too, since the first server may have processed it.
    closed,
    /// colibri refused the response: the protocol's rules make it malformed (RFC 9113 §8.1.1,
    /// RFC 9112 §8), or the content coding the client removes is corrupt or ends early (decision
    /// 101).
    malformed,
    /// The request is one the protocol refuses to send, such as a method that is not a token or
    /// a field line RFC 9110 §5.5 forbids.
    invalid,
    /// The response's content did not fit `body`, or a wanted value did not fit `values`.
    too_large,
};

/// A request the program sends, in its own memory (decision 124). The client only reads it.
pub const Request = struct {
    /// The request method (RFC 9110 §9).
    method: []const u8,
    /// The target's path and query in origin form (RFC 9112 §3.2.1), which h2 sends as `:path`
    /// (RFC 9113 §8.3.1).
    path: []const u8,
    /// The request's own field lines. The client adds Host in h11 and Content-Length, so these
    /// name neither, nor anything that frames the message (RFC 9110 §6.1).
    fields: []const Field = &.{},
    /// The path and the field lines no intermediary may add to a compression table, such as a
    /// credential: never-indexed literals in h2 (RFC 7541 §6.2.3, §7.1.3). h11 compresses nothing,
    /// and writes them as it writes any other.
    never_indexed: NeverIndexed = .{},
    /// The request's content, sent whole. Empty for none.
    content: []const u8 = "",

    /// The Content-Length value of the request, written into `digits`, or null when it sends none.
    /// RFC 9110 §8.6: a user agent sends one when the request has content, or when its method gives
    /// content a meaning, as POST's and PUT's do (RFC 9110 §9.3.3, §9.3.4).
    pub fn content_length(request: *const Request, digits: []u8) ?[]const u8 {
        const method = http.method.standard(request.method);
        const defines_content = method == .post or method == .put;
        if (request.content.len == 0 and !defines_content) return null;
        return std.fmt.bufPrint(digits, "{d}", .{request.content.len}) catch unreachable;
    }
};

/// Where the response to a request goes, and what arrived, in the program's memory (decision
/// 123). The client writes it from `request` until the exchange's `finished` event.
pub const Response = struct {
    /// The response fields the caller reads, and the octets their values are copied into.
    wanted: []Wanted = &.{},
    values: []u8 = &.{},
    /// Where the response's content is copied.
    body: []u8 = &.{},

    /// How the exchange ended, set once it has.
    outcome: Outcome = .pending,
    /// The final response's status code (RFC 9110 §15). The client sets it at the final head, so
    /// it also holds the status when the outcome is `too_large`.
    status: u16 = 0,
    /// Interim responses read before the final one (RFC 9110 §15.2).
    interims: u32 = 0,
    /// Octets of `body` the content filled.
    body_len: usize = 0,
    /// Octets of `values` the wanted values filled.
    values_len: usize = 0,
    /// Octets of the request's `content` written. Fewer than all when the response ended first
    /// (RFC 9113 §8.1, RFC 9112 §9.5) or the exchange ended another way.
    content_sent: usize = 0,
    /// The code of the RST_STREAM that reset the stream (RFC 9113 §7), for `reset`.
    error_code: u32 = 0,
    /// The content coding the client removed from the response's content (decision 101), or null
    /// when the content arrived uncoded or in a coding the client passes on as it came.
    coding: ?http.content_coding.Coding = null,

    /// Clears what the client writes, so the program may pass the response to `request` again.
    pub fn clear(response: *Response) void {
        response.outcome = .pending;
        response.status = 0;
        response.interims = 0;
        response.body_len = 0;
        response.values_len = 0;
        response.content_sent = 0;
        response.error_code = 0;
        response.coding = null;
        for (response.wanted) |*wanted| wanted.value = null;
        assert(response.outcome == .pending and response.body_len == 0);
    }

    /// The response's content, once the outcome is `response`.
    pub fn content_received(response: *const Response) []const u8 {
        assert(response.outcome == .response);
        return response.body[0..response.body_len];
    }
};

/// Which parts of a request go out as never-indexed literals.
pub const NeverIndexed = struct {
    /// The path, which carries the query, as a DoH GET's does (RFC 8484 §4.1).
    path: bool = false,
    /// One flag for each of the request's field lines, in order, or empty for none.
    fields: []const bool = &.{},
};

/// An exchange that ended: its id, the request, and the response, whose outcome says how. The
/// program may reuse the memory of both.
pub const Finished = struct {
    id: Id,
    request: *const Request,
    response: *Response,
};

/// An exchange a connection ended, as it reports it to its channel: what `Finished` holds, and
/// whether any of the response arrived before the end. The channel reads `response_began` to decide
/// whether it sends the request again (decision 124), and a program never sees it.
pub const Ended = struct {
    id: Id,
    request: *const Request,
    response: *Response,
    /// Some of the response arrived: an octet of it over h11, or a HEADERS frame on its stream
    /// over h2 and h3.
    response_began: bool,
};

pub const Event = union(enum) {
    /// The connection speaks `Protocol`: over TLS once the handshake completes, as ALPN selected
    /// (RFC 7301 §3.2), and in cleartext from the start. Reported once, before any `finished`.
    connected: Protocol,
    /// The server issued a resumption ticket (RFC 9846 §4.7.1), which `take_ticket` hands over.
    ticket,
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
pub const Received = struct {
    /// Octets of the caller's input taken.
    consumed: usize,
    event: ?Event,
};

test "clearing a response makes it pending again, and keeps where the response goes" {
    var wanted = [_]Wanted{.{ .name = "content-type", .value = "text/plain" }};
    var response: Response = .{ .wanted = &wanted };
    response.outcome = .response;
    response.status = 200;
    response.body_len = 3;
    response.coding = .gzip;
    response.clear();
    try std.testing.expectEqual(.pending, response.outcome);
    try std.testing.expectEqual(0, response.body_len);
    try std.testing.expectEqual(null, response.coding);
    try std.testing.expectEqual(null, response.wanted[0].value);
    try std.testing.expectEqualStrings("content-type", response.wanted[0].name);
}
