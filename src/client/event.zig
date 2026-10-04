//! What a client connection takes and reports, the same for h11 and h2 (decision 100): an
//! exchange the caller places in its own memory, which holds the request and where its response
//! goes, and the events `Connection.receive` returns.
//!
//! The caller keeps an exchange in place, and every slice it names, from `request` until the
//! exchange's `finished` event, or until `cancel` returns. The client reads the request's part
//! and writes the response's part, and the caller reads that part once the event arrives.
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
    /// ", " (RFC 9110 §5.3), in the exchange's `values`. Null when the section has none.
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

/// One request and where its response goes, in the caller's memory.
pub const HttpExchange = struct {
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
    /// The response fields the caller reads, and the octets their values are copied into.
    wanted: []Wanted = &.{},
    values: []u8 = &.{},
    /// Where the response's content is copied.
    body: []u8 = &.{},

    /// How the exchange ended, set once it has.
    outcome: Outcome = .pending,
    /// The final response's status code (RFC 9110 §15).
    status: u16 = 0,
    /// Interim responses read before the final one (RFC 9110 §15.2).
    interims: u32 = 0,
    /// Octets of `body` the content filled.
    body_len: usize = 0,
    /// Octets of `values` the wanted values filled.
    values_len: usize = 0,
    /// Octets of `content` written. Fewer than all when the response ended first (RFC 9113 §8.1)
    /// or the exchange ended another way.
    content_sent: usize = 0,
    /// The code of the RST_STREAM that reset the stream (RFC 9113 §7), for `reset`.
    error_code: u32 = 0,
    /// The content coding the client removed from the response's content (decision 101), or null
    /// when the content arrived uncoded or in a coding the client passes on as it came.
    coding: ?http.content_coding.Coding = null,

    /// Clears what the client writes, so the exchange can be made again.
    pub fn clear(exchange: *HttpExchange) void {
        exchange.outcome = .pending;
        exchange.status = 0;
        exchange.interims = 0;
        exchange.body_len = 0;
        exchange.values_len = 0;
        exchange.content_sent = 0;
        exchange.error_code = 0;
        exchange.coding = null;
        for (exchange.wanted) |*wanted| wanted.value = null;
        assert(exchange.outcome == .pending and exchange.body_len == 0);
    }

    /// The Content-Length value of the request, written into `digits`, or null when it sends none.
    /// RFC 9110 §8.6: a user agent sends one when the request has content, or when its method gives
    /// content a meaning, as POST's and PUT's do (RFC 9110 §9.3.3, §9.3.4).
    pub fn content_length(exchange: *const HttpExchange, digits: []u8) ?[]const u8 {
        const method = http.method.standard(exchange.method);
        const defines_content = method == .post or method == .put;
        if (exchange.content.len == 0 and !defines_content) return null;
        return std.fmt.bufPrint(digits, "{d}", .{exchange.content.len}) catch unreachable;
    }

    /// The response's content, once the outcome is `response`.
    pub fn content_received(exchange: *const HttpExchange) []const u8 {
        assert(exchange.outcome == .response);
        return exchange.body[0..exchange.body_len];
    }
};

/// Which parts of a request go out as never-indexed literals.
pub const NeverIndexed = struct {
    /// The path, which carries the query, as a DoH GET's does (RFC 8484 §4.1).
    path: bool = false,
    /// One flag for each of the exchange's field lines, in order, or empty for none.
    fields: []const bool = &.{},
};

/// An exchange that ended: its id, and the exchange, whose outcome says how.
pub const Finished = struct {
    id: Id,
    exchange: *HttpExchange,
};

pub const Event = union(enum) {
    /// The connection speaks `Protocol`: over TLS once the handshake completes, as ALPN selected
    /// (RFC 7301 §3.2), and in cleartext from the start. Reported once, before any `finished`.
    connected: Protocol,
    /// The server issued a resumption ticket (RFC 9846 §4.7.1), which `take_ticket` hands over.
    ticket,
    /// An exchange ended. Its slot is free, and the caller may reuse its memory.
    finished: Finished,
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

test "clearing an exchange makes it pending again, and leaves its request alone" {
    var wanted = [_]Wanted{.{ .name = "content-type", .value = "text/plain" }};
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .wanted = &wanted };
    exchange.outcome = .response;
    exchange.status = 200;
    exchange.body_len = 3;
    exchange.coding = .gzip;
    exchange.clear();
    try std.testing.expectEqual(.pending, exchange.outcome);
    try std.testing.expectEqual(0, exchange.body_len);
    try std.testing.expectEqual(null, exchange.coding);
    try std.testing.expectEqual(null, exchange.wanted[0].value);
    try std.testing.expectEqualStrings("GET", exchange.method);
}
