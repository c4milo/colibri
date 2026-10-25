//! What `receive` reports, the same for h11, h2 and h3 (decision 100): a request's head, its
//! content, its trailer section, its end by cancellation, or that its response is done; and, from
//! the endpoint (decision 119), that a response can take more, that a TCP connection owes octets or
//! is to be closed, that a connection ended, or that every connection did. Every slice points into
//! storage the connection or the caller holds, and stays valid until the endpoint's next call that
//! the comment on `Endpoint.receive` lists.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const deadline = @import("deadline.zig");
const close_reason = @import("close_reason.zig");

/// One header: a field line's name and value (RFC 9110 §5.2).
pub const Header = http.Field;

/// A connection an endpoint holds: its slot, and the slot's generation, which advances each time
/// the endpoint reports that a connection there ended (decision 119). So a handle of an ended
/// connection names nothing. Generation 0 names no connection.
pub const ConnectionHandle = packed struct(u64) {
    /// Below the endpoint's TCP and QUIC slots together. TCP slots come first, so a TCP
    /// connection's slot is below the count of TCP slots. A slot is free again at its
    /// connection's `ended`, so a program whose socket outlives `ended` maps a slot to the state
    /// of the connection the slot holds now, and keeps the whole handle with that state.
    slot: u32,
    generation: u32,
};

/// A request's number on its connection: the h2 or QUIC stream it arrived on, or for h11 its place
/// on the connection, counting from 1. A connection never gives two requests one number.
pub const Number = u64;

/// A request's id: the connection that carries it and its number there (decision 119). A response
/// names the request it answers by it.
pub const RequestId = packed struct(u128) {
    connection: ConnectionHandle,
    number: Number,
};

/// The id a connection reports for its request `number`, with no connection named: the endpoint
/// that holds the connection names it.
pub fn id_of(number: Number) RequestId {
    return .{ .connection = .{ .slot = 0, .generation = 0 }, .number = number };
}

/// The protocol serving a connection.
pub const Protocol = enum { h11, h2, h3 };

/// The HTTP version a request came in, numbered as RFC 9110 §2.5 numbers it: 1.0 or 1.1 for h11,
/// 2.0 for h2, and 3.0 for h3.
pub const Version = struct {
    major: u8,
    minor: u8,
};

/// The head of a response, which `respond` writes: its status, its field lines, and whether the
/// response ends with it. An interim response (1xx) ignores `end`, because the final response
/// still follows it (RFC 9110 §15.2).
pub const Response = struct {
    status: u16,
    headers: []const Header = &.{},
    end: bool,
    /// Whether the server may code the content in a coding the request accepts (decision 101),
    /// when its configuration names codings. Only the caller knows whether the content mixes a
    /// secret with octets a peer chose, which compression must not do (RFC 9113 §10.6), or
    /// carries a field computed over the uncoded octets, such as a digest of them. A coded
    /// response gains Content-Encoding and loses Content-Length, and a strong ETag becomes weak.
    codable: bool = false,
};

/// Octets of a response's content, which `write_body` writes, and whether the content ends with
/// them.
pub const ResponseBody = struct {
    bytes: []const u8,
    end: bool,
};

/// A request's headers or trailers: its field section, less the pseudo-header fields h2 places
/// first (RFC 9113 §8.3).
pub const Headers = struct {
    section: *const http.FieldSection,
    /// The index of the first regular field line.
    first: u32,

    /// The section's regular field lines, skipping the pseudo-header fields at its front.
    pub fn of(section: *const http.FieldSection) Headers {
        var first: u32 = 0;
        // RFC 9113 §8.3: every pseudo-header field comes before the regular field lines.
        while (first < section.len() and is_pseudo(section.get(first).name)) first += 1;
        assert(first <= section.len());
        return .{ .section = section, .first = first };
    }

    /// The first regular field line named `name`, compared case-insensitively (RFC 9110 §5.1).
    pub fn find(headers: Headers, name: []const u8) ?Header {
        assert(!is_pseudo(name));
        return headers.section.find(name);
    }

    /// The regular field lines in arrival order.
    pub fn iterator(headers: Headers) http.field_section.Iterator {
        return .{ .section = headers.section, .index = headers.first };
    }

    /// How many regular field lines the section holds.
    pub fn len(headers: Headers) u32 {
        assert(headers.first <= headers.section.len());
        return headers.section.len() - headers.first;
    }
};

/// RFC 9113 §8.3: a pseudo-header field's name starts with a colon.
fn is_pseudo(name: []const u8) bool {
    return name.len > 0 and name[0] == ':';
}

/// A target's path and query, apart (decision 127): the path before the first `?` (RFC 3986 §3.3),
/// "/" when that is empty, and the rest after the `?`, or null with no `?`.
pub const Target = struct { path: ?[]const u8, query: ?[]const u8 };

pub fn split_target(target: ?[]const u8) Target {
    const whole = target orelse return .{ .path = null, .query = null };
    // RFC 3986 §3.4: the query starts at the first "?" and runs to the end of the target.
    const mark = std.mem.indexOfScalar(u8, whole, '?') orelse return .{ .path = whole, .query = null };
    // RFC 9110 §4.2.3: an empty path is "/".
    const path = if (mark == 0) root_path else whole[0..mark];
    return .{ .path = path, .query = whole[mark + 1 ..] };
}

const root_path = "/";

/// A request's head.
pub const Request = struct {
    id: RequestId,
    method: []const u8,
    version: Version,
    /// The request-target as it arrived for h11 (RFC 9112 §3.2). For h2 and h3 it is the
    /// `:path`, or CONNECT's `:authority` (RFC 9113 §8.3.1, §8.5; RFC 9114 §4.3.1, §4.4).
    target: []const u8,
    /// The `:scheme` of h2 and h3. For h11 it is "https" over TLS and "http" in cleartext, or an
    /// absolute-form target's scheme (RFC 9112 §3.3). Null for CONNECT (RFC 9113 §8.5, RFC 9114
    /// §4.4, RFC 9112 §3.2.3).
    scheme: ?[]const u8,
    /// The `:authority` of h2 and h3. For h11 it is an absolute-form target's authority, else the
    /// Host field (RFC 9112 §3.2.2, §3.3). Null when the request carries none.
    authority: ?[]const u8,
    /// The path of h2's and h3's `:path`, or of h11's target, without its query, or `*` for the
    /// asterisk-form (RFC 9112 §3.2). An empty path, as an absolute-form target may carry, gives
    /// "/" (RFC 9110 §4.2.3, https://github.com/c4milo/colibri/issues/103). Null for CONNECT (RFC
    /// 9113 §8.5, RFC 9114 §4.4, RFC 9112 §3.2.3). `server.router` matches this value.
    path: ?[]const u8,
    /// The query after the path's `?` (RFC 3986 §3.4), without the `?`, or null when the target
    /// carries none. `server.QueryParameters` reads its pairs (decision 127).
    query: ?[]const u8,
    headers: Headers,
    /// Whether the head ended the request, so no content follows.
    end: bool,
};

/// Octets of a request's content, and whether they end it. The last `body` of a request may carry
/// none. `user_data` is the word the program set at the request's head (decision 119).
pub const RequestBody = struct {
    id: RequestId,
    user_data: usize = 0,
    bytes: []const u8,
    end: bool,
};

/// A request's trailer section, which ends it (RFC 9110 §6.5).
pub const Trailers = struct {
    id: RequestId,
    user_data: usize = 0,
    headers: Headers,
};

/// A request ended before its response did: the peer reset its stream, colibri refused it (RFC
/// 9113 §6.4, §5.4.2; RFC 9114 §4.1.1, §4.1.2), one of decision 110's deadlines passed on its
/// stream, its connection stopped first, or the program cancelled it. Through a connection, the
/// id may be one no `request` event named, when the refusal came before the head was read whole.
pub const Cancelled = struct {
    id: RequestId,
    user_data: usize = 0,
    reason: CancelReason,
};

pub const CancelReason = union(enum) {
    /// The peer reset the request's stream.
    peer_reset,
    /// colibri refused the request, which the peer sent malformed.
    refused,
    /// The deadline passed, and colibri reset the stream (decision 110).
    timeout: deadline.Timeout,
    /// The connection stopped before the response was whole (decision 119).
    closed,
    /// The program called `cancel` (decision 119).
    program,
};

/// The response to a request is whole, and the server reads none of the caller's octets for it
/// again, so the caller may reuse the memory its body came from (decision 103). h11 and h2 report
/// it after the call that wrote the response's last octet, and h3 once the peer acknowledged
/// every octet of it. A request cancelled first gets none.
pub const Done = struct {
    id: RequestId,
    user_data: usize = 0,
};

/// A response whose last write took fewer octets than it was given, or found no room, can take
/// more (decision 119).
pub const Writable = struct {
    id: RequestId,
    user_data: usize,
};

/// A connection is over (decision 119). Every request it carried had its `finished` first, and
/// its handle and every id on it name nothing from here on.
pub const Ended = struct {
    connection: ConnectionHandle,
    /// The deadline that passed or the limit the peer passed, when colibri closed the connection
    /// for one (decision 110), or null.
    reason: ?close_reason.CloseReason,
    /// Whether colibri closed it because its peer broke a protocol rule or its record layer
    /// failed.
    failed: bool,
};

/// How a request ended, in its `finished` event (decision 126).
pub const Result = union(enum) {
    /// The response is whole, and the server reads none of the caller's bytes for it again, so
    /// the caller may reuse the memory its body came from (decision 103). h11 and h2 report it
    /// after the call that wrote the response's last byte, and h3 once the peer acknowledged every
    /// byte of it.
    sent,
    /// The request ended before its response did, for this reason.
    cancelled: CancelReason,
};

/// A request is over, once: its response was sent, or it was cancelled (decision 126). The
/// caller may reuse the memory of both. Through a connection, the id of a refused request may be
/// one no `request` event named, when the refusal came before the head was read whole.
pub const Finished = struct {
    id: RequestId,
    user_data: usize = 0,
    result: Result,
};

/// What a connection reports to the endpoint that holds it, which the endpoint turns into an
/// `Event`: a request's end comes as `done` or `cancelled` here, and as `finished` there. The root
/// does not export it.
pub const ConnectionEvent = union(enum) {
    request: Request,
    body: RequestBody,
    trailers: Trailers,
    cancelled: Cancelled,
    done: Done,
};

/// What one `receive` call of a connection took and reported.
pub const ConnectionResult = struct {
    /// Bytes of the caller's input taken.
    consumed: usize,
    event: ?ConnectionEvent,
};

pub const Event = union(enum) {
    request: Request,
    body: RequestBody,
    trailers: Trailers,
    finished: Finished,
    /// A response can take more (decision 119).
    writable: Writable,
    /// A TCP connection owes octets: the program calls `send_stream` for it (decision 119).
    send: ConnectionHandle,
    /// The program closes this TCP connection's socket: colibri reads and writes nothing more on
    /// it.
    close: ConnectionHandle,
    ended: Ended,
    /// After `shutdown`, every connection has ended.
    closed,
};

/// What one `receive` call took and reported.
pub const ReceiveResult = struct {
    /// Bytes of the caller's input taken.
    consumed: usize,
    event: ?Event,
};

test "decision 127: a target comes apart at its first ?, and an empty path is /" {
    try std.testing.expectEqualDeep(Target{ .path = "/a", .query = "b=1?c" }, split_target("/a?b=1?c"));
    try std.testing.expectEqualDeep(Target{ .path = "/a", .query = null }, split_target("/a"));
    try std.testing.expectEqualDeep(Target{ .path = "/a", .query = "" }, split_target("/a?"));
    try std.testing.expectEqualDeep(Target{ .path = "/", .query = "x" }, split_target("?x"));
    try std.testing.expectEqualDeep(Target{ .path = null, .query = null }, split_target(null));
}

test "decision 119: a connection's ids name no connection, which the endpoint that holds it names" {
    const id = id_of(7);
    try std.testing.expectEqual(7, id.number);
    try std.testing.expectEqual(0, id.connection.generation);
    try std.testing.expectEqual(0, id.connection.slot);
    // Ids compare whole: the same number on another connection is another request.
    const other: RequestId = .{ .connection = .{ .slot = 0, .generation = 1 }, .number = 7 };
    try std.testing.expect(id != other);
}
