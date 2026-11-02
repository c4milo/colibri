//! The tests of the bounds on h11's drop (decision 146): a response the caller no longer reads is
//! read and dropped only while it leaves the connection open, while its content left fits
//! `drop_len_max`, and until `Config.drop_ns` runs out. Past a bound the connection fails.
const std = @import("std");
const support = @import("connection_test_support.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;

const drop_len_max = constants.limits.drop_len_max;
const drop_ns = constants.policy.drop_timeout_ns;

/// Where the tests' exchanges put their responses, outside any stack frame. Test-only.
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 64;
/// Content the peer sends in pieces, outside any stack frame. Test-only.
var piece: [piece_len]u8 = @splat('x');
const piece_len: usize = 16_384;

/// The exchange the caller cancels, and the one written after it, which waits for its response.
var cancelled: Exchange align(@alignOf(Exchange)) = undefined;
var next: Exchange align(@alignOf(Exchange)) = undefined;

fn get(body: []u8) Exchange {
    return .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = body } };
}

/// Writes two GETs and cancels the first at `support.now_ns`, before any response arrives.
fn start_cancelled() !void {
    try support.start_cleartext(.h11);
    cancelled = get(&bodies[0]);
    next = get(&bodies[1]);
    const id = try connection.request(&cancelled.request, &cancelled.response);
    _ = try connection.request(&next.request, &next.response);
    support.client_send();
    connection.cancel(id, support.now_ns);
}

fn peer_writes(octets: []const u8) !void {
    @memcpy(support.to_client[support.to_client_len..][0..octets.len], octets);
    support.to_client_len += octets.len;
    try support.client_receive();
}

/// The peer writes `len` octets of content in pieces, and the client reads each.
fn peer_writes_content(len: u64) !void {
    var left = len;
    // Bounded: each pass writes a piece, and a test's content is a few hundred pieces at most.
    while (left > 0) {
        const taken: usize = @intCast(@min(left, piece_len));
        try peer_writes(piece[0..taken]);
        left -= taken;
    }
}

/// The connection failed, so the exchange written after the cancelled one ends `closed`, and the
/// cancelled one reports nothing.
fn expect_failed() !void {
    try testing.expect(connection.failed);
    try testing.expectEqual(.closed, next.response.result);
    try testing.expectEqual(.pending, cancelled.response.result);
    try testing.expectEqual(1, support.count(.finished));
}

/// The drop ended with its response, and the next response arrived on the same connection.
fn expect_kept() !void {
    try peer_writes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    try testing.expect(!connection.failed);
    try testing.expectEqualStrings("hello", next.response.body_received());
    try testing.expectEqual(.pending, cancelled.response.result);
}

test "decision 146: a drop reads a Content-Length of drop_len_max, and fails the connection past it" {
    try start_cancelled();
    try peer_writes(std.fmt.comptimePrint("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n", .{drop_len_max}));
    try peer_writes_content(drop_len_max);
    try expect_kept();

    try start_cancelled();
    // The head says more is left than a drop reads, so no content is read.
    try peer_writes(std.fmt.comptimePrint("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n", .{drop_len_max + 1}));
    try expect_failed();
}

test "decision 146: a drop counts the chunked content that arrived" {
    try start_cancelled();
    try peer_writes(std.fmt.comptimePrint("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\n", .{piece_len}));
    // Bounded: each pass writes one chunk.
    for (0..drop_len_max / piece_len - 1) |_| {
        try peer_writes(piece[0..]);
        try peer_writes(std.fmt.comptimePrint("\r\n{x}\r\n", .{piece_len}));
    }
    try peer_writes(piece[0..]);
    try testing.expect(!connection.failed);
    // One octet more than a drop reads.
    try peer_writes("\r\n1\r\nx");
    try expect_failed();
}

test "decision 146 ruling 4: no drop of a response that closes the connection" {
    try start_cancelled();
    // RFC 9112 §9.6: the "close" option.
    try peer_writes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n");
    try expect_failed();

    try start_cancelled();
    // RFC 9112 §6.3 rule 8: content that runs until the close.
    try peer_writes("HTTP/1.1 200 OK\r\n\r\n");
    try expect_failed();

    try start_cancelled();
    // RFC 9112 §9.3: an HTTP/1.0 response closes the connection unless it says to keep it.
    try peer_writes("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\n");
    try expect_failed();
}

test "decision 146: a drop fails the connection when its time runs out" {
    try start_cancelled();
    try testing.expectEqual(support.now_ns + drop_ns, connection.deadline_ns().?);
    try peer_writes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel");
    connection.on_instant(support.now_ns + drop_ns - 1);
    try testing.expect(!connection.failed);
    connection.on_instant(support.now_ns + drop_ns);
    try testing.expect(connection.failed);
    try testing.expectEqual(null, connection.deadline_ns());
    try support.client_receive();
    try expect_failed();
}

test "decision 146: a drop's time runs from its start, and a later read does not start it again" {
    try start_cancelled();
    const later = support.now_ns + drop_ns - 1;
    const head = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";
    @memcpy(support.to_client[0..head.len], head);
    var consumed: usize = 0;
    // Bounded: a call takes the octets, or reports one of the few events the connection owes.
    for (0..support.events_max) |_| {
        if (consumed == head.len) break;
        consumed += connection.receive(support.to_client[consumed..head.len], later).consumed;
    }
    try testing.expectEqual(head.len, consumed);
    try testing.expectEqual(support.now_ns + drop_ns, connection.deadline_ns().?);
}

test "decision 146: a drop's time starts once its response is the one being read" {
    try support.start_cleartext(.h11);
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try connection.request(&first.request, &first.response);
    const id = try connection.request(&second.request, &second.response);
    support.client_send();
    connection.cancel(id, support.now_ns - 1);
    // The first response is still awaited, so the drop has not begun.
    try testing.expectEqual(null, connection.deadline_ns());
    try peer_writes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    try testing.expectEqual(.response, first.response.result);
    try testing.expectEqual(support.now_ns + drop_ns, connection.deadline_ns().?);
}

test "decision 146: a drop with no time limit has no deadline" {
    try support.start_configured(.{ .authority = support.authority, .protocols = support.only(.h11), .drop_ns = null });
    cancelled = get(&bodies[0]);
    next = get(&bodies[1]);
    const id = try connection.request(&cancelled.request, &cancelled.response);
    _ = try connection.request(&next.request, &next.response);
    support.client_send();
    connection.cancel(id, support.now_ns);
    try testing.expectEqual(null, connection.deadline_ns());
    try peer_writes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    try expect_kept();
}
