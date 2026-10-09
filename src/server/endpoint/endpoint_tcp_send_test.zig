//! The tests of what a TCP slot owes its socket and how it ends (`endpoint_held_tcp.zig`, decision
//! 119): one `send` for each debt, again only after a `send_stream` that left room; a `close` once
//! the connection has finished; and every request's one ending before the connection's `ended`,
//! whoever closed the socket (INV-30).
const std = @import("std");
const h2 = @import("h2");
const event = @import("../event.zig");
const support = @import("endpoint_tcp_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");

const testing = std.testing;
const endpoint = &support.endpoint;

const ok: u16 = 200;
const word: usize = 0x5e1d;
/// A request h11 keeps the connection open after.
const get_kept = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

/// A cleartext h2 connection that read the client's preface and request on stream 1, left open
/// when `end` is false.
fn start_h2(end: bool) !event.ConnectionHandle {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, h2_support.client_preface);
    _ = support.give(handle, try h2_support.request_frame(1, "/", end));
    try testing.expectEqual(1, support.nth(.request, 0).?.number);
    return handle;
}

/// How many `send` events the endpoint reported.
fn sends() usize {
    var count: usize = 0;
    while (support.nth(.send, count) != null) count += 1;
    return count;
}

test "decision 119: a send comes once for each debt, and again only after a send_stream leaves room" {
    const handle = try start_h2(true);
    support.flushing = false;
    const id = support.id_of(handle, 1);
    const before = sends();
    try endpoint.respond(id, .{ .status = ok, .end = false });
    support.collect();
    try testing.expectEqual(before + 1, sends());
    // More is owed while the send waits: no second one.
    _ = try endpoint.write_body(id, .{ .octets = "first", .end = false });
    support.collect();
    try testing.expectEqual(before + 1, sends());
    // A send_stream that fills its buffer leaves more owed, and the send still waits.
    var small: [4]u8 = undefined;
    try testing.expectEqual(small.len, endpoint.send_stream(handle, &small, support.now_ns));
    support.collect();
    try testing.expectEqual(before + 1, sends());
    // One that leaves room wrote all, and the next debt brings a new send.
    support.flush(handle);
    support.collect();
    try testing.expectEqual(before + 1, sends());
    _ = try endpoint.write_body(id, .{ .octets = "second", .end = true });
    support.collect();
    try testing.expectEqual(before + 2, sends());
}

test "INV-30: a response written whole ends with done when the program closes the socket" {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, get_kept);
    const id = support.id_of(handle, support.nth(.request, 0).?.number);
    try endpoint.set_user_data(id, word);
    try endpoint.respond(id, .{ .status = ok, .end = true });
    endpoint.transport_closed(handle);
    support.collect();
    try testing.expectEqual(word, support.nth(.done, 0).?.user_data);
    try testing.expectEqual(null, support.nth(.cancelled, 0));
    try testing.expect(support.index_of(.done).? < support.index_of(.ended).?);
    // The program closed the socket, so no close is reported.
    try testing.expectEqual(null, support.nth(.close, 0));
}

test "INV-30: requests open when the socket closes end with cancelled, and then the connection" {
    const handle = try start_h2(false);
    try endpoint.set_user_data(support.id_of(handle, 1), word);
    endpoint.transport_closed(handle);
    support.collect();
    const cancelled = support.nth(.cancelled, 0).?;
    try testing.expectEqual(event.CancelReason.closed, cancelled.reason.?);
    try testing.expectEqual(word, cancelled.user_data);
    try testing.expect(support.index_of(.cancelled).? < support.index_of(.ended).?);
    try testing.expect(!support.nth(.ended, 0).?.failed);
}

test "decision 119: the program's cancel is reported before the input that names its request" {
    const handle = try start_h2(false);
    endpoint.cancel(support.id_of(handle, 1));
    // The client's DATA for stream 1 arrives after the program cancelled it.
    var frame: [h2.constants.frame_header_len + 1]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_data(&writer, 1, "x", true, 0);
    const received = endpoint.receive(.{ .stream = .{ .connection = handle, .octets = &frame } }, support.now_ns);
    try testing.expectEqual(0, received.consumed);
    try testing.expectEqual(event.CancelReason.program, received.event.?.cancelled.reason);
}

test "decision 119: an h11 cancel ends the request, and then the connection" {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, get_kept);
    endpoint.cancel(support.id_of(handle, support.nth(.request, 0).?.number));
    support.collect();
    try testing.expectEqual(event.CancelReason.program, support.nth(.cancelled, 0).?.reason.?);
    // RFC 9112 §9.6: h11 cannot end one request and keep the connection.
    try testing.expect(support.index_of(.cancelled).? < support.index_of(.close).?);
    try testing.expect(support.index_of(.close).? < support.index_of(.ended).?);
}

test "RFC 9113 §5.4.1: an h2 connection error ends open requests, sends the GOAWAY, closes, and fails" {
    const handle = try start_h2(false);
    // RFC 9113 §6.1: a DATA frame on stream 0 is a connection error of type PROTOCOL_ERROR. Its
    // header is a length of 1, type 0, no flags and stream 0, then one octet.
    _ = support.give(handle, "\x00\x00\x01\x00\x00\x00\x00\x00\x00x");
    support.collect();
    try testing.expectEqual(event.CancelReason.closed, support.nth(.cancelled, 0).?.reason.?);
    const sent = support.sent_of(handle.slot);
    try testing.expect(std.mem.indexOfScalar(u8, sent, h2.constants.frame_type_goaway) != null);
    try testing.expect(support.index_of(.close).? < support.index_of(.ended).?);
    try testing.expect(support.nth(.ended, 0).?.failed);
}

test "decision 101: a coded response's ring owes octets, which a send writes out" {
    try support.start(null, .{});
    tcp_support.pool.reset(.none());
    support.config.codings = &tcp_support.codings;
    support.config.encoders = tcp_support.pool.encoders();
    try endpoint.init(&support.config, tcp_support.stream.random(), tcp_support.now_seconds, support.now_ns);
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, "GET / HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\n\r\n");
    const id = support.id_of(handle, support.nth(.request, 0).?.number);
    try endpoint.respond(id, .{ .status = ok, .end = false, .codable = true });
    _ = try endpoint.write_body(id, .{ .octets = "coded through the ring", .end = true });
    support.collect();
    // The ring's octets went out, so the response is whole and done.
    try testing.expect(support.nth(.done, 0) != null);
}

test "RFC 9112 §9.6: input after h11 closed is consumed and dropped" {
    try support.start(null, .{});
    support.flushing = false;
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    try endpoint.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = ok, .end = true });
    support.collect();
    try testing.expectEqual(0, support.give(handle, get_kept));
}

/// The client preface with SETTINGS_INITIAL_WINDOW_SIZE (0x4) of 100 octets (RFC 9113 §6.5.2),
/// then the acknowledgment of the server's SETTINGS.
const preface_small_window = h2.constants.client_preface ++ "\x00\x00\x06\x04\x00\x00\x00\x00\x00" ++
    "\x00\x04\x00\x00\x00\x64" ++ h2_support.settings_ack;

test "decision 101: a coded ring an h2 window holds owes a send once a WINDOW_UPDATE opens it" {
    try support.start(null, .{});
    tcp_support.pool.reset(.none());
    tcp_support.fill_incompressible();
    support.config.codings = &tcp_support.codings;
    support.config.encoders = tcp_support.pool.encoders();
    try endpoint.init(&support.config, tcp_support.stream.random(), tcp_support.now_seconds, support.now_ns);
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, preface_small_window);
    const accepts_gzip = [_]tcp_support.Field{.{ .name = "accept-encoding", .value = "gzip" }};
    _ = support.give(handle, try h2_support.request_frame_with(1, "GET", "/", &accepts_gzip, true));
    const id = support.id_of(handle, 1);
    try endpoint.respond(id, .{ .status = ok, .end = false, .codable = true });
    _ = try endpoint.write_body(id, .{ .octets = tcp_support.incompressible[0..coded_len], .end = true });
    support.collect();
    // The window took 100 octets of the ring, and the rest waits.
    try testing.expectEqual(null, support.nth(.done, 0));
    var update: [h2.constants.frame_header_len + h2.constants.window_update_len]u8 = undefined;
    var writer = h2.core.Writer.init(&update);
    try h2.frame.write_window_update(&writer, 1, coded_len * 2);
    _ = support.give(handle, &update);
    support.collect();
    try testing.expect(support.nth(.done, 0) != null);
}

/// Incompressible content longer than the stream's window of 100 octets.
const coded_len: usize = 2_048;

test "decision 119: a pipelined h11 request held by the program is read once it is passed after done" {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    const two = "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n" ++ "GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n";
    // h11 reads /a, and holds /b until /a's response ends: the program keeps the rest.
    const held = support.give(handle, two);
    try testing.expect(held > 0);
    const id = support.id_of(handle, support.nth(.request, 0).?.number);
    const length = [_]tcp_support.Field{.{ .name = "content-length", .value = "5" }};
    try endpoint.respond(id, .{ .status = ok, .fields = &length, .end = false });
    _ = try endpoint.write_body(id, .{ .octets = "hello", .end = false });
    support.collect();
    // The end writes no octet, so no `send` follows it: the `done` is the event to pass again on.
    _ = try endpoint.write_body(id, .{ .octets = "", .end = true });
    support.collect();
    try testing.expect(support.nth(.done, 0) != null);
    try testing.expectEqual(0, support.give(handle, two[two.len - held ..]));
    try testing.expect(support.nth(.request, 1) != null);
}

test "decision 119: an endpoint that serves no TCP version accepts nothing" {
    try support.start(support.identity(), .{ .h11 = false, .h2 = false });
    try testing.expectEqual(null, endpoint.accept(.tls, support.now_ns));
    try testing.expectEqual(null, endpoint.accept(.cleartext, support.now_ns));
}
