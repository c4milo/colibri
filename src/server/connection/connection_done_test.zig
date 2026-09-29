//! The tests of the `done` event (decision 103): a response's request is done after the call that
//! wrote its last octet, once, and `receive` reports it before it reads anything more.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");

const testing = std.testing;
const connection = &support.connection;

const ok: u16 = 200;
const early_hints: u16 = 103;
const trailer_fields = [_]support.Field{.{ .name = "checksum", .value = "1" }};

/// Expects `receive` to report nothing, with nothing to read. Test-only.
fn expect_nothing() !void {
    const received = try connection.receive(&.{}, support.now_ns);
    try testing.expectEqual(0, received.consumed);
    try testing.expectEqual(null, received.event);
}

test "decision 103: an h2 response is done after the call that ends it, before the next request" {
    try h2_support.start();
    _ = try support.receive_copy(try h2_support.request_frame(1, "/", true));
    try connection.respond(1, .{ .status = ok, .end = false });
    try expect_nothing();
    try testing.expectEqual(5, try connection.write_body(1, .{ .octets = "hello", .end = true }));
    // A request that arrives next waits behind the `done` event.
    const next = try h2_support.request_frame(3, "/next", true);
    const first = try support.receive_copy(next);
    try testing.expectEqual(0, first.consumed);
    try testing.expectEqual(1, first.event.?.done.id);
    const second = try support.receive_copy(next);
    try testing.expectEqual(3, second.event.?.request.id);
}

test "decision 103: an interim response ends no h2 request, and a final one without content does" {
    try h2_support.start();
    _ = try support.receive_copy(try h2_support.request_frame(1, "/", true));
    // RFC 9113 §8.1: an interim response ends no stream, whatever `end` asks.
    try connection.respond(1, .{ .status = early_hints, .end = true });
    try expect_nothing();
    try connection.respond(1, .{ .status = ok, .end = true });
    try support.expect_done(1);
    try expect_nothing();
}

test "decision 103: content the output took in part owes no done until its last octet" {
    try h2_support.start();
    _ = try support.receive_copy(try h2_support.request_frame(1, "/", true));
    try connection.respond(1, .{ .status = ok, .end = false });
    _ = support.drain();
    // Room for a DATA frame's header and three octets of its payload.
    const room: usize = h2.constants.frame_header_len + 3;
    connection.output_len = support.server_constants.output_len - room;
    try testing.expectEqual(3, try connection.write_body(1, .{ .octets = "hello", .end = true }));
    try expect_nothing();
    connection.output_len = 0;
    try testing.expectEqual(2, try connection.write_body(1, .{ .octets = "lo", .end = true }));
    try support.expect_done(1);
}

test "decision 103: an h2 trailer section ends the response, and makes the request done" {
    try h2_support.start();
    _ = try support.receive_copy(try h2_support.request_frame(1, "/", true));
    try connection.respond(1, .{ .status = ok, .end = false });
    try testing.expectEqual(1, try connection.write_body(1, .{ .octets = "x", .end = false }));
    try expect_nothing();
    try connection.write_trailers(1, &trailer_fields);
    try support.expect_done(1);
}

test "decision 103: a request the caller or the peer cancelled is never done" {
    try h2_support.start();
    _ = try support.receive_copy(try h2_support.request_frame(1, "/", true));
    _ = try support.receive_copy(try h2_support.request_frame(3, "/", false));
    try connection.respond(1, .{ .status = ok, .end = false });
    connection.cancel(1);
    try expect_nothing();
    var writer = h2.core.Writer.init(h2_support.frames[0..]);
    try h2.frame.write_rst_stream(&writer, 3, h2.constants.error_cancel);
    try testing.expectEqual(3, (try support.receive_copy(writer.written())).event.?.cancelled.id);
    try expect_nothing();
}

test "decision 103: the transport's close drops the done events owed" {
    try h2_support.start();
    _ = try support.receive_copy(try h2_support.request_frame(1, "/", true));
    try connection.respond(1, .{ .status = ok, .end = true });
    connection.transport_closed();
    try expect_nothing();
}

test "decision 103: an h11 response is done once, whatever the calls after it" {
    try support.start_cleartext(.h11);
    const request = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    try testing.expectEqual(1, (try support.receive_copy(request)).event.?.request.id);
    try connection.respond(1, .{ .status = ok, .end = false });
    try expect_nothing();
    try testing.expectEqual(5, try connection.write_body(1, .{ .octets = "hello", .end = true }));
    // The response is whole, so more content is out of order, and owes no second `done`.
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(1, .{ .octets = "x", .end = true }));
    try support.expect_done(1);
    try expect_nothing();
}

test "decision 103: an h11 trailer section ends the chunked response, and makes the request done" {
    try support.start_cleartext(.h11);
    const request = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    try testing.expectEqual(1, (try support.receive_copy(request)).event.?.request.id);
    // RFC 9112 §7.1: content of unknown length to an HTTP/1.1 request goes out chunked.
    try connection.respond(1, .{ .status = ok, .end = false });
    try testing.expectEqual(1, try connection.write_body(1, .{ .octets = "x", .end = false }));
    try expect_nothing();
    try connection.write_trailers(1, &trailer_fields);
    try support.expect_done(1);
}
