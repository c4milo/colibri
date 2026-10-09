//! The tests of a server connection in cleartext that chooses between h11 and h2 by its first
//! octets (`connection_cleartext.zig`, decision 117).
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");

const testing = std.testing;
const connection = &support.connection;

/// The client's connection preface and an empty SETTINGS frame (RFC 9113 §3.4). The client has not
/// read the server's SETTINGS yet, so it acknowledges none.
const preface_and_settings = h2.constants.client_preface ++ "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
const h11_request = "GET / HTTP/1.1\r\nhost: example.com\r\n\r\n";

/// A connection with the default configuration, which allows both h11 and h2.
fn start_both() !void {
    support.config = .{};
    try connection.init(&support.config, support.stream.random(), 0, 0);
}

test "RFC 9113 §3.3: the connection preface chooses h2 when both versions are allowed" {
    try start_both();
    try testing.expectEqual(null, connection.protocol());
    const received = try support.receive_copy(preface_and_settings);
    try testing.expectEqual(preface_and_settings.len, received.consumed);
    try testing.expectEqual(.h2, connection.protocol().?);
    // RFC 9113 §3.4: the server's connection preface, its SETTINGS frame, goes out first.
    const sent = support.drain();
    try testing.expectEqual(h2.constants.frame_type_settings, sent[h2_support.type_index]);
    const request = try support.receive_copy(try h2_support.request_frame(1, "/", true));
    try testing.expectEqualStrings("/", request.event.?.request.path.?);
}

test "RFC 9113 §3.3: any other first octets choose h11" {
    try start_both();
    const received = try support.receive_copy(h11_request);
    try testing.expectEqual(.h11, connection.protocol().?);
    try testing.expectEqualStrings("/", received.event.?.request.path.?);
}

test "RFC 9113 §3.3: a prefix of the preface chooses nothing and consumes nothing" {
    try start_both();
    const prefix = h2.constants.client_preface[0..16];
    const waiting = try support.receive_copy(prefix);
    try testing.expectEqual(0, waiting.consumed);
    try testing.expectEqual(null, waiting.event);
    try testing.expectEqual(null, connection.protocol());
    // Nothing is said before a protocol is chosen.
    try testing.expectEqual(0, support.drain().len);
    try testing.expect(!connection.should_close());
    // The caller passes the octets again with what it read next.
    const received = try support.receive_copy(preface_and_settings);
    try testing.expectEqual(preface_and_settings.len, received.consumed);
    try testing.expectEqual(.h2, connection.protocol().?);
}

test "decision 117: a version `versions` turns off is never chosen" {
    // h11 alone: the preface is an h11 request line like any other, and h2 never runs.
    support.config = .{ .versions = support.only(.h11) };
    try connection.init(&support.config, support.stream.random(), 0, 0);
    try testing.expectEqual(.h11, connection.protocol().?);
    _ = support.receive_copy(preface_and_settings) catch {};
    try testing.expectEqual(.h11, connection.protocol().?);
    // h2 alone: other first octets are an invalid preface, which fails the connection (RFC 9113
    // §3.4).
    support.config = .{ .versions = support.only(.h2) };
    try connection.init(&support.config, support.stream.random(), 0, 0);
    try testing.expectEqual(.h2, connection.protocol().?);
    try testing.expectError(error.ConnectionFailed, support.receive_copy(h11_request));
    // h3 alone leaves a TCP connection nothing to speak (RFC 9114 §3.1).
    support.config = .{ .versions = .{ .h11 = false, .h2 = false } };
    try testing.expectError(error.NoVersion, connection.init(&support.config, support.stream.random(), 0, 0));
}

test "decision 110: a connection whose first octets never came closes at its first-request deadline" {
    try start_both();
    const deadline_ns = connection.deadline_ns().?;
    connection.on_instant(deadline_ns - 1);
    try testing.expect(!connection.should_close());
    connection.on_instant(deadline_ns);
    try testing.expectEqual(.first_request, connection.close_reason().?.deadline);
    try testing.expect(connection.should_close());
    try testing.expectEqual(0, support.drain().len);
}

test "decision 117: a shutdown before the first octets ends the connection at once" {
    try start_both();
    connection.shutdown();
    // It holds no request and has said nothing, as an idle h11 connection when it shuts down.
    try testing.expect(connection.should_close());
    const received = try support.receive_copy(h11_request);
    try testing.expectEqual(0, received.consumed);
    try testing.expectEqual(null, received.event);
    try testing.expectEqual(0, support.drain().len);
}

test "decision 110 as amended: a body rate is judged by the version the first octets chose" {
    // While the first octets may still choose h2, whose body arrives a DATA frame at a time, a
    // rate an honest peer can fall short of is refused.
    try start_both();
    try testing.expectError(error.DeadlineInvalid, connection.set_deadlines(.{ .body_rate_min = 819 }));
    // h11 in cleartext reads a body octet by octet, so once it is chosen any rate stands.
    _ = try support.receive_copy(h11_request);
    try testing.expectEqual(.h11, connection.protocol().?);
    try connection.set_deadlines(.{ .body_rate_min = 819 });
    // h2 keeps refusing it.
    try start_both();
    _ = try support.receive_copy(preface_and_settings);
    try testing.expectError(error.DeadlineInvalid, connection.set_deadlines(.{ .body_rate_min = 819 }));
}
