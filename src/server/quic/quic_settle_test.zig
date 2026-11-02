//! The tests of a QUIC connection's `receive` at the instant it settled at (design §8 step 29d.6):
//! it fires the deadlines and settles each request again only after a call that changed what
//! they read. Each test reads the server's events itself, one `receive` at a time, and moves no
//! datagram between them.
const std = @import("std");
const support = @import("quic_test_support.zig");
const constants = @import("../constants.zig");
const Timeout = @import("../deadline.zig").Timeout;

const testing = std.testing;
const connection = &support.connection;
const Field = support.Field;

const ok: u16 = 200;
/// Rounds that carry a request to the server, and its answer back.
const rounds_few: usize = 2;
/// A client window of a tenth of a send window's quota, which a response's content passes.
const window_small: u64 = 1_024;
/// Content of four small windows, a part of it that one small window takes, and a trailer value
/// of two small windows, which one does not take.
const content_windows: usize = 4;
const content: [content_windows * window_small]u8 = @splat('r');
const content_part_len: usize = 512;
const trailer_windows: usize = 2;
const trailer_value: [trailer_windows * window_small]u8 = @splat('t');
/// The responses that the test of two requests writes.
const responses_two: u32 = 2;

/// A server and a client connected, the client's streams starting with `stream_window` octets of
/// credit, and a GET whose head the server reported and that has no response yet.
fn reported_get(stream_window: u64) !*support.Fetch {
    support.client_stream_window = stream_window;
    defer support.client_stream_window = support.window_default;
    try support.start();
    try support.connect();
    const fetch = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    try testing.expect(connection.requests.of(fetch.id) != null);
    return fetch;
}

/// A `receive` at the test's instant, which reports nothing.
fn receive_none() !void {
    try testing.expectEqual(null, (try connection.receive(support.now_ns)).event);
}

test "design §8 step 29d.6: a limit shortened at the instant the connection settled at fires at the next receive" {
    try support.start();
    try support.connect();
    try receive_none();
    const since_ns = support.now_ns - connection.clock.opened_ns;
    try testing.expect(since_ns > 0 and since_ns < constants.policy.first_request_timeout_ns);
    try testing.expectEqual(null, connection.clock.timed_out);
    // Decision 110: a shorter limit counts from the start the deadline already has.
    try connection.set_timeouts(.{ .first_request_ns = since_ns });
    try receive_none();
    try testing.expectEqual(Timeout.first_request, connection.clock.timed_out.?);
}

test "design §8 step 29d.6: a response written at the instant the connection settled at waits on its peer at the next receive" {
    const fetch = try reported_get(support.window_default);
    try receive_none();
    try testing.expectEqual(0, connection.sends.busy);
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    try receive_none();
    try testing.expectEqual(1, connection.sends.busy);
}

test "design §8 step 29d.6: content written at the instant the connection settled at waits on its stream's credit at the next receive" {
    const fetch = try reported_get(window_small);
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    try receive_none();
    try testing.expectEqual(0, connection.sends.bound);
    try testing.expectEqual(content.len, try connection.write_body(fetch.id, .{ .bytes = &content, .end = true }));
    try receive_none();
    try testing.expectEqual(1, connection.sends.bound);
}

test "design §8 step 29d.6: a trailer section written at the instant the connection settled at waits on its stream's credit at the next receive" {
    const fetch = try reported_get(window_small);
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    try testing.expectEqual(content_part_len, try connection.write_body(fetch.id, .{ .bytes = content[0..content_part_len], .end = false }));
    try receive_none();
    try testing.expectEqual(0, connection.sends.bound);
    const trailers = [_]Field{.{ .name = "trailer", .value = &trailer_value }};
    try connection.write_trailers(fetch.id, &trailers);
    try receive_none();
    try testing.expectEqual(1, connection.sends.bound);
}

test "design §8 step 29d.6: a response cancelled at the instant the connection settled at waits on its peer no more at the next receive" {
    const fetch = try reported_get(window_small);
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    try testing.expectEqual(content.len, try connection.write_body(fetch.id, .{ .bytes = &content, .end = true }));
    try receive_none();
    try testing.expectEqual(1, connection.sends.busy);
    try testing.expectEqual(1, connection.sends.bound);
    connection.cancel(fetch.id);
    try receive_none();
    try testing.expectEqual(0, connection.sends.busy);
    try testing.expectEqual(0, connection.sends.bound);
}

test "design §8 step 29d.7: each response written at the instant the connection settled at waits on its peer at the next receive" {
    try support.start();
    try support.connect();
    const first = try support.request("GET", "/first", "");
    const second = try support.request("GET", "/second", "");
    try support.pump(rounds_few);
    try receive_none();
    try testing.expectEqual(0, connection.sends.busy);
    try connection.respond(first.id, .{ .status = ok, .end = true });
    try connection.respond(second.id, .{ .status = ok, .end = true });
    try receive_none();
    try testing.expectEqual(responses_two, connection.sends.busy);
    // Each record settled once: the next receive at this instant settles none again.
    try testing.expectEqual(0, connection.requests.changed.count());
}
