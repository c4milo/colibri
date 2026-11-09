//! The tests of a struct route that answers each request octet while its client still sends, over
//! h11 and h2 (decision 127 as amended, design §8 step 46): the router runs on the engine of the
//! TCP tests, which reports each event to it. Each reply is longer than what the engine takes at
//! once, so the route writes most of it from `on_writable`. A router that calls `on_writable` only
//! after the body ends holds each reply until then.
const std = @import("std");
const h2 = @import("h2");
const support = @import("../engine/engine_tcp_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");
const server_constants = @import("../constants.zig");
const event = @import("../event.zig");
const duplex = @import("router_duplex_test_support.zig");

const testing = std.testing;
const engine = &support.engine;

/// The request body, one octet a piece, and the octets of each reply: past a connection's output
/// over h11, and past ten windows of `small_window` over h2, by `memories_per_reply` times the
/// route's response memory. Test-only.
const pieces = "abc";
const memories_per_reply = 4;
const h11_reply_len = server_constants.limits.output_len + memories_per_reply * duplex.response_bytes;
const h2_reply_len = memories_per_reply * duplex.response_bytes;
/// The rounds a test moves octets for each piece at most.
const rounds_max = 64;

/// The client preface with a SETTINGS frame whose SETTINGS_INITIAL_WINDOW_SIZE (0x4) is
/// `small_window` (RFC 9113 §6.5.2), then the acknowledgment of the server's SETTINGS.
const small_window: u32 = 100;
const preface_small_window = h2.constants.protocol.client_preface ++ "\x00\x00\x06\x04\x00\x00\x00\x00\x00" ++
    "\x00\x04\x00\x00\x00\x64" ++ h2_support.settings_ack;
const stream_id: u32 = 1;

/// The router and its route's settings, which the program hook reaches. Test-only.
var router: duplex.Pool align(@alignOf(duplex.Pool)) = .{};
var app: duplex.App align(@alignOf(duplex.App)) = .{ .reply_len = 0 };

/// Passes each request's event the engine reports to the router, as a program's loop does.
fn take(reported: event.Event) void {
    _ = router.handle(&app, engine, reported);
}

/// Starts the engine with the router as its program, and accepts one cleartext connection.
fn start(settings: duplex.App) !event.ConnectionHandle {
    try support.start(null, .{});
    support.program = take;
    router = .{};
    app = settings;
    return engine.accept(.{ .tls = false }, support.now_ns).?;
}

/// Writes what the connection owes to its socket until the route wrote `target` octets.
fn drain_h11(handle: event.ConnectionHandle, target: usize) void {
    // Bounded: each round empties the connection's output, which reports `writable`.
    for (0..rounds_max) |_| {
        support.flush(handle);
        support.collect();
        if (app.written >= target) return;
    }
}

test "decision 127 as amended: a struct route answers each octet before the body ends, over h11" {
    const handle = try start(.{ .reply_len = h11_reply_len });
    // The fixture's socket takes octets only when the test flushes, so the output fills.
    support.flushing = false;
    _ = support.give(handle, "POST /duplex HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n");
    for (pieces, 1..) |piece, count| {
        _ = support.give(handle, &.{piece});
        drain_h11(handle, count * h11_reply_len);
        try testing.expectEqual(count * h11_reply_len, app.written);
    }
    try testing.expect(app.ended);
    try testing.expect(app.open_calls > 0);
    // Calls that wrote nothing while the body was open waited, and cancelled nothing.
    try testing.expect(app.idle_calls > 0);
    try testing.expect(support.nth(.done, 0) != null);
    try testing.expectEqual(null, support.nth(.cancelled, 0));
}

/// Passes a WINDOW_UPDATE frame that opens the stream's window by `small_window` (RFC 9113
/// §6.9).
fn open_window(handle: event.ConnectionHandle) !void {
    var update: [h2.constants.protocol.frame_header_len + h2.constants.protocol.window_update_len]u8 = undefined;
    var writer = h2.core.Writer.init(&update);
    try h2.frame.write_window_update(&writer, stream_id, small_window);
    _ = support.give(handle, &update);
}

/// Passes one DATA frame of `piece`, which ends the stream when `end` is set (RFC 9113 §6.1).
fn give_data(handle: event.ConnectionHandle, piece: u8, end: bool) !void {
    var frame: [h2.constants.protocol.frame_header_len + 1]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_data(&writer, stream_id, &.{piece}, end, 0);
    _ = support.give(handle, &frame);
}

/// Opens the stream's window until the route wrote `target` octets, or the rounds ran out.
fn drain_h2(handle: event.ConnectionHandle, target: usize) !void {
    // Bounded: each round opens the window once, which reports `writable`.
    for (0..rounds_max) |_| {
        if (app.written >= target) return;
        try open_window(handle);
    }
}

/// Starts an h2 connection whose streams' windows hold `small_window`, with a POST of `path`
/// whose body stays open.
fn start_h2(settings: duplex.App, path: []const u8) !event.ConnectionHandle {
    const handle = try start(settings);
    _ = support.give(handle, preface_small_window);
    _ = support.give(handle, try h2_support.request_frame_with(stream_id, "POST", path, &.{}, false));
    return handle;
}

test "decision 127 as amended: a struct route answers each octet before the body ends, over h2" {
    const handle = try start_h2(.{ .reply_len = h2_reply_len }, "/duplex");
    for (pieces, 1..) |piece, count| {
        try give_data(handle, piece, count == pieces.len);
        try drain_h2(handle, count * h2_reply_len);
        try testing.expectEqual(count * h2_reply_len, app.written);
    }
    try open_window(handle);
    try testing.expect(app.ended);
    try testing.expect(app.open_calls > 0);
    // Calls that wrote nothing while the body was open waited, and cancelled nothing.
    try testing.expect(app.idle_calls > 0);
    try testing.expect(support.nth(.done, 0) != null);
    try testing.expectEqual(null, support.nth(.cancelled, 0));
}

test "decision 127 as amended: a .whole_body route's on_writable waits for the body's end, over h2" {
    // The route owes its reply at the head, and the window takes a part of it.
    const handle = try start_h2(.{ .reply_len = 0, .head_len = h2_reply_len }, "/whole");
    try drain_h2(handle, h2_reply_len);
    try testing.expectEqual(0, app.open_calls);
    try testing.expect(app.written < h2_reply_len);
    // Once the body ends, the router calls `on_writable` under the rule of decision 127.
    try give_data(handle, pieces[0], true);
    try drain_h2(handle, h2_reply_len);
    try open_window(handle);
    try testing.expectEqual(h2_reply_len, app.written);
    try testing.expect(app.ended);
    try testing.expect(support.nth(.done, 0) != null);
}
