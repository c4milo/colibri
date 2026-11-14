//! The tests of a router whose `header_bytes` is 0 (the owner's ruling of 2026-11-13). The router
//! copies no header, and calls each function route at the head. For a request whose body is still
//! to come, a read of `request.body` fails, and the router drops the body.
const std = @import("std");
const event = @import("../event.zig");
const Router = @import("router.zig").Router;
const support = @import("router_handle_test_support.zig");
const whole = @import("router_whole_test_support.zig");
const tcp_support = @import("../engine/engine_tcp_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");
const deadline_support = @import("../connection/connection_deadline_test_support.zig");

const testing = std.testing;
const App = whole.App;

/// A router whose entries copy no header. Test-only.
const HeadPool = Router(App, whole.routes, whole.options_with(0));

/// The status of a function route's response that the router ends.
const ok = 200;

test "the owner's ruling of 2026-11-13: header_bytes 0 calls a function route at the head" {
    var app: App = .{};
    var recorder: support.Recorder = .{};
    var pool: HeadPool = .{};
    _ = pool.handle(&app, &recorder, .{ .request = support.request_of(1, "POST", "/empty", false) });
    try testing.expectEqual(1, app.calls);
    try testing.expectEqual(error.ReadFailed, app.empty_read.?);
    try testing.expect(app.empty_body.? == &support.body_readers.failing);
    try testing.expectEqual(ok, @intFromEnum(recorder.heads[0].status));
    // The router drops the body, so the route gets no second call.
    _ = pool.handle(&app, &recorder, .{ .body = .{ .id = whole.first_id, .user_data = recorder.user_data, .bytes = "x", .end = true } });
    try testing.expectEqual(1, app.calls);
    try testing.expectEqual(1, recorder.head_count);
}

/// The router and the program's context of the tests over the TCP engine. Test-only.
var router: HeadPool align(@alignOf(HeadPool)) = .{};
var context: App align(@alignOf(App)) = .{};

const engine = &tcp_support.engine;

/// Passes each event the TCP engine reports to the router, as a program's loop does.
fn take(reported: event.Event) void {
    _ = router.handle(&context, engine, reported);
}

/// Starts the TCP engine with the router as its program, and accepts one cleartext connection
/// that speaks h2.
fn start_h2() !event.ConnectionHandle {
    try tcp_support.start(null, .{});
    tcp_support.program = take;
    router = .{};
    context = .{};
    const handle = engine.accept(.{ .tls = false }, tcp_support.now_ns).?;
    _ = tcp_support.give(handle, h2_support.client_preface);
    return handle;
}

/// Passes a HEADERS frame of `method` and `/empty` on the first stream, with the stream open.
fn give_head(handle: event.ConnectionHandle, method: []const u8) !void {
    _ = tcp_support.give(handle, try h2_support.request_frame_with(whole.first_stream, method, "/empty", &.{}, false));
}

/// Passes a DATA frame of `bytes` that ends the first stream (RFC 9113 §6.1).
fn give_end(handle: event.ConnectionHandle, bytes: []const u8) !void {
    _ = tcp_support.give(handle, try deadline_support.data_frame(whole.first_stream, bytes, true, 0));
}

/// The status of the response on the first stream.
fn status(handle: event.ConnectionHandle) !u16 {
    return deadline_support.response_status(tcp_support.sent_of(handle.slot), whole.first_stream);
}

test "the owner's ruling of 2026-11-13: a GET that ends in an empty DATA frame gets 200, over h2" {
    const handle = try start_h2();
    try give_head(handle, "GET");
    // The call came at the head, where the body was still to come.
    try testing.expectEqual(1, context.calls);
    try testing.expectEqual(error.ReadFailed, context.empty_read.?);
    // RFC 9113 §8.1: a DATA frame with END_STREAM and no octets ends the request.
    try give_end(handle, "");
    try testing.expectEqual(1, context.calls);
    try testing.expectEqual(ok, try status(handle));
}

test "the owner's ruling of 2026-11-13: a POST gets its call at the head, where a read of its body fails, over h2" {
    const handle = try start_h2();
    try give_head(handle, "POST");
    try testing.expectEqual(1, context.calls);
    try testing.expectEqual(error.ReadFailed, context.empty_read.?);
    try give_end(handle, "x");
    try testing.expectEqual(1, context.calls);
    try testing.expectEqual(ok, try status(handle));
}
