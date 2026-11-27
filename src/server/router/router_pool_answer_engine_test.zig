//! The test of an answer with no entry over h2, on the engine of the TCP tests (design §8 step
//! 53): a 404 whose HEADERS frame finds no room in the connection's output is not reset, and goes
//! once the output empties.
const std = @import("std");
const h2 = @import("h2");
const event = @import("../event.zig");
const constants = @import("../constants.zig");
const Response = @import("../response/response.zig").Response;
const RequestContext = @import("../request_context.zig").RequestContext;
const Router = @import("router.zig").Router;
const tcp_support = @import("../engine/engine_tcp_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");
const deadline_support = @import("../connection/connection_deadline_test_support.zig");

const testing = std.testing;
const tcp_engine = &tcp_support.engine;

const App = struct {};

/// More content than a connection's output holds, which the program keeps. Test-only.
const long_content: [constants.limits.output_len + 1]u8 = @splat('c');

fn fill(_: *App, _: *RequestContext, _: *const event.Request, response: *Response) !void {
    try response.write_kept(&long_content);
    try response.end();
}

fn on_error(_: *App, _: *RequestContext, _: *const event.Request, _: anyerror, response: *Response) void {
    response.status = .internal_server_error;
}

const routes = .{
    .error_handler = on_error,
    .routes = .{.{ .get, "/fill", fill }},
};

/// The entries of the pool, and bytes of each entry's response memory. Test-only.
const requests = 2;
const response_buffer_bytes = 64;
const Pool = Router(App, routes, .{ .requests = requests, .response_buffer_bytes = response_buffer_bytes, .request_body_bytes = 0, .request_header_bytes = 0 });

/// The router and the program's context, which the engine's program hook reaches. Test-only.
var engine_router: Pool align(@alignOf(Pool)) = .{};
var engine_app: App align(@alignOf(App)) = .{};

/// Passes each event the TCP engine reports to the router, as a program's loop does.
fn take_tcp(reported: event.Event) void {
    _ = engine_router.handle(&engine_app, tcp_engine, &reported);
}

/// The h2 streams of the test's two requests (RFC 9113 §5.1.1), and the 404's status code.
const fill_stream: u32 = 1;
const missing_stream: u32 = 3;
const not_found_code: u16 = 404;
/// The rounds of send and poll that the test runs at most until the 404 goes.
const rounds_max = 4;

test "RFC 9110 §15.5.5: over h2, a 404 with no room in the output is not reset, and goes once the output empties" {
    try tcp_support.start(null, .{});
    tcp_support.program = take_tcp;
    defer tcp_support.program = null;
    // The test's socket takes nothing until `flush`, so the output stays full.
    tcp_support.flushing = false;
    defer tcp_support.flushing = true;
    engine_router = .{};
    const handle = tcp_engine.accept(.{ .tls = false }, tcp_support.now_ns).?;
    _ = tcp_support.give(handle, h2_support.client_preface);
    _ = tcp_support.give(handle, try h2_support.request_frame(fill_stream, "/fill", true));
    _ = tcp_support.give(handle, try h2_support.request_frame(missing_stream, "/missing", true));
    // The head of the 404 found no room: it waits in a slot, and the stream is not reset.
    try testing.expect(engine_router.answers.slots[0].used);
    try testing.expectEqual(null, tcp_support.nth(.cancelled, 0));
    // A head waits for an empty output, and the other stream may write there first, so the 404
    // may go in a later round.
    for (0..rounds_max) |_| {
        tcp_support.flush(handle);
        tcp_support.collect();
        if (!engine_router.answers.slots[0].used) break;
    }
    tcp_support.flush(handle);
    const sent = tcp_support.sent_of(handle.slot);
    try testing.expectEqual(not_found_code, try deadline_support.response_status(sent, missing_stream));
    try testing.expectEqual(null, deadline_support.find_frame(sent, h2.constants.protocol.frame_type_rst_stream, missing_stream));
    tcp_support.collect();
    // The request's `finished` freed the slot.
    try testing.expect(!engine_router.answers.slots[0].used);
}
