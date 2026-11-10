//! A long response through a struct route over h3 (design §8 step 46): the router runs on the
//! engine that the QUIC tests drive, with an h3 client in the same process. Some of the client's
//! datagrams are lost, so its acknowledgments arrive late, and some of the server's are lost, so
//! QUIC sends runs again from the router's memory (RFC 9000 §13.3). A run the writer wrote over
//! before the peer acknowledged it would reach the client changed.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const Router = @import("router.zig").Router;
const quic_support = @import("../quic/quic_test_support.zig");
const stream = @import("router_stream_test_support.zig");

const testing = std.testing;
const App = stream.App;
const engine = &quic_support.engine_support.engine;

/// Octets of the entry's response memory, of the response, sixteen times as many, and of each
/// message. Test-only.
const response_bytes = 512;
const stream_turns = 16;
const stream_len = stream_turns * response_bytes;
const message_len = 100;
/// The rounds a test pumps at most, and the rounds between two losses of each side.
const rounds_max = 512;
const client_loss_every = 3;
const server_loss_every = 5;
/// Octets of the response memory of a route that flushes each small message, and the messages it
/// writes, of 7 to 128 octets each (the owner's ruling of 2026-11-09).
const long_response_bytes = 8192;
const long_messages = stream.messages_max;
/// The rounds the long response takes at most, and the rounds from one datagram of the client
/// that arrives to the next, so each acknowledgment is late.
const long_rounds_max = 2048;
const client_heard_every = 3;
const ok_code: u16 = 200;
const internal_server_error: http.Status = .internal_server_error;

fn on_error(_: *App, _: *const event.Request, _: anyerror, response: *ResponseWriter) void {
    response.status = internal_server_error;
}

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/stream", stream.Stream },
    },
};

const Pool = Router(App, routes, .{ .requests = 1, .response_bytes = response_bytes, .body_bytes = 0 });
const LongPool = Router(App, routes, .{ .requests = 1, .response_bytes = long_response_bytes, .body_bytes = 0 });

/// The routers and their route's settings, which the program hooks reach. Test-only.
var router: Pool align(@alignOf(Pool)) = .{};
var long_router: LongPool align(@alignOf(LongPool)) = .{};
var app: App align(@alignOf(App)) = .{ .stream_len = stream_len, .message_len = message_len, .flush = true };

/// Passes each event the engine reports to the router, as a program's loop does.
fn take(reported: event.Event) void {
    _ = router.handle(&app, engine, reported);
}

fn take_long(reported: event.Event) void {
    _ = long_router.handle(&app, engine, reported);
}

test "design §8 step 46: a struct route sends sixteen times response_bytes over h3, with loss" {
    try quic_support.start_engine(null);
    try quic_support.connect();
    router = .{};
    app = .{ .stream_len = stream_len, .message_len = message_len, .flush = true };
    quic_support.seen_support.program = take;
    defer quic_support.seen_support.program = null;
    const fetch = try quic_support.request("GET", "/stream", "");
    // Bounded: each round moves time on and moves datagrams both ways.
    for (0..rounds_max) |round| {
        if (fetch.ended) break;
        // RFC 9000 §13.2: the next round's datagrams acknowledge what these lost ones did.
        quic_support.client_mute = round % client_loss_every == 1;
        if (round % server_loss_every == 2) quic_support.server_drop = 1;
        try quic_support.pump(1);
    }
    quic_support.client_mute = false;
    try testing.expect(fetch.ended);
    try testing.expectEqual(ok_code, fetch.status);
    try testing.expect(stream.is_stream(quic_support.content_of(fetch), stream_len));
    // The memory held five messages at once, so the route waited for acknowledgments.
    try testing.expect(app.failed_writes > 0);
    try testing.expectEqual(0, app.roomless_calls);
}

test "design §8 step 46: a struct route flushes 1,000 small messages over h3, acknowledged late" {
    // The owner's ruling of 2026-11-09: an h3 response holds about seven runs until the peer
    // acknowledges them, and the writer has sixteen slots. A flush that finds a run in each slot
    // adds its octets to the newest run the engine has not taken, so no flush fails.
    try quic_support.start_engine(null);
    try quic_support.connect();
    long_router = .{};
    const long_stream_len = stream.varied_stream_len(long_messages);
    app = .{ .stream_len = long_stream_len, .message_len = stream.message_len_max, .varied = true, .flush = true };
    quic_support.seen_support.program = take_long;
    defer quic_support.seen_support.program = null;
    const fetch = try quic_support.request("GET", "/stream", "");
    // Bounded: each round moves time on and moves datagrams both ways.
    for (0..long_rounds_max) |round| {
        if (fetch.ended) break;
        // RFC 9000 §13.2: the client's datagrams of two rounds in three are lost, and the next
        // one that arrives acknowledges what they did.
        quic_support.client_mute = round % client_heard_every != 0;
        try quic_support.pump(1);
    }
    quic_support.client_mute = false;
    try testing.expect(fetch.ended);
    try testing.expectEqual(null, fetch.reset);
    try testing.expectEqual(ok_code, fetch.status);
    try testing.expect(stream.is_stream(quic_support.content_of(fetch), long_stream_len));
    try testing.expectEqual(0, app.failed_flushes);
    // The memory held the octets in flight, so the route waited for acknowledgments.
    try testing.expect(app.failed_writes > 0);
    try testing.expectEqual(0, app.roomless_calls);
}
