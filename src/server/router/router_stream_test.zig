//! The tests of a long response through a struct route's `on_writable` (design §8 step 46): the
//! body's writer writes again into memory the engine released, so a response many times longer
//! than `response_bytes` goes out whole and in order, and no run changes before its release.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const writer_internal = @import("../response_writer/response_writer_internal.zig");
const Router = @import("router.zig").Router;
const support = @import("router_handle_test_support.zig");
const stream = @import("router_stream_test_support.zig");

const testing = std.testing;
const App = stream.App;
const Holder = stream.Holder;

/// Octets of the entry's response memory, and of the response: sixteen times as many. Test-only.
const response_bytes = 128;
const stream_turns = 16;
const stream_len = stream_turns * response_bytes;
/// A message that does not divide the memory, so a write finds a region too short for it, and
/// one that divides it, so the writer fills its region exactly.
const message_len_odd = 24;
const message_len_even = 32;
/// The acknowledgments a test gives at most before the response ends: two for each octet.
const acknowledgments_per_octet = 2;
const rounds_max = acknowledgments_per_octet * stream_len;
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

const Fixture = struct {
    app: App,
    holder: Holder,
    pool: Pool = .{},

    fn start(fixture: *Fixture) void {
        fixture.handle(.{ .request = support.request_of(1, "GET", "/stream", true) });
    }

    /// Reports the `writable` the engine owes, as a program passes it to the router.
    fn writable(fixture: *Fixture) void {
        fixture.holder.owed = false;
        fixture.handle(.{ .writable = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.holder.user_data } });
    }

    fn handle(fixture: *Fixture, received: event.Event) void {
        const handled = fixture.pool.handle(&fixture.app, &fixture.holder, received);
        std.debug.assert(handled == .taken);
    }

    fn response(fixture: *Fixture) *ResponseWriter {
        return &fixture.pool.entries[0].response;
    }

    /// Acknowledges all of the oldest run but its last octet, then that octet, with a `writable`
    /// after each, as an h3 peer's late acknowledgments free runs, until the response ends.
    fn acknowledge_late(fixture: *Fixture) !void {
        // Bounded: each pass acknowledges one octet at least, or the response ended.
        for (0..rounds_max) |_| {
            if (fixture.holder.ended) return;
            const oldest = fixture.holder.oldest_len();
            if (oldest == 0) return error.TestExpectedHeldRun;
            fixture.holder.acknowledge(oldest - 1);
            if (fixture.holder.owed) fixture.writable();
            fixture.holder.acknowledge(1);
            if (fixture.holder.owed) fixture.writable();
        }
        return error.TestExpectedEnd;
    }

    /// Requires the whole response, in order, with no held run changed and no request cancelled.
    fn expect_stream(fixture: *Fixture) !void {
        try testing.expect(fixture.holder.ended);
        try testing.expect(stream.is_stream(fixture.holder.stream[0..fixture.holder.taken], stream_len));
        try testing.expect(!fixture.holder.overwritten);
        try testing.expectEqual(0, fixture.holder.cancelled);
        try testing.expectEqual(1, fixture.holder.heads);
    }
};

test "design §8 step 46: an engine that copies takes sixteen times response_bytes through body()" {
    // h11 and h2 copy each run inside `write_body`, so the writer writes over it at once.
    var fixture: Fixture = .{
        .app = .{ .stream_len = stream_len, .message_len = message_len_odd },
        .holder = .{ .holds = false },
    };
    fixture.start();
    try fixture.expect_stream();
    try testing.expectEqual(1, fixture.app.calls);
    try testing.expectEqual(0, fixture.app.failed_writes);
    try testing.expectEqual(0, fixture.holder.release_waits);
}

test "design §8 step 46: over an engine that holds runs, writes wait for late acknowledgments" {
    var fixture: Fixture = .{
        .app = .{ .stream_len = stream_len, .message_len = message_len_odd, .flush = true },
        .holder = .{ .holds = true },
    };
    fixture.start();
    // The memory holds five messages and three octets more: the sixth fits nowhere, so it is
    // not written, and the writer waits for the engine to release a run.
    try testing.expectEqual(5 * message_len_odd, fixture.holder.taken);
    try testing.expectEqual(1, fixture.app.failed_writes);
    try testing.expectEqual(1, fixture.holder.release_waits);
    try testing.expect(writer_internal.waiting(fixture.response()));
    try testing.expectEqual(0, fixture.holder.cancelled);
    try fixture.acknowledge_late();
    try fixture.expect_stream();
    try testing.expectEqual(0, fixture.app.roomless_calls);
}

test "design §8 step 46: the router calls on_writable only when the writer has room" {
    var fixture: Fixture = .{
        .app = .{ .stream_len = stream_len, .message_len = message_len_even, .flush = true },
        .holder = .{ .holds = true },
    };
    fixture.start();
    // Four messages fill the memory exactly, and the engine holds each.
    try testing.expectEqual(response_bytes, fixture.holder.taken);
    try testing.expectEqual(1, fixture.app.calls);
    // A `writable` that released nothing finds no room: the route is not called, and the writer
    // waits again.
    fixture.writable();
    try testing.expectEqual(1, fixture.app.calls);
    try testing.expectEqual(2, fixture.holder.release_waits);
    try testing.expectEqual(0, fixture.holder.cancelled);
    try fixture.acknowledge_late();
    try fixture.expect_stream();
    try testing.expectEqual(0, fixture.app.roomless_calls);
}
