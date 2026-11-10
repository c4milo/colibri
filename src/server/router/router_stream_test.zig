//! The tests of a long response through a struct route's `on_writable` (design §8 step 46): the
//! body's writer writes again into memory the engine released, so a response many times longer
//! than `response_bytes` goes out whole and in order, and no run changes before its release.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const constants = @import("../constants.zig");
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
/// Octets of the response memory of a route that flushes each small message, and the messages it
/// writes, of 7 to 128 octets each (the owner's ruling of 2026-11-09).
const long_response_bytes = 8192;
const long_messages = stream.messages_max;
/// The acknowledgments a test gives at most before the response ends: two for each octet.
const acknowledgments_per_octet = 2;
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

const Fixture = FixtureOf(Pool);

/// A router of type `PoolOf` over a `Holder`, and its route's settings.
fn FixtureOf(comptime PoolOf: type) type {
    return struct {
        app: App,
        holder: Holder,
        pool: PoolOf = .{},

        const Self = @This();

        fn start(fixture: *Self) void {
            fixture.handle(.{ .request = support.request_of(1, "GET", "/stream", true) });
        }

        /// Reports the `writable` the engine owes, as a program passes it to the router.
        fn writable(fixture: *Self) void {
            fixture.holder.owed = false;
            fixture.handle(.{ .writable = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.holder.user_data } });
        }

        fn handle(fixture: *Self, received: event.Event) void {
            const handled = fixture.pool.handle(&fixture.app, &fixture.holder, received);
            std.debug.assert(handled == .taken);
        }

        fn response(fixture: *Self) *ResponseWriter {
            return &fixture.pool.entries[0].response;
        }

        /// Acknowledges all of the oldest run but its last octet, then that octet, with a
        /// `writable` after each, as an h3 peer's late acknowledgments free runs, until the
        /// response ends.
        fn acknowledge_late(fixture: *Self) !void {
            // Bounded: each pass acknowledges one octet at least, or the response ended.
            for (0..acknowledgments_per_octet * fixture.app.stream_len) |_| {
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

        /// Requires the whole response, in order, with no held run changed and no request
        /// cancelled.
        fn expect_stream(fixture: *Self) !void {
            try testing.expect(fixture.holder.ended);
            try testing.expect(stream.is_stream(fixture.holder.stream[0..fixture.holder.taken], fixture.app.stream_len));
            try testing.expect(!fixture.holder.overwritten);
            try testing.expectEqual(0, fixture.holder.cancelled);
            try testing.expectEqual(1, fixture.holder.heads);
        }
    };
}

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

test "design §8 step 46: a route writes after a write that failed, and its response still ends" {
    // The sixth message finds no room, so the writer asks the engine for a `writable` at a
    // release. The route then writes one octet, which fits, and flushes it. The engine takes that
    // run whole, which ends the wait it held, so the writer asks again.
    var fixture: Fixture = .{
        .app = .{ .stream_len = stream_len, .message_len = message_len_odd, .flush = true, .octet_after_failure = true },
        .holder = .{ .holds = true },
    };
    fixture.start();
    try testing.expectEqual(5 * message_len_odd + 1, fixture.holder.taken);
    try testing.expectEqual(1, fixture.app.octets_after_failure);
    try testing.expectEqual(2, fixture.holder.release_waits);
    try testing.expect(fixture.holder.owed);
    try testing.expect(writer_internal.waiting(fixture.response()));
    try fixture.acknowledge_late();
    try fixture.expect_stream();
    try testing.expectEqual(0, fixture.app.failed_flushes);
}

test "design §8 step 46: the test engine ends a wait at a write it takes whole, as the engine does" {
    var holder: Holder = .{ .holds = true };
    const id: event.RequestId = @bitCast(@as(u128, 1));
    _ = try holder.write_body(id, .{ .bytes = "ab", .end = false });
    holder.wait_release(id);
    try testing.expect(holder.owed);
    // `State.write_body`: a write that found room ends the wait of its request.
    _ = try holder.write_body(id, .{ .bytes = "c", .end = false });
    try testing.expect(!holder.owed);
}

test "design §8 step 46: a route flushes 1,000 small messages while the engine holds runs" {
    // The owner's ruling of 2026-11-09: the writer has a slot for each of sixteen runs, and the
    // engine holds eight until late acknowledgments. A flush past the sixteenth run adds its
    // octets to the newest run, so no flush fails and the request is not cancelled.
    var fixture: FixtureOf(LongPool) = .{
        .app = .{ .stream_len = stream.varied_stream_len(long_messages), .message_len = stream.message_len_max, .varied = true, .flush = true },
        .holder = .{ .holds = true },
    };
    fixture.start();
    try testing.expectEqual(0, fixture.app.failed_flushes);
    try testing.expectEqual(0, fixture.holder.cancelled);
    // The first call filled the memory. The engine holds eight runs, and eight wait in the
    // writer's other slots: the newest of them holds each message after the sixteenth.
    try testing.expectEqual(1, fixture.app.failed_writes);
    try testing.expectEqual(constants.limits.response_pieces_max, fixture.response().piece_count);
    try fixture.acknowledge_late();
    try fixture.expect_stream();
    try testing.expectEqual(0, fixture.app.failed_flushes);
    try testing.expectEqual(0, fixture.app.roomless_calls);
}

test "design §8 step 46: an engine that copies takes 1,000 flushed messages in one call" {
    // An engine that copies each run and takes all of it leaves no run in a slot, as h11 and h2 do
    // while they have room. So no flush finds a run in every slot, and the route ends in one
    // call, as it did before the ruling of 2026-11-09.
    var fixture: FixtureOf(LongPool) = .{
        .app = .{ .stream_len = stream.varied_stream_len(long_messages), .message_len = stream.message_len_max, .varied = true, .flush = true },
        .holder = .{ .holds = false },
    };
    fixture.start();
    try fixture.expect_stream();
    try testing.expectEqual(1, fixture.app.calls);
    try testing.expectEqual(0, fixture.app.failed_writes);
    try testing.expectEqual(0, fixture.app.failed_flushes);
    try testing.expectEqual(0, fixture.holder.release_waits);
}
