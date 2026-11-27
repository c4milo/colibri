//! The tests of the router's answers with no entry that wait for room in the engine (design §8
//! step 53), against the engine of `router_handle_test_support.zig`, which refuses a head when a
//! test tells it to. A slot names its request by its id, so each event of the tests carries the
//! word 0.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const Response = @import("../response/response.zig").Response;
const RequestContext = @import("../request_context.zig").RequestContext;
const Router = @import("router.zig").Router;
const support = @import("router_handle_test_support.zig");

const testing = std.testing;

const App = struct {};

fn hold(_: *App, _: *RequestContext, _: *const event.Request, response: *Response) !void {
    try response.body().writeAll("held");
    try response.end();
}

fn on_error(_: *App, _: *RequestContext, _: *const event.Request, _: anyerror, response: *Response) void {
    response.status = .internal_server_error;
}

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/held", hold },
        .{ .post, "/held", hold },
        // Another path names DELETE, so a DELETE of `/held` gets 405, and not 501.
        .{ .delete, "/other", hold },
    },
};

/// A pool of two entries, so it has two slots for the answers that wait, and bytes of each
/// entry's response memory. Test-only.
const requests = 2;
const response_buffer_bytes = 64;
const Pool = Router(App, routes, .{ .requests = requests, .response_buffer_bytes = response_buffer_bytes, .request_body_bytes = 0, .request_header_bytes = 0 });

const Fixture = struct {
    app: App = .{},
    recorder: support.Recorder = .{},
    pool: Pool = .{},
    number: u64 = 0,

    /// Hands the router the head of a request, and returns its id and the word the router set,
    /// which is 0 for a request with no entry.
    fn request(fixture: *Fixture, method: []const u8, target: []const u8) event.Writable {
        fixture.number += 1;
        fixture.recorder.user_data = 0;
        const head = support.request_of(fixture.number, method, target, true);
        std.debug.assert(fixture.pool.handle(&fixture.app, &fixture.recorder, &.{ .request = head }) == .taken);
        return .{ .id = head.id, .user_data = fixture.recorder.user_data };
    }

    fn writable(fixture: *Fixture, of: event.Writable) void {
        std.debug.assert(fixture.pool.handle(&fixture.app, &fixture.recorder, &.{ .writable = of }) == .taken);
    }

    fn finished(fixture: *Fixture, of: event.Writable, result: event.Result) void {
        const done: event.Finished = .{ .id = of.id, .user_data = of.user_data, .result = result };
        std.debug.assert(fixture.pool.handle(&fixture.app, &fixture.recorder, &.{ .finished = done }) == .taken);
    }

    /// The answers that wait: the slots in use, which the pool's count must equal.
    fn waiting(fixture: *const Fixture) usize {
        var count: usize = 0;
        for (fixture.pool.answers.slots) |slot| count += @intFromBool(slot.used);
        std.debug.assert(count == fixture.pool.answers.used);
        return count;
    }
};

test "design §8 step 53: a 404 that the engine has no room for waits for its writable" {
    var fixture: Fixture = .{};
    fixture.recorder.head_blocked = true;
    const missing = fixture.request("GET", "/missing");
    // The head found no room: the request is not cancelled, and a slot names it by its id. Its
    // word stays 0, as that of each request with no entry.
    try testing.expectEqual(0, fixture.recorder.cancelled);
    try testing.expectEqual(0, fixture.recorder.head_count);
    try testing.expectEqual(0, missing.user_data);
    try testing.expectEqual(1, fixture.waiting());
    // A `writable` with no room yet writes nothing and cancels nothing.
    fixture.writable(missing);
    try testing.expectEqual(0, fixture.recorder.head_count);
    try testing.expectEqual(0, fixture.recorder.cancelled);
    fixture.recorder.head_blocked = false;
    fixture.writable(missing);
    try testing.expectEqual(1, fixture.recorder.head_count);
    try testing.expectEqual(404, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expect(fixture.recorder.ended);
    // The request's `finished` frees the slot.
    fixture.finished(missing, .sent);
    try testing.expectEqual(0, fixture.waiting());
}

test "RFC 9110 §15.5.6: a 405 that waits keeps its Allow value, and a 501 that waits has none" {
    var fixture: Fixture = .{};
    fixture.recorder.head_blocked = true;
    const refused = fixture.request("DELETE", "/held");
    const unknown = fixture.request("PATCH", "/held");
    try testing.expectEqual(requests, fixture.waiting());
    fixture.recorder.head_blocked = false;
    // The second answer goes first: each `writable` writes the answer of its own request.
    fixture.writable(unknown);
    fixture.writable(refused);
    try testing.expectEqual(501, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqual(0, fixture.recorder.heads[0].headers.len);
    try testing.expectEqual(405, @intFromEnum(fixture.recorder.heads[1].status));
    try testing.expectEqualStrings("GET, HEAD, POST", fixture.recorder.allow[1]);
}

test "RFC 9110 §15.6.4: a 503 that the engine has no room for waits too" {
    var fixture: Fixture = .{};
    // No body byte goes, so both entries stay in use.
    fixture.recorder.room = 0;
    _ = fixture.request("GET", "/held");
    _ = fixture.request("GET", "/held");
    fixture.recorder.head_blocked = true;
    const third = fixture.request("GET", "/held");
    try testing.expectEqual(0, fixture.recorder.cancelled);
    fixture.recorder.head_blocked = false;
    fixture.writable(third);
    try testing.expectEqual(503, @intFromEnum(fixture.recorder.heads[2].status));
}

test "design §8 step 53: with an answer in each slot, one more request is cancelled" {
    var fixture: Fixture = .{};
    fixture.recorder.head_blocked = true;
    const first = fixture.request("GET", "/a");
    _ = fixture.request("GET", "/b");
    try testing.expectEqual(0, fixture.recorder.cancelled);
    _ = fixture.request("GET", "/c");
    try testing.expectEqual(1, fixture.recorder.cancelled);
    try testing.expectEqual(requests, fixture.waiting());
    // A request that ends while its answer waits frees its slot for the next one.
    fixture.finished(first, .{ .cancelled = .peer_reset });
    try testing.expectEqual(requests - 1, fixture.waiting());
    _ = fixture.request("GET", "/d");
    try testing.expectEqual(1, fixture.recorder.cancelled);
    try testing.expectEqual(requests, fixture.waiting());
}

test "design §8 step 53: an error of the engine other than no room cancels the request" {
    var fixture: Fixture = .{};
    fixture.recorder.head_failure = error.SectionTooLarge;
    _ = fixture.request("GET", "/missing");
    try testing.expectEqual(1, fixture.recorder.cancelled);
    try testing.expectEqual(0, fixture.waiting());
    // The same error on a `writable` cancels the request that waited.
    fixture.recorder.head_failure = null;
    fixture.recorder.head_blocked = true;
    const waits = fixture.request("GET", "/missing");
    fixture.recorder.head_failure = error.SectionTooLarge;
    fixture.writable(waits);
    try testing.expectEqual(2, fixture.recorder.cancelled);
}

test "design §8 step 53: the body of a request whose answer waits goes to no entry" {
    var fixture: Fixture = .{};
    fixture.recorder.head_blocked = true;
    const missing = fixture.request("POST", "/missing");
    const body: event.RequestBody = .{ .id = missing.id, .user_data = missing.user_data, .bytes = "dropped", .end = true };
    try testing.expect(fixture.pool.handle(&fixture.app, &fixture.recorder, &.{ .body = body }) == .taken);
    try testing.expectEqual(0, fixture.recorder.cancelled);
    try testing.expectEqual(1, fixture.waiting());
}

test "design §8 step 53: an event of another request with no entry touches no answer that waits" {
    var fixture: Fixture = .{};
    fixture.recorder.head_blocked = true;
    const waits = fixture.request("GET", "/missing");
    fixture.recorder.head_blocked = false;
    // This 404 finds room, so it goes at once and takes no slot.
    const answered = fixture.request("GET", "/gone");
    try testing.expectEqual(1, fixture.recorder.head_count);
    fixture.writable(answered);
    try testing.expectEqual(1, fixture.recorder.head_count);
    fixture.finished(answered, .sent);
    try testing.expectEqual(1, fixture.waiting());
    fixture.writable(waits);
    try testing.expectEqual(1 + 1, fixture.recorder.head_count);
}
