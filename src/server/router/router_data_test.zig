//! The tests of a stream route's `on_data` (decision 163 ruling 6, design §8 step 50f), against an
//! engine that records each call. `on_data` reads each piece of the body through the
//! `server.RequestBodyStream`, `keep` joins the end of a piece with the octets that arrive later, and
//! `ended` says when the body ended. A route that answered at the head gets no `on_data`.
//! `router_data_engine_test.zig` runs the same routes over h11, h2 and h3.
const std = @import("std");
const event = @import("../event.zig");
const support = @import("router_handle_test_support.zig");
const data = @import("router_data_test_support.zig");

const testing = std.testing;
const Recorder = support.Recorder;

const Fixture = struct {
    app: data.App = .{},
    recorder: Recorder = .{},
    pool: data.Pool = .{},

    fn handle(fixture: *Fixture, received: event.Event) void {
        const handled = fixture.pool.handle(&fixture.app, &fixture.recorder, received);
        std.debug.assert(handled == .taken);
    }

    fn head(fixture: *Fixture, target: []const u8, end: bool) void {
        fixture.handle(.{ .request = support.request_of(1, "POST", target, end) });
    }

    fn body(fixture: *Fixture, bytes: []const u8, end: bool) void {
        fixture.handle(.{ .body = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.recorder.user_data, .bytes = bytes, .end = end } });
    }

    /// The first piece that call `call` of `on_data` got.
    fn first(fixture: *const Fixture, call: usize) []const u8 {
        return fixture.app.firsts[call].get();
    }
};

test "decision 163 ruling 6: on_data reads every piece of a body of three events, and ended turns true" {
    var fixture: Fixture = .{};
    fixture.head("/collect", false);
    fixture.body("ab", false);
    fixture.body("cd", false);
    try testing.expect(!fixture.recorder.ended);
    fixture.body("ef", true);
    try testing.expectEqual(3, fixture.app.calls);
    try testing.expectEqualStrings("abcdef", fixture.app.collected.get());
    try testing.expectEqualStrings("cd", fixture.first(1));
    try testing.expectEqual(1, fixture.app.pieces[1]);
    try testing.expectEqualSlices(bool, &.{ false, false, true }, fixture.app.ended_at[0..3]);
    // The router ends the response the route left open once the body ended.
    try testing.expect(fixture.recorder.ended);
    try testing.expectEqual(200, @intFromEnum(fixture.recorder.heads[0].status));
}

test "decision 163 ruling 6: a trailer section ends the stream" {
    var fixture: Fixture = .{};
    fixture.head("/collect", false);
    fixture.body("ab", false);
    const trailers = support.request_of(1, "POST", "/collect", false).headers;
    fixture.handle(.{ .trailers = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.recorder.user_data, .headers = trailers } });
    try testing.expectEqual(2, fixture.app.calls);
    try testing.expectEqual(0, fixture.app.pieces[1]);
    try testing.expect(fixture.app.ended_at[1]);
}

test "decision 163 ruling 6: a message that two events cut is read whole in the second on_data" {
    var fixture: Fixture = .{};
    fixture.head("/framed", false);
    // A message of three octets, of which two arrive first, and then a message of one octet.
    fixture.body("\x03ab", false);
    try testing.expectEqual(0, fixture.app.message_count);
    fixture.body("c\x01z", false);
    try testing.expectEqualStrings("abcz", fixture.app.messages.get());
    try testing.expectEqual(2, fixture.app.message_count);
    try testing.expectEqualSlices(usize, &.{ 1, 1 }, fixture.app.message_calls[0..2]);
    fixture.body("", true);
    try testing.expect(fixture.app.ended_at[2]);
}

test "decision 163 ruling 6: a message that two events cut is read whole through a wrapper" {
    var fixture: Fixture = .{};
    fixture.head("/framed-wrapped", false);
    // The wrapper gives one octet a read, so its buffer joins the kept octets with each new one.
    fixture.body("\x03a", false);
    try testing.expectEqual(0, fixture.app.message_count);
    fixture.body("bc\x01z", true);
    try testing.expectEqualStrings("abcz", fixture.app.messages.get());
    try testing.expectEqualSlices(usize, &.{ 1, 1 }, fixture.app.message_calls[0..2]);
    try testing.expect(fixture.app.ended_at[1]);
}

test "decision 163 ruling 6: the kept octets start the next on_data's first piece" {
    var fixture: Fixture = .{};
    fixture.app.keep_len = 3;
    fixture.head("/collect", false);
    fixture.body("abcde", false);
    fixture.body("fg", true);
    try testing.expectEqualStrings("cdefg", fixture.first(1));
    try testing.expectEqualStrings("abcdefg", fixture.app.collected.get());
}

test "decision 163 ruling 6: keep(0) keeps nothing" {
    var fixture: Fixture = .{};
    fixture.app.keep_len = 3;
    fixture.app.keep_none = true;
    fixture.head("/collect", false);
    fixture.body("abcde", false);
    fixture.body("fg", true);
    try testing.expectEqualStrings("fg", fixture.first(1));
    try testing.expectEqualStrings("abcdefg", fixture.app.collected.get());
}

test "RFC 9110 §15.5.14: a tail kept past body_bytes gets 413, and one of body_bytes does not" {
    var fixture: Fixture = .{};
    fixture.app.keep_len = data.body_bytes;
    fixture.head("/collect", false);
    fixture.body("0123456789abcdef", false);
    try testing.expectEqual(0, fixture.recorder.head_count);
    // The kept octets and the next one do not fit `body_bytes` together.
    fixture.body("!", false);
    try testing.expectEqual(413, @intFromEnum(fixture.recorder.heads[0].status));
    var past: Fixture = .{};
    past.app.keep_len = data.body_bytes + 1;
    past.head("/collect", false);
    past.body("0123456789abcdef!", false);
    try testing.expectEqual(413, @intFromEnum(past.recorder.heads[0].status));
    // The router reads no more of the body.
    past.body("x", true);
    try testing.expectEqual(1, past.app.calls);
}

test "RFC 9110 §15.5.14: kept octets that fill a wrapper's buffer get 413" {
    var fixture: Fixture = .{};
    fixture.app.keep_len = data.small_buffer_len;
    fixture.head("/collect-wrapped", false);
    // The wrapper's buffer holds four octets. The route keeps each octet, so the fourth fills it.
    fixture.body("abc", false);
    try testing.expectEqual(0, fixture.recorder.head_count);
    fixture.body("de", false);
    try testing.expectEqual(413, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqualStrings("abcd", fixture.app.collected.get());
}

test "decision 163 ruling 6: a route that ended its response in on_request gets no on_data" {
    var fixture: Fixture = .{};
    fixture.head("/refused", false);
    try testing.expectEqual(403, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expect(fixture.recorder.ended);
    // The router drops the body, more than `body_bytes` of it too.
    fixture.body("0123456789abcdef!", false);
    fixture.body("x", true);
    try testing.expectEqual(0, fixture.app.calls);
    try testing.expectEqual(1, fixture.recorder.head_count);
    try testing.expectEqual(0, fixture.recorder.cancelled);
}

test "decision 163 ruling 6: a route with on_request alone gets no on_data, and its response ends with the body" {
    var fixture: Fixture = .{};
    fixture.head("/head-only", false);
    fixture.body("0123456789abcdef!", false);
    try testing.expectEqual(0, fixture.recorder.head_count);
    fixture.body("x", true);
    try testing.expectEqual(202, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqualStrings("head", fixture.recorder.heads[0].headers[0].value);
    try testing.expect(fixture.recorder.ended);
}

test "decision 163 ruling 6: a stream route's response sends its status, its headers and a middleware's" {
    var fixture: Fixture = .{};
    fixture.head("/created", false);
    fixture.body("made", true);
    const head = fixture.recorder.heads[0];
    try testing.expectEqual(201, @intFromEnum(head.status));
    // `Brand` wrote its header into the response before `on_request` wrote its own.
    try testing.expectEqualStrings("server", head.headers[0].name);
    try testing.expectEqualStrings("x-kind", head.headers[1].name);
    try testing.expectEqualStrings("stream", head.headers[1].value);
    try testing.expectEqualStrings("made", fixture.recorder.body_bytes());
    try testing.expect(fixture.recorder.ended);
}
