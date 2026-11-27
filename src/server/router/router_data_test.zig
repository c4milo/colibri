//! The tests of a stream route's `on_data` (decision 163 ruling 6, design §8 step 50f), against an
//! engine that records each call. `on_data` reads each piece of the body through the
//! `server.RequestBodyStream`, `keep` joins the end of a piece with the bytes that arrive later, and
//! `ended` says when the body ended. At the body's end, `next` gives the kept bytes as the last
//! piece. Through a wrapper, the router copies kept bytes into the entry's `request_body_bytes`. A route
//! that answered at the head gets no `on_data`. `router_data_engine_test.zig` runs the same routes
//! over h11, h2 and h3.
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
        const handled = fixture.pool.handle(&fixture.app, &fixture.recorder, &received);
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

    /// Lets the app count the pieces that lie in the entry's body memory.
    fn watch_storage(fixture: *Fixture) void {
        fixture.app.storage = &fixture.pool.entries[0].body.held;
    }

    /// The status of the response's head.
    fn status(fixture: *const Fixture) u16 {
        return @intFromEnum(fixture.recorder.heads[0].status);
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
    // A message of three bytes, of which two arrive first, and then a message of one byte.
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
    // The wrapper gives one byte a read, so its buffer joins the kept bytes with each new one.
    fixture.body("\x03a", false);
    try testing.expectEqual(0, fixture.app.message_count);
    fixture.body("bc\x01z", true);
    try testing.expectEqualStrings("abcz", fixture.app.messages.get());
    try testing.expectEqualSlices(usize, &.{ 1, 1 }, fixture.app.message_calls[0..2]);
    try testing.expect(fixture.app.ended_at[1]);
}

test "decision 163 ruling 6: a wrap_body that keeps the router's reader cuts no message and ends the stream" {
    var fixture: Fixture = .{};
    fixture.head("/framed-kept-reader", false);
    // The kept bytes fill the event's bytes, which the router's reader holds, and no wrapper's.
    fixture.body("\x03ab", false);
    try testing.expectEqual(0, fixture.app.message_count);
    fixture.body("c", false);
    try testing.expectEqualStrings("abc", fixture.app.messages.get());
    // Over h11 and h3 the end comes in an event with no bytes.
    fixture.body("", true);
    try testing.expectEqual(3, fixture.app.calls);
    try testing.expect(fixture.app.ended_at[2]);
    try testing.expectEqual(200, @intFromEnum(fixture.recorder.heads[0].status));
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

test "RFC 9110 §15.5.14: a tail kept past request_body_bytes gets 413, and one of request_body_bytes does not" {
    var fixture: Fixture = .{};
    fixture.app.keep_len = data.request_body_bytes;
    fixture.head("/collect", false);
    fixture.body("0123456789abcdef", false);
    try testing.expectEqual(0, fixture.recorder.head_count);
    // The kept bytes and the next one do not fit `request_body_bytes` together.
    fixture.body("!", false);
    try testing.expectEqual(413, @intFromEnum(fixture.recorder.heads[0].status));
    var past: Fixture = .{};
    past.app.keep_len = data.request_body_bytes + 1;
    past.head("/collect", false);
    past.body("0123456789abcdef!", false);
    try testing.expectEqual(413, @intFromEnum(past.recorder.heads[0].status));
    // The router reads no more of the body.
    past.body("x", true);
    try testing.expectEqual(1, past.app.calls);
}

test "decision 163 ruling 6 as amended: kept octets that fill a wrapper's buffer join later octets" {
    var fixture: Fixture = .{};
    fixture.app.keep_len = data.small_buffer_len;
    fixture.head("/collect-wrapped", false);
    // The wrapper's buffer holds four bytes. The route keeps the last four bytes of each piece,
    // and the router joins the fifth byte to four kept ones.
    fixture.body("abc", false);
    fixture.body("de", true);
    try testing.expectEqualStrings("abcde", fixture.app.collected.get());
    try testing.expectEqualStrings("abcd", fixture.first(1));
    // "abcd", "bcde", and at the end "bcde" again as the last piece.
    try testing.expectEqual(3, fixture.app.pieces[1]);
    try testing.expectEqual(200, fixture.status());
}

test "decision 163 ruling 6 as amended: a body with no length is kept whole and read as the last piece" {
    var fixture: Fixture = .{};
    fixture.head("/whole", false);
    fixture.body("ab", false);
    fixture.body("cd", false);
    // Over h11 and h3 the end comes in an event with no bytes.
    fixture.body("", true);
    try testing.expectEqualStrings("abcd", fixture.app.whole.get());
    // The last piece holds no new byte, and its `keep` keeps nothing: `next` then returns null.
    try testing.expectEqual(3, fixture.app.calls);
    try testing.expectEqual(1, fixture.app.pieces[2]);
    try testing.expect(fixture.app.ended_at[2]);
    try testing.expectEqual(200, fixture.status());
}

test "decision 163 ruling 6 as amended: the last piece follows the last DATA frame and a trailer section" {
    var fixture: Fixture = .{};
    fixture.head("/whole", false);
    fixture.body("ab", false);
    // Over h2 the end may come with the last bytes: the piece that joins them, then the last piece.
    fixture.body("cd", true);
    try testing.expectEqualStrings("abcd", fixture.app.whole.get());
    try testing.expectEqual(2, fixture.app.pieces[1]);
    try testing.expect(fixture.app.ended_at[1]);
    var trailed: Fixture = .{};
    trailed.head("/whole", false);
    trailed.body("ab", false);
    const trailers = support.request_of(1, "POST", "/whole", false).headers;
    trailed.handle(.{ .trailers = .{ .id = @bitCast(@as(u128, 1)), .user_data = trailed.recorder.user_data, .headers = trailers } });
    try testing.expectEqualStrings("ab", trailed.app.whole.get());
    try testing.expectEqual(1, trailed.app.pieces[1]);
    try testing.expect(trailed.app.ended_at[1]);
}

test "RFC 9110 §15.5.14: a last piece past request_body_bytes gets 413, and one of request_body_bytes does not" {
    var fixture: Fixture = .{};
    fixture.head("/whole", false);
    // The end comes with the bytes, so the router holds none of them.
    fixture.body("0123456789abcdef!", true);
    try testing.expectEqual(413, fixture.status());
    try testing.expectEqual(1, fixture.app.pieces[0]);
    var fits: Fixture = .{};
    fits.head("/whole", false);
    fits.body("0123456789abcdef", true);
    try testing.expectEqualStrings("0123456789abcdef", fits.app.whole.get());
    try testing.expectEqual(200, fits.status());
    var held: Fixture = .{};
    held.head("/whole", false);
    held.body("01234567", false);
    held.body("89abcdef!", false);
    try testing.expectEqual(413, held.status());
}

test "decision 163 ruling 6 as amended: a long keep through a wrapper that keeps a window is read whole" {
    // The wrapper's `rebase` asserts, as std's flate decompressor does, that it holds no more than
    // its buffer of eight bytes less its window of four. The message of seven bytes is longer.
    var fixture: Fixture = .{};
    fixture.head("/framed-windowed", false);
    fixture.body("\x01a\x07bcd", false);
    fixture.body("efgh", true);
    try testing.expectEqualStrings("abcdefgh", fixture.app.messages.get());
    try testing.expectEqual(200, fixture.status());
    var whole: Fixture = .{};
    whole.head("/whole-windowed", false);
    whole.body("abcdef", false);
    whole.body("ghijkl", false);
    whole.body("", true);
    try testing.expectEqualStrings("abcdefghijkl", whole.app.whole.get());
    try testing.expectEqual(200, whole.status());
}

test "decision 163 ruling 6 as amended: through a wrapper, the router copies a piece only after a keep" {
    var fixture: Fixture = .{};
    fixture.watch_storage();
    fixture.head("/framed-wrapped", false);
    fixture.body("\x03a", false);
    fixture.body("bc\x01z", true);
    try testing.expectEqualStrings("abcz", fixture.app.messages.get());
    // "\x03", then "\x03a" joined after a keep.
    try testing.expectEqual(2, fixture.app.pieces[0]);
    try testing.expectEqual(1, fixture.app.copies[0]);
    // "\x03ab" and "\x03abc" joined, "\x01" after a keep(0) with no copy, and "\x01z" joined.
    try testing.expectEqual(4, fixture.app.pieces[1]);
    try testing.expectEqual(3, fixture.app.copies[1]);
    var none: Fixture = .{};
    none.watch_storage();
    none.head("/collect-wrapped", false);
    none.body("abc", true);
    try testing.expectEqualStrings("abc", none.app.collected.get());
    try testing.expectEqual(0, none.app.copies[0]);
}

test "decision 163 ruling 6 as amended: through a wrapper, the end of a stored piece outlives on_data" {
    // Two pieces a call: the second is "ab", joined after a keep, and the route keeps "b" of it.
    var fixture: Fixture = .{};
    fixture.app.keep_len = 1;
    fixture.app.pieces_per_call = 2;
    fixture.head("/collect-wrapped", false);
    fixture.body("abcd", false);
    try testing.expectEqualStrings("ab", fixture.app.collected.get());
    // The next call starts with the kept "b", joined with "c" from the bytes the router held.
    fixture.body("ef", false);
    try testing.expectEqualStrings("bc", fixture.first(1));
    try testing.expectEqualStrings("abcd", fixture.app.collected.get());
}

test "RFC 9110 §15.5.14: through a wrapper, kept octets past request_body_bytes get 413" {
    var fixture: Fixture = .{};
    fixture.head("/whole-windowed", false);
    fixture.body("01234567", false);
    try testing.expectEqual(0, fixture.recorder.head_count);
    // Sixteen kept bytes fill `request_body_bytes`, and the seventeenth joins none.
    fixture.body("89abcdef!", false);
    try testing.expectEqual(413, fixture.status());
    var fits: Fixture = .{};
    fits.head("/whole-windowed", false);
    fits.body("01234567", false);
    fits.body("89abcdef", true);
    try testing.expectEqualStrings("0123456789abcdef", fits.app.whole.get());
    // A wrapper that gives more bytes a read than `request_body_bytes` holds: the route keeps seventeen.
    var batched: Fixture = .{};
    batched.app.keep_len = data.request_body_bytes + 1;
    batched.head("/collect-batched", false);
    batched.body("0123456789abcdefghij", false);
    try testing.expectEqual(413, batched.status());
}

test "RFC 9110 §15.5.14: through a wrapper, kept octets and the octets the router holds share request_body_bytes" {
    // One piece a call leaves the router's bytes unread: they wait beside the kept ones.
    var fixture: Fixture = .{};
    fixture.app.keep_len = data.request_body_bytes;
    fixture.app.pieces_per_call = 1;
    fixture.head("/collect-wrapped", false);
    fixture.body("abcd", false);
    fixture.body("efghijklmno", false);
    try testing.expectEqualStrings("ab", fixture.first(1));
    try testing.expectEqual(0, fixture.recorder.head_count);
    // Two kept bytes, thirteen unread and two new pass sixteen.
    fixture.body("pq", false);
    try testing.expectEqual(413, fixture.status());
    var at_once: Fixture = .{};
    at_once.app.keep_len = data.request_body_bytes;
    at_once.app.pieces_per_call = 1;
    at_once.head("/collect-wrapped", false);
    // One kept byte and sixteen unread pass sixteen once `on_data` returns.
    at_once.body("0123456789abcdef!", false);
    try testing.expectEqual(413, at_once.status());
    // Three pieces a call: the joined piece grows toward the router's bytes, and stops at them.
    var grows: Fixture = .{};
    grows.app.keep_len = data.request_body_bytes;
    grows.app.pieces_per_call = 3;
    grows.head("/collect-wrapped", false);
    grows.body("abcdefgh", false);
    try testing.expectEqual(0, grows.recorder.head_count);
    // Five kept bytes and eleven held fill sixteen, so the sixth byte joins none.
    grows.body("ijklmn", false);
    try testing.expectEqual(413, grows.status());
    try testing.expectEqualStrings("abcde", grows.app.collected.get());
}

test "decision 163 ruling 6: a route that ended its response in on_request gets no on_data" {
    var fixture: Fixture = .{};
    fixture.head("/refused", false);
    try testing.expectEqual(403, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expect(fixture.recorder.ended);
    // The router drops the body, more than `request_body_bytes` of it too.
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
    try testing.expectEqualStrings("made", fixture.recorder.request_body_bytes());
    try testing.expect(fixture.recorder.ended);
}

test "decision 163 ruling 6 as amended: a route that keeps part of a piece and returns reads the rest once" {
    // The route takes one piece a call and keeps its last byte, so each call returns before
    // `next` gives null. The router lets go of the rest of the piece, through each kind of reader.
    for ([_][]const u8{ "/collect-batched", "/collect-kept-reader" }) |target| {
        var fixture: Fixture = .{};
        fixture.app.pieces_per_call = 1;
        fixture.app.keep_len = 1;
        fixture.head(target, false);
        fixture.body("abcd", false);
        fixture.body("ef", true);
        try testing.expectEqualStrings("abcdef", fixture.app.collected.get());
    }
}
