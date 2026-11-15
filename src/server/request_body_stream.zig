//! `server.RequestBodyStream`: the stream of a request's body, which a stream route's `on_data`
//! reads (decision 163 ruling 6, design §8 step 50f). The root exports it as
//! `server.RequestBodyStream`. It holds no header: the body is the request's payload.
//!
//! `next` gives each piece of the body that has arrived, with no copy, from the reader of the
//! body: the router's, or the last wrapper of a middleware's `wrap_body`. A reader cannot say that
//! no piece waits yet, so `next` returns null then. `keep` leaves the end of a piece unread. The
//! next call of `next`, in this `on_data` or in a later one, gives those octets again, joined with
//! the octets that arrive after them. So a route reads a message that two events cut, as Connect
//! and gRPC frame theirs.
const std = @import("std");
const assert = std.debug.assert;

/// The stream of one request's body. The router places one in the request's entry, and passes a
/// pointer to it to each `on_data`. A program never makes one, and keeps no pointer to it, or to
/// a piece, after `on_data` returns.
pub const RequestBodyStream = struct {
    // Each field is colibri's. A program reads none of them.
    /// The reader of the body: the router's, over the octets of the event and the octets it held,
    /// or the last wrapper of a middleware's `wrap_body`.
    reader: *std.Io.Reader,
    /// Octets at the reader's seek that `next` gave last, and the octets at their end that `keep`
    /// kept.
    given: usize = 0,
    kept: usize = 0,
    /// Whether the reader is a middleware's wrapper. Its buffer holds the kept octets, and must
    /// hold one more octet to join them with the octets that arrive later.
    wrapped: bool = false,
    /// Whether `next` found the body's end.
    at_end: bool = false,

    /// The next piece of the body that has arrived, or null when no piece waits now. Each call
    /// first lets go of the piece it gave before, less the octets that `keep` kept. A piece that
    /// follows a `keep` starts with the kept octets. A piece stays valid until the next call of
    /// `next`, or until `on_data` returns.
    ///
    /// Through a middleware's wrapper, a piece holds at most the octets of the wrapper's buffer.
    /// A null at the body's end makes `ended` true.
    pub fn next(stream: *RequestBodyStream) ?[]const u8 {
        const reader = stream.reader;
        reader.toss(stream.given - stream.kept);
        stream.given = stream.kept;
        // A wrapper's buffer that the kept octets fill has no room for one more octet.
        if (stream.wrapped and stream.kept >= reader.buffer.len) return null;
        // One octet past the kept ones: a piece holds at least one octet that is new.
        const piece = reader.peekGreedy(stream.kept + 1) catch |failure| {
            if (failure == error.EndOfStream) stream.at_end = true;
            return null;
        };
        assert(piece.len > stream.kept);
        stream.given = piece.len;
        stream.kept = 0;
        return piece;
    }

    /// Leaves the last `len` octets of the piece that `next` gave last unread. The next call of
    /// `next`, in this `on_data` or in a later one, starts with them, joined with the octets that
    /// arrive later. A later `keep` takes the place of an earlier one, and `keep(0)` keeps none.
    ///
    /// The router copies the kept octets into the request's entry when they outlive the engine's
    /// event. More than `body_bytes` octets there get 413 (RFC 9110 §15.5.14). Through a
    /// middleware's wrapper, kept octets that fill its buffer get 413 too.
    pub fn keep(stream: *RequestBodyStream, len: usize) void {
        assert(len <= stream.given);
        stream.kept = len;
    }

    /// Whether the body ended and `next` gave every piece of it. It turns true when `next`
    /// returns null at the body's end.
    ///
    /// A route never relies on `ended` at its last piece. Over h2 the end may come with the last
    /// piece, on a DATA frame with END_STREAM. Over h11 and h3 the end comes in a later event with
    /// no octets, and the router calls `on_data` again for it.
    pub fn ended(stream: *const RequestBodyStream) bool {
        return stream.at_end;
    }
};

test "decision 163 ruling 6: RequestBodyStream exports next, keep and ended" {
    try @import("core").public_names.expect(RequestBodyStream, &.{ "next", "keep", "ended" });
}

const testing = std.testing;
const router_body = @import("router/router_body.zig");

/// A stream over the router's reader, and the octets of each event. Test-only.
const Fixture = struct {
    body: router_body.Body(body_bytes) = .{},
    stream: RequestBodyStream = undefined,

    const body_bytes = 16;

    fn start(fixture: *Fixture) void {
        fixture.stream = .{ .reader = &fixture.body.cursor.reader };
    }

    /// Points the reader at `bytes`, after any octets held, as the router does at a body event.
    fn give(fixture: *Fixture, bytes: []const u8, end: bool) !void {
        fixture.body.cursor.ended = end;
        if (fixture.body.held_len > 0) try fixture.body.append(bytes);
        _ = fixture.body.reader_over(bytes);
    }
};

test "decision 163 ruling 6: next gives each piece once, and null when none waits" {
    var fixture: Fixture = .{};
    fixture.start();
    try fixture.give("abc", false);
    try testing.expectEqualStrings("abc", fixture.stream.next().?);
    try testing.expectEqual(null, fixture.stream.next());
    try testing.expect(!fixture.stream.ended());
}

test "decision 163 ruling 6: keep joins the kept octets with the next piece" {
    var fixture: Fixture = .{};
    fixture.start();
    try fixture.give("abcd", false);
    try testing.expectEqualStrings("abcd", fixture.stream.next().?);
    fixture.stream.keep(2);
    // No octet arrived after the kept ones, so no piece waits.
    try testing.expectEqual(null, fixture.stream.next());
    // A later `keep` takes the place of the earlier one.
    fixture.stream.keep(1);
    try testing.expectEqual(null, fixture.stream.next());
    try testing.expectEqual(1, fixture.stream.given);
}

test "decision 163 ruling 6: keep(0) keeps nothing" {
    var fixture: Fixture = .{};
    fixture.start();
    try fixture.give("ab", true);
    try testing.expectEqualStrings("ab", fixture.stream.next().?);
    fixture.stream.keep(0);
    try testing.expectEqual(null, fixture.stream.next());
    try testing.expect(fixture.stream.ended());
}

test "decision 163 ruling 6: ended turns true only when next finds the end" {
    var fixture: Fixture = .{};
    fixture.start();
    try fixture.give("ab", true);
    try testing.expect(!fixture.stream.ended());
    _ = fixture.stream.next();
    try testing.expect(!fixture.stream.ended());
    try testing.expectEqual(null, fixture.stream.next());
    try testing.expect(fixture.stream.ended());
}

test "decision 163 ruling 6: a wrapper's buffer that kept octets fill gives no piece" {
    var bytes = "abcd".*;
    var reader: std.Io.Reader = .fixed(&bytes);
    var stream: RequestBodyStream = .{ .reader = &reader, .wrapped = true };
    try testing.expectEqualStrings("abcd", stream.next().?);
    stream.keep(4);
    // The buffer holds four octets, so it has no room to join a fifth to them.
    try testing.expectEqual(null, stream.next());
    try testing.expect(!stream.ended());
}
