//! `server.RequestBodyStream`: the stream of a request's body, which a stream route's `on_data`
//! reads (decision 163 ruling 6, design §8 step 50f). The root exports it as
//! `server.RequestBodyStream`. It holds no header: the body is the request's payload.
//!
//! `next` gives each piece of the body that has arrived, with no copy, from the reader of the
//! body: the router's, or the last wrapper of a middleware's `wrap_body`. A reader cannot say that
//! no piece waits yet, so `next` returns null then. `keep` leaves the end of a piece unread. The
//! next call of `next`, in this `on_data` or in a later one, gives those bytes again, joined with
//! the bytes that arrive after them. So a route reads a message that two events cut, as Connect
//! and gRPC frame theirs. At the body's end, `next` gives the kept bytes once more as the last
//! piece, so a route reads a body with no length whole, as Connect's unary call sends it.
//!
//! Through a wrapper, `next` copies the kept bytes into the entry's `request_body_bytes`, and joins the
//! bytes that the wrapper gives later there (decision 163 ruling 6 as amended). So it asks a
//! wrapper for one byte past those it gave, never more. A wrapper's `rebase` may hold fewer
//! bytes than its buffer, as std's flate decompressor does, which keeps its window there. A
//! piece that follows no `keep` stays in the wrapper's buffer, with no copy.
const std = @import("std");
const assert = std.debug.assert;

/// The stream of one request's body. The router places one in the request's entry, and passes a
/// pointer to it to each `on_data`. A program never makes one, and keeps no pointer to it, or to
/// a piece, after `on_data` returns.
pub const RequestBodyStream = struct {
    // Each field is colibri's. A program reads none of them.
    /// The reader of the body: the router's, over the bytes of the event and the bytes it held,
    /// or the last wrapper of a middleware's `wrap_body`.
    reader: *std.Io.Reader,
    /// The bytes of the entry's `request_body_bytes` that kept bytes may take, whose length bounds them.
    /// The router's reader holds kept bytes there itself. Through a wrapper, the router points
    /// `storage` at the bytes past the ones it holds, and `next` copies kept bytes to its end.
    storage: []u8 = &.{},
    /// Bytes of the piece that `next` gave last, and the bytes at its end that `keep` kept.
    given: usize = 0,
    kept: usize = 0,
    /// Whether the reader is a middleware's wrapper.
    wrapped: bool = false,
    /// Whether the piece that `next` gave last lies at the end of `storage`, and not in the
    /// reader's buffer. Only a wrapper's pieces lie there.
    stored: bool = false,
    /// Whether kept bytes did not fit `storage`. The router then answers 413.
    too_large: bool = false,
    /// Whether `next` gave the kept bytes once more as the body's last piece.
    last: bool = false,
    /// Whether `next` found the body's end.
    at_end: bool = false,

    /// The next piece of the body that has arrived, or null when no piece waits now. Each call
    /// first lets go of the piece it gave before, less the bytes that `keep` kept. A piece that
    /// follows a `keep` starts with the kept bytes. A piece stays valid until the next call of
    /// `next`, or until `on_data` returns.
    ///
    /// At the body's end, a call after a `keep` gives the kept bytes once more as the last piece,
    /// with no new byte. The call after that one returns null. A null at the body's end makes
    /// `ended` true.
    pub fn next(stream: *RequestBodyStream) ?[]const u8 {
        // Through a wrapper, kept bytes join the later bytes in `storage`.
        if (stream.wrapped and (stream.kept > 0 or stream.stored)) return next_stored(stream);
        return next_buffered(stream);
    }

    /// Leaves the last `len` bytes of the piece that `next` gave last unread. The next call of
    /// `next`, in this `on_data` or in a later one, starts with them, joined with the bytes that
    /// arrive later. A later `keep` takes the place of an earlier one, and `keep(0)` keeps none.
    /// A `keep` of the body's last piece keeps nothing.
    ///
    /// The kept bytes take the entry's `request_body_bytes` when they outlive the engine's event, or
    /// when they come through a middleware's wrapper. Kept bytes that do not fit there get 413
    /// (RFC 9110 §15.5.14), at the body's end too.
    pub fn keep(stream: *RequestBodyStream, len: usize) void {
        assert(len <= stream.given);
        stream.kept = len;
    }

    /// Whether the body ended and `next` gave every piece of it. It turns true when `next`
    /// returns null at the body's end.
    ///
    /// A route never relies on `ended` at its last piece. Over h2 the end may come with the last
    /// piece, on a DATA frame with END_STREAM. Over h11 and h3 the end comes in a later event with
    /// no bytes, and the router calls `on_data` again for it.
    pub fn ended(stream: *const RequestBodyStream) bool {
        return stream.at_end;
    }
};

/// The next piece in the reader's buffer, which starts with the kept bytes that the reader holds:
/// the router's reader, or a wrapper when no byte is kept.
inline fn next_buffered(stream: *RequestBodyStream) ?[]const u8 {
    const reader = stream.reader;
    reader.toss(stream.given - stream.kept);
    stream.given = stream.kept;
    // One byte past the kept ones: a piece holds at least one byte that is new.
    const piece = reader.peekGreedy(stream.kept + 1) catch |failure| return past_end(stream, failure);
    assert(piece.len > stream.kept);
    stream.given = piece.len;
    stream.kept = 0;
    return piece;
}

/// What `next` returns when no byte waits past the kept ones. At the body's end, it gives the
/// kept bytes once more as the last piece. A `keep` of that piece keeps nothing, so the call after
/// it returns null.
fn past_end(stream: *RequestBodyStream, failure: std.Io.Reader.Error) ?[]const u8 {
    if (failure != error.EndOfStream) return null;
    if (stream.kept == 0 or stream.last) {
        stream.at_end = true;
        return null;
    }
    // RFC 9110 §15.5.14: content larger than the server takes gets 413, a kept last piece too.
    if (stream.kept > stream.storage.len) return mark_too_large(stream);
    stream.last = true;
    const piece = if (stream.stored) stream.storage[stream.storage.len - stream.kept ..] else stream.reader.buffered();
    assert(piece.len == stream.kept);
    stream.given = stream.kept;
    stream.kept = 0;
    return piece;
}

/// `next` through a wrapper after a `keep`, or after a piece that `storage` held. It copies the
/// kept bytes to the end of `storage`, and joins there the bytes that the wrapper gives after
/// them. So it asks the wrapper for one byte past those it gave, never more.
fn next_stored(stream: *RequestBodyStream) ?[]const u8 {
    assert(stream.wrapped);
    const kept = stream.kept;
    if (kept == 0) {
        // The route kept none of the stored piece, so the wrapper's next piece needs no copy.
        assert(stream.stored);
        stream.stored = false;
        stream.given = 0;
        return next_buffered(stream);
    }
    if (!stream.stored) {
        // RFC 9110 §15.5.14: kept bytes past the entry's `request_body_bytes` get 413.
        if (kept > stream.storage.len) return mark_too_large(stream);
        store_kept(stream);
    }
    // The router keeps the bytes it holds clear of the stored ones.
    assert(kept <= stream.storage.len);
    stream.given = kept;
    const fresh = stream.reader.peekGreedy(1) catch |failure| return past_end(stream, failure);
    const room = stream.storage.len - kept;
    // RFC 9110 §15.5.14: kept bytes that fill the entry's `request_body_bytes` join no later byte.
    if (room == 0) return mark_too_large(stream);
    return join(stream, fresh[0..@min(fresh.len, room)]);
}

/// Copies the kept bytes at the end of the wrapper's last piece to the end of `storage`, and
/// lets the wrapper go of them.
fn store_kept(stream: *RequestBodyStream) void {
    const reader = stream.reader;
    reader.toss(stream.given - stream.kept);
    const kept = reader.buffered()[0..stream.kept];
    @memcpy(stream.storage[stream.storage.len - kept.len ..], kept);
    reader.toss(kept.len);
    stream.stored = true;
}

/// Moves the kept bytes at the end of `storage` back by `fresh.len`, copies `fresh` after them,
/// and lets the wrapper go of `fresh`. The piece ends at the end of `storage`.
fn join(stream: *RequestBodyStream, fresh: []const u8) []const u8 {
    const end = stream.storage.len;
    const kept = stream.kept;
    const start = end - kept - fresh.len;
    @memmove(stream.storage[start..][0..kept], stream.storage[end - kept ..][0..kept]);
    @memcpy(stream.storage[end - fresh.len ..], fresh);
    stream.reader.toss(fresh.len);
    stream.given = kept + fresh.len;
    stream.kept = 0;
    return stream.storage[start..];
}

/// Records that kept bytes did not fit `storage`, and gives no piece.
fn mark_too_large(stream: *RequestBodyStream) ?[]const u8 {
    stream.too_large = true;
    return null;
}

test "decision 163 ruling 6: RequestBodyStream exports next, keep and ended" {
    try @import("core").public_names.expect(RequestBodyStream, &.{ "next", "keep", "ended" });
}

const testing = std.testing;
const router_body = @import("router/router_body.zig");

/// A stream over the router's reader, and the bytes of each event. Test-only.
const Fixture = struct {
    body: router_body.Body(request_body_bytes) = .{},
    stream: RequestBodyStream = undefined,

    const request_body_bytes = 16;

    fn start(fixture: *Fixture) void {
        fixture.stream = .{ .reader = &fixture.body.cursor.reader, .storage = &fixture.body.held };
    }

    /// Starts a stream as through a wrapper, which copies kept bytes into `storage`.
    fn start_wrapped(fixture: *Fixture, storage: []u8) void {
        fixture.stream = .{ .reader = &fixture.body.cursor.reader, .storage = storage, .wrapped = true };
    }

    /// Points the reader at `bytes`, after any bytes held, as the router does at a body event.
    fn give(fixture: *Fixture, bytes: []const u8, end: bool) !void {
        fixture.body.cursor.ended = end;
        if (fixture.body.held_len > 0) try fixture.body.append(bytes);
        _ = fixture.body.reader_over(bytes);
    }
};

/// Whether `piece` lies in `storage`.
fn lies_in(piece: []const u8, storage: []const u8) bool {
    const start = @intFromPtr(storage.ptr);
    return @intFromPtr(piece.ptr) >= start and @intFromPtr(piece.ptr) + piece.len <= start + storage.len;
}

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
    // No byte arrived after the kept ones, so no piece waits.
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

test "decision 163 ruling 6 as amended: at the end, next gives the kept octets as the last piece once" {
    var fixture: Fixture = .{};
    fixture.start();
    try fixture.give("abcd", true);
    try testing.expectEqualStrings("abcd", fixture.stream.next().?);
    fixture.stream.keep(3);
    try testing.expectEqualStrings("bcd", fixture.stream.next().?);
    try testing.expect(!fixture.stream.ended());
    // A `keep` of the last piece keeps nothing.
    fixture.stream.keep(3);
    try testing.expectEqual(null, fixture.stream.next());
    try testing.expect(fixture.stream.ended());
    try testing.expectEqual(null, fixture.stream.next());
}

test "RFC 9110 §15.5.14: kept octets past storage give no last piece, and the router answers 413" {
    var fixture: Fixture = .{};
    fixture.start();
    const bytes = "0123456789abcdef!";
    try fixture.give(bytes, true);
    try testing.expectEqualStrings(bytes, fixture.stream.next().?);
    fixture.stream.keep(bytes.len);
    try testing.expectEqual(null, fixture.stream.next());
    try testing.expect(fixture.stream.too_large);
    try testing.expect(!fixture.stream.ended());
}

test "decision 163 ruling 6 as amended: through a wrapper, kept octets join later octets in storage" {
    var fixture: Fixture = .{};
    var storage: [8]u8 = undefined;
    fixture.start_wrapped(&storage);
    var first = "abc".*;
    try fixture.give(&first, false);
    // A piece that follows no `keep` stays in the reader's buffer.
    try testing.expect(lies_in(fixture.stream.next().?, &first));
    fixture.stream.keep(2);
    try testing.expectEqual(null, fixture.stream.next());
    // The kept bytes left the reader's buffer, which the next event writes again.
    first = "xyz".*;
    try fixture.give("de", false);
    const joined = fixture.stream.next().?;
    try testing.expectEqualStrings("bcde", joined);
    try testing.expect(lies_in(joined, &storage));
    fixture.stream.keep(4);
    try fixture.give("", true);
    const last = fixture.stream.next().?;
    try testing.expectEqualStrings("bcde", last);
    try testing.expect(lies_in(last, &storage));
    fixture.stream.keep(1);
    try testing.expectEqual(null, fixture.stream.next());
    try testing.expect(fixture.stream.ended());
}

test "RFC 9110 §15.5.14: through a wrapper, kept octets that fill storage join no later octet" {
    var fixture: Fixture = .{};
    var storage: [2]u8 = undefined;
    fixture.start_wrapped(&storage);
    try fixture.give("ab", false);
    try testing.expectEqualStrings("ab", fixture.stream.next().?);
    fixture.stream.keep(2);
    try testing.expectEqual(null, fixture.stream.next());
    try testing.expect(!fixture.stream.too_large);
    try fixture.give("c", false);
    try testing.expectEqual(null, fixture.stream.next());
    try testing.expect(fixture.stream.too_large);
}
