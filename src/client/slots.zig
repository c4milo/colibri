//! The exchanges one client connection holds (decision 100): a slot for each, from `request` until
//! its `finished` event is reported. Ids rise in the order `request` took the exchanges, and h11
//! writes them and reads their responses in that order (RFC 9112 §9.2), so the oldest is the one
//! with the lowest id.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const http = @import("http");
const coding_pool = @import("coding_pool.zig");
const constants = @import("constants.zig");
const event = @import("event.zig");

const RequestId = event.RequestId;
const Request = event.Request;
const Response = event.Response;
const Result = event.Result;

pub const Stage = enum {
    free,
    /// Taken, and its head not written: it waits for the protocol, for room, for the peer's
    /// stream limit (RFC 9113 §5.1.2) or for h11's pipelining (RFC 9112 §9.3.2).
    queued,
    /// Its head is written. Its content may still be going out, and its response is awaited.
    sent,
    /// h11: its response is read and dropped, because its content did not fit or its caller
    /// cancelled it. `request` and `response` are not read, and a cancelled slot reports nothing.
    dropping,
    /// It ended, and its `finished` event is owed.
    ended,
};

pub const Slot = struct {
    stage: Stage = .free,
    id: RequestId = 0,
    /// The request the program placed, which the client only reads, and its response, which the
    /// client writes (decision 124).
    request: *const Request = undefined,
    response: *Response = undefined,
    /// The stream the request opened, 0 before it opened one: h2's (RFC 9113 §5.1.1), or QUIC's
    /// (RFC 9000 §2.1), whose client-initiated bidirectional streams start at 0 too, so a QUIC
    /// slot says whether it opened one with `stage`.
    stream_id: u64 = 0,
    /// QUIC: the stream may still send the request's octets again, which it reads from the
    /// request (RFC 9000 §3.1), so an ended exchange is not reported until it is closed.
    holds_octets: bool = false,
    /// The protocol refused the rest of the content, so no more of it is written.
    content_stopped: bool = false,
    /// The part of the request's content the connection writes now (decision 153): the whole
    /// `body` of a request that is not streamed, or the piece `write_body` handed. `piece_sent`
    /// counts its octets written, and `piece_end` says the content ends after it.
    piece: []const u8 = "",
    piece_sent: usize = 0,
    piece_end: bool = false,
    /// A streamed request's piece is the caller's, and the connection still reads it.
    piece_held: bool = false,
    /// The connection reads the piece no more, and owes the caller its `body_taken` event.
    taken_owed: bool = false,
    /// The content's end went out: h11 wrote its last octet or its last chunk, h2 its
    /// END_STREAM flag, and h3 supplied its FIN.
    content_ended: bool = false,
    /// A streamed response (decision 153 ruling 7): its `headers` event is owed; `Response.body`
    /// holds a piece the caller has not released; and that piece's `body` event is owed. While a
    /// piece is held the connection reads no more of the response, and the exchange's `finished`
    /// event waits for the release.
    headers_owed: bool = false,
    body_held: bool = false,
    body_owed: bool = false,
    /// Some of the response arrived: an octet of it over h11, read or still held. Over h2, the
    /// header of a HEADERS frame on its stream, before h2 reads the frame. Over h3, a HEADERS
    /// frame h3 took, or the header of one first on its stream when the connection ends. Every
    /// frame of a response follows a HEADERS frame (RFC 9113 §8.1, RFC 9114 §4.1). The pool
    /// sends a request again only when its connection closed before this (decision 124).
    response_began: bool = false,
    /// A dropping slot whose exchange ended before its response did, and whose `finished` event
    /// is owed once the response is read.
    report_after_drop: bool = false,
    /// A dropping slot: the octets of content it dropped, and the instant its drop runs out
    /// (decision 146). The time starts once its response is the one being read, so it stays null
    /// before then, and with no time limit.
    dropped_len: u64 = 0,
    drop_until_ns: ?u64 = null,
    /// The decoders the exchange holds from its request's Accept-Encoding until its response's
    /// head names a coding, and the one it keeps until the response ends: `gzip` and `deflate`'s,
    /// with the pool it came from, then `zstd`'s and `br`'s; and the coded octets it was given
    /// (decision 101 as amended).
    decoding: h11.coding.Decoding = .{},
    decoders: ?h11.coding.Storage = null,
    zstd: coding_pool.Held(coding_pool.Zstd) = .{},
    br: coding_pool.Held(coding_pool.Brotli) = .{},
    /// The codings the request's Accept-Encoding offered, the only ones its response is decoded
    /// from (decision 101). `gzip` and `deflate` share one decoder, so holding it says neither.
    offered: std.EnumSet(http.content_coding.Coding) = .initEmpty(),
    coded_len: usize = 0,

    /// Whether no more of the request's content is to be written: its end went out, or the
    /// protocol refused the rest.
    pub fn content_done(slot: *const Slot) bool {
        assert(slot.stage == .sent);
        return slot.content_stopped or slot.content_ended;
    }

    /// Whether the connection has content to write now: octets of the piece, or the end after
    /// it. A streamed request that waits for its next piece has none.
    pub fn content_ready(slot: *const Slot) bool {
        if (slot.content_done()) return false;
        return slot.piece_sent < slot.piece.len or slot.piece_end;
    }

    /// The whole piece went out, so the connection reads it no more, and its `body_taken` event
    /// is owed when the caller handed it.
    pub fn piece_written(slot: *Slot) void {
        assert(slot.piece_sent == slot.piece.len);
        if (!slot.piece_held) return;
        slot.piece_held = false;
        slot.taken_owed = true;
    }
};

/// Hands `slot` the next piece of its streamed request (decision 153), the last one when `last`
/// is set. The caller keeps `piece` until the slot's `body_taken` event. `BodyStopped` says no
/// more of the content goes out: the exchange ended, or the protocol refused the rest.
pub fn hand(slot: *Slot, piece: []const u8, last: bool) error{BodyStopped}!void {
    assert(slot.request.streamed.request);
    // The pool refuses a second piece while one is held, and a piece after the end.
    assert(!slot.piece_held and !slot.taken_owed and !slot.piece_end);
    // RFC 9113 §8.1 and RFC 9112 §9.5: once the exchange ended, no more of its request goes out.
    if (slot.stage != .queued and slot.stage != .sent) return error.BodyStopped;
    // RFC 9113 §5.1 and RFC 9114 §4.1: the stream takes no more of the request.
    if (slot.content_stopped) return error.BodyStopped;
    slot.piece = piece;
    slot.piece_sent = 0;
    slot.piece_end = last;
    slot.piece_held = true;
    // An empty piece that does not end the content has nothing to write, so it is taken at once.
    if (piece.len == 0 and !last) slot.piece_written();
}

/// The flags of a slot that each owe the caller one event (decision 153).
pub const Owing = enum { taken_owed, headers_owed, body_owed };

pub const Slots = struct {
    slots: [constants.limits.requests_max]Slot,
    /// The id the next exchange gets.
    next_id: RequestId,

    pub fn init(slots: *Slots) void {
        slots.slots = @splat(.{});
        slots.next_id = 1;
        assert(slots.count(.free) == constants.limits.requests_max);
    }

    /// Takes a free slot for `request` and its `response`, and returns its id, or null when every
    /// slot is taken.
    pub fn take(slots: *Slots, request: *const Request, response: *Response) ?RequestId {
        // Decision 153: a streamed response comes into `body` one piece at a time, so it has room.
        assert(!request.streamed.response or response.body.len > 0);
        const slot = slots.first(.free) orelse return null;
        slot.* = .{ .stage = .queued, .id = slots.next_id, .request = request, .response = response };
        // A request that is not streamed has one piece, its whole body, which ends the content.
        if (!request.streamed.request) {
            slot.piece = request.body;
            slot.piece_end = true;
        }
        slots.next_id += 1;
        assert(slot.id < slots.next_id);
        return slot.id;
    }

    /// The slot of the exchange `id`, or null when no slot holds it.
    pub fn of_id(slots: *Slots, id: RequestId) ?*Slot {
        for (&slots.slots) |*slot| {
            if (slot.stage != .free and slot.id == id) return slot;
        }
        return null;
    }

    /// The slot whose request opened `stream_id`, sent or dropping, or null.
    pub fn of_stream(slots: *Slots, stream_id: u64) ?*Slot {
        for (&slots.slots) |*slot| {
            const live = slot.stage == .sent or slot.stage == .dropping;
            if (live and slot.stream_id == stream_id) return slot;
        }
        return null;
    }

    /// The oldest slot at `stage`, or null.
    pub fn oldest(slots: *Slots, stage: Stage) ?*Slot {
        var found: ?*Slot = null;
        for (&slots.slots) |*slot| {
            if (slot.stage != stage) continue;
            if (found == null or slot.id < found.?.id) found = slot;
        }
        return found;
    }

    /// The oldest ended slot whose octets no stream reads any more, whose `finished` event is owed
    /// first, or null. Decision 153 ruling 7: a slot whose caller holds a piece of its response,
    /// or whose `headers` event is owed, waits.
    pub fn oldest_reportable(slots: *Slots) ?*Slot {
        var found: ?*Slot = null;
        for (&slots.slots) |*slot| {
            if (slot.stage != .ended or slot.holds_octets) continue;
            if (slot.body_held or slot.headers_owed) continue;
            if (found == null or slot.id < found.?.id) found = slot;
        }
        return found;
    }

    /// The slot that owes the event `flag` names, or null.
    pub fn owing(slots: *Slots, comptime flag: Owing) ?*Slot {
        for (&slots.slots) |*slot| {
            if (slot.stage != .free and @field(slot, @tagName(flag))) return slot;
        }
        return null;
    }

    /// Whether the caller holds a piece of a streamed response (decision 153 ruling 7).
    pub fn holding_body(slots: *const Slots) bool {
        for (&slots.slots) |*slot| {
            if (slot.stage != .free and slot.body_held) return true;
        }
        return false;
    }

    /// Where `slot` sits in the table, which keys a transport's storage for it.
    pub fn index_of(slots: *const Slots, slot: *const Slot) usize {
        const index = (@intFromPtr(slot) - @intFromPtr(&slots.slots[0])) / @sizeOf(Slot);
        assert(index < slots.slots.len and &slots.slots[index] == slot);
        return index;
    }

    /// The oldest slot whose response is awaited, sent or dropping: the one h11's next response
    /// answers (RFC 9112 §9.2).
    pub fn oldest_awaiting(slots: *Slots) ?*Slot {
        const sent = slots.oldest(.sent);
        const dropping = slots.oldest(.dropping);
        if (sent == null) return dropping;
        if (dropping == null) return sent;
        return if (sent.?.id < dropping.?.id) sent else dropping;
    }

    /// How many slots are at `stage`.
    pub fn count(slots: *const Slots, stage: Stage) u32 {
        var counted: u32 = 0;
        for (&slots.slots) |*slot| counted += @intFromBool(slot.stage == stage);
        return counted;
    }

    /// Whether a request waits to be written, or has content to write now.
    pub fn unwritten(slots: *const Slots) bool {
        for (&slots.slots) |*slot| {
            if (slot.stage == .queued) return true;
            if (slot.stage == .sent and slot.content_ready()) return true;
        }
        return false;
    }

    /// Whether every slot holds an exchange, so the next `take` returns null.
    pub fn full(slots: *const Slots) bool {
        return slots.count(.free) == 0;
    }

    /// Whether no exchange is queued or awaits its response.
    pub fn idle(slots: *const Slots) bool {
        return slots.count(.queued) == 0 and slots.count(.sent) == 0 and slots.count(.dropping) == 0;
    }

    /// Ends every queued exchange with `queued_outcome` and every one awaiting its response with
    /// `sent_outcome`, as a connection that carries nothing more does.
    pub fn end_all(slots: *Slots, queued_outcome: Result, sent_outcome: Result) void {
        for (&slots.slots) |*slot| {
            switch (slot.stage) {
                .queued => end(slot, queued_outcome),
                .sent => end(slot, sent_outcome),
                .dropping => settle_drop(slot),
                .free, .ended => {},
            }
        }
        assert(slots.idle());
    }

    fn first(slots: *Slots, stage: Stage) ?*Slot {
        for (&slots.slots) |*slot| {
            if (slot.stage == stage) return slot;
        }
        return null;
    }
};

/// Ends the slot's exchange with `outcome`, whose `finished` event is then owed.
pub fn end(slot: *Slot, outcome: Result) void {
    assert(slot.stage == .queued or slot.stage == .sent);
    assert(outcome != .pending);
    give_back(slot);
    slot.response.result = outcome;
    slot.stage = .ended;
}

/// Starts dropping a sent slot's response. With `report`, the exchange ended already and its
/// `finished` event is owed once the response is read; without, the caller cancelled it.
pub fn drop(slot: *Slot, report: bool) void {
    assert(slot.stage == .sent);
    assert(!report or slot.response.result != .pending);
    assert(slot.dropped_len == 0 and slot.drop_until_ns == null);
    give_back(slot);
    // Decision 153 ruling 7: the caller gets back a piece it held with the exchange, and the
    // rest of the response is read and dropped. A response that is not streamed keeps the octets
    // that fit in `body` (decision 153 ruling 13).
    if (slot.body_held) slot.response.body_len = 0;
    slot.headers_owed = false;
    slot.body_held = false;
    slot.body_owed = false;
    slot.stage = .dropping;
    slot.report_after_drop = report;
}

/// A dropping slot's response ended: its `finished` event is owed, or, cancelled, it is free.
pub fn settle_drop(slot: *Slot) void {
    assert(slot.stage == .dropping);
    slot.stage = if (slot.report_after_drop) .ended else .free;
}

/// Frees a slot whose `finished` event was reported, or which its caller cancelled.
pub fn release(slot: *Slot) void {
    assert(slot.stage != .free);
    give_back(slot);
    slot.* = .{};
}

/// Gives back every decoder the slot holds, reserved or decoding: its response ended, or nothing
/// more of it is read.
pub fn give_back(slot: *Slot) void {
    slot.zstd.release();
    slot.br.release();
    const storage = slot.decoders orelse return;
    h11.coding.release(&slot.decoding, storage);
    slot.decoders = null;
    assert(!slot.decoding.holds());
}

const testing = std.testing;

/// The request each test slot takes. Test-only.
const test_request: Request = .{ .method = "GET", .path = "/" };

test "ids rise in the order exchanges are taken, and a released slot is taken again" {
    var slots: Slots = undefined;
    slots.init();
    var responses: [constants.limits.requests_max + 1]Response = @splat(.{});
    for (responses[0..constants.limits.requests_max], 1..) |*response, expected| {
        try testing.expectEqual(expected, slots.take(&test_request, response).?);
    }
    try testing.expectEqual(null, slots.take(&test_request, &responses[constants.limits.requests_max]));
    release(slots.of_id(3).?);
    try testing.expectEqual(constants.limits.requests_max + 1, slots.take(&test_request, &responses[constants.limits.requests_max]).?);
    try testing.expectEqual(1, slots.oldest(.queued).?.id);
}

test "the oldest exchange awaiting its response may be sent or dropping" {
    var slots: Slots = undefined;
    slots.init();
    var responses: [3]Response = @splat(.{});
    for (&responses) |*response| _ = slots.take(&test_request, response).?;
    for (&slots.slots) |*slot| {
        if (slot.stage == .queued) slot.stage = .sent;
    }
    drop(slots.of_id(1).?, false);
    try testing.expectEqual(1, slots.oldest_awaiting().?.id);
    settle_drop(slots.of_id(1).?);
    try testing.expectEqual(2, slots.oldest_awaiting().?.id);
    // A connection that carries nothing more ends every exchange it holds.
    slots.end_all(.refused, .closed);
    try testing.expectEqual(.closed, responses[1].result);
    try testing.expect(slots.idle());
    try testing.expectEqual(2, slots.count(.ended));
}
