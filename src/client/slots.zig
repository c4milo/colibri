//! The exchanges one client connection holds (decision 100): a slot for each, from `request` until
//! its `finished` event is reported. Ids rise in the order `request` took the exchanges, and h11
//! writes them and reads their responses in that order (RFC 9112 §9.2), so the oldest is the one
//! with the lowest id.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const event = @import("event.zig");

const Id = event.Id;
const HttpExchange = event.HttpExchange;
const Outcome = event.Outcome;

pub const Stage = enum {
    free,
    /// Taken, and its head not written: it waits for the protocol, for room, for the peer's
    /// stream limit (RFC 9113 §5.1.2) or for h11's pipelining (RFC 9112 §9.3.2).
    queued,
    /// Its head is written. Its content may still be going out, and its response is awaited.
    sent,
    /// h11: its response is read and dropped, because its content did not fit or its caller
    /// cancelled it. `exchange` is not read, and a cancelled slot reports nothing.
    dropping,
    /// It ended, and its `finished` event is owed.
    ended,
};

pub const Slot = struct {
    stage: Stage = .free,
    id: Id = 0,
    exchange: *HttpExchange = undefined,
    /// The stream the request opened, 0 before it opened one: h2's (RFC 9113 §5.1.1), or QUIC's
    /// (RFC 9000 §2.1), whose client-initiated bidirectional streams start at 0 too, so a QUIC
    /// slot says whether it opened one with `stage`.
    stream_id: u64 = 0,
    /// QUIC: the stream may still send the request's octets again, which it reads from the
    /// exchange (RFC 9000 §3.1), so an ended exchange is not reported until it is closed.
    holds_octets: bool = false,
    /// The protocol refused the rest of the content, so no more of it is written.
    content_stopped: bool = false,
    /// A dropping slot whose exchange ended before its response did, and whose `finished` event
    /// is owed once the response is read.
    report_after_drop: bool = false,

    /// Whether no more of the exchange's content is to be written: all of it went out, or the
    /// protocol refused the rest.
    pub fn content_done(slot: *const Slot) bool {
        assert(slot.stage == .sent);
        return slot.content_stopped or slot.exchange.content_sent == slot.exchange.content.len;
    }
};

pub const Slots = struct {
    slots: [constants.exchanges_max]Slot,
    /// The id the next exchange gets.
    next_id: Id,

    pub fn init(slots: *Slots) void {
        slots.slots = @splat(.{});
        slots.next_id = 1;
        assert(slots.count(.free) == constants.exchanges_max);
    }

    /// Takes a free slot for `exchange` and returns its id, or null when every slot is taken.
    pub fn take(slots: *Slots, exchange: *HttpExchange) ?Id {
        const slot = slots.first(.free) orelse return null;
        slot.* = .{ .stage = .queued, .id = slots.next_id, .exchange = exchange };
        slots.next_id += 1;
        assert(slot.id < slots.next_id);
        return slot.id;
    }

    /// The slot of the exchange `id`, or null when no slot holds it.
    pub fn of_id(slots: *Slots, id: Id) ?*Slot {
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
    /// first, or null.
    pub fn oldest_reportable(slots: *Slots) ?*Slot {
        var found: ?*Slot = null;
        for (&slots.slots) |*slot| {
            if (slot.stage != .ended or slot.holds_octets) continue;
            if (found == null or slot.id < found.?.id) found = slot;
        }
        return found;
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

    /// Whether no exchange is queued or awaits its response.
    pub fn idle(slots: *const Slots) bool {
        return slots.count(.queued) == 0 and slots.count(.sent) == 0 and slots.count(.dropping) == 0;
    }

    /// Ends every queued exchange with `queued_outcome` and every one awaiting its response with
    /// `sent_outcome`, as a connection that carries nothing more does.
    pub fn end_all(slots: *Slots, queued_outcome: Outcome, sent_outcome: Outcome) void {
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
pub fn end(slot: *Slot, outcome: Outcome) void {
    assert(slot.stage == .queued or slot.stage == .sent);
    assert(outcome != .pending);
    slot.exchange.outcome = outcome;
    slot.stage = .ended;
}

/// Starts dropping a sent slot's response. With `report`, the exchange ended already and its
/// `finished` event is owed once the response is read; without, the caller cancelled it.
pub fn drop(slot: *Slot, report: bool) void {
    assert(slot.stage == .sent);
    assert(!report or slot.exchange.outcome != .pending);
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
    slot.* = .{};
}

const testing = std.testing;

test "ids rise in the order exchanges are taken, and a released slot is taken again" {
    var slots: Slots = undefined;
    slots.init();
    var exchanges: [constants.exchanges_max + 1]HttpExchange = @splat(.{ .method = "GET", .path = "/" });
    for (exchanges[0..constants.exchanges_max], 1..) |*exchange, expected| {
        try testing.expectEqual(expected, slots.take(exchange).?);
    }
    try testing.expectEqual(null, slots.take(&exchanges[constants.exchanges_max]));
    release(slots.of_id(3).?);
    try testing.expectEqual(constants.exchanges_max + 1, slots.take(&exchanges[constants.exchanges_max]).?);
    try testing.expectEqual(1, slots.oldest(.queued).?.id);
}

test "the oldest exchange awaiting its response may be sent or dropping" {
    var slots: Slots = undefined;
    slots.init();
    var exchanges: [3]HttpExchange = @splat(.{ .method = "GET", .path = "/" });
    for (&exchanges) |*exchange| _ = slots.take(exchange).?;
    for (&slots.slots) |*slot| {
        if (slot.stage == .queued) slot.stage = .sent;
    }
    drop(slots.of_id(1).?, false);
    try testing.expectEqual(1, slots.oldest_awaiting().?.id);
    settle_drop(slots.of_id(1).?);
    try testing.expectEqual(2, slots.oldest_awaiting().?.id);
    // A connection that carries nothing more ends every exchange it holds.
    slots.end_all(.refused, .closed);
    try testing.expectEqual(.closed, exchanges[1].outcome);
    try testing.expect(slots.idle());
    try testing.expectEqual(2, slots.count(.ended));
}
