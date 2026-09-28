//! The events a client connection owes its caller (decision 100), whichever transport carries it:
//! the version it speaks, a resumption ticket, each exchange's end, draining, and the close. They
//! are reported one a call, in that order, before the connection reads anything more.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("event.zig");
const slots_module = @import("slots.zig");

const Event = event.Event;
const Protocol = event.Protocol;
const Slots = slots_module.Slots;

pub const Owed = struct {
    /// The connection speaks its version, and has not said so.
    connected: bool = false,
    /// The server issued a ticket the caller has not heard of.
    ticket: bool = false,
    /// The connection takes no new request, and has not said so.
    draining: bool = false,
    /// The `closed` event went out.
    closed_reported: bool = false,

    /// The first event owed, which the call counts as reported. `protocol` is the version the
    /// connection speaks, and `over` whether it carries nothing more and every exchange it held
    /// has finished. A finished exchange's slot is free once its event is reported.
    pub fn next(owed: *Owed, slots: *Slots, protocol: ?Protocol, over: bool) ?Event {
        if (owed.connected) {
            owed.connected = false;
            return .{ .connected = protocol.? };
        }
        if (owed.ticket) {
            owed.ticket = false;
            return .ticket;
        }
        if (slots.oldest_reportable()) |slot| {
            const ended: event.Finished = .{ .id = slot.id, .exchange = slot.exchange };
            slots_module.release(slot);
            return .{ .finished = ended };
        }
        if (owed.draining) {
            owed.draining = false;
            return .draining;
        }
        if (owed.closed_reported or !over) return null;
        assert(slots.idle() and slots.count(.ended) == 0);
        owed.closed_reported = true;
        return .closed;
    }
};

const testing = std.testing;

test "the version comes first, then the ticket, each exchange's end, draining, and the close" {
    var slots: Slots = undefined;
    slots.init();
    var exchange: event.Exchange = .{ .method = "GET", .path = "/" };
    const id = slots.take(&exchange).?;
    slots_module.end(slots.of_id(id).?, .response);
    var owed: Owed = .{ .connected = true, .ticket = true, .draining = true };
    try testing.expectEqual(Protocol.h2, owed.next(&slots, .h2, true).?.connected);
    try testing.expectEqual(.ticket, std.meta.activeTag(owed.next(&slots, .h2, true).?));
    try testing.expectEqual(id, owed.next(&slots, .h2, true).?.finished.id);
    try testing.expectEqual(.draining, std.meta.activeTag(owed.next(&slots, .h2, true).?));
    // The close waits for the connection to be over, and goes out once.
    try testing.expectEqual(null, owed.next(&slots, .h2, false));
    try testing.expectEqual(.closed, std.meta.activeTag(owed.next(&slots, .h2, true).?));
    try testing.expectEqual(null, owed.next(&slots, .h2, true));
}
