//! The events a client connection owes its caller (decision 100), whichever transport carries it:
//! the version it speaks, a resumption ticket, each request piece it reads no more, each streamed
//! response's head and pieces (decision 153), each exchange's end, draining, and the close. They
//! are reported one a call, in that order, before the connection reads anything more.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("event.zig");
const slots_module = @import("slots.zig");
const response_write = @import("response_write.zig");

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
        // A piece's `body_taken` goes out before its exchange's `finished`, which frees the slot.
        if (slots.owing(.taken_owed)) |slot| {
            slot.taken_owed = false;
            return .{ .body_taken = slot.id };
        }
        // A streamed response's head goes out before its first piece, and each piece before the
        // exchange's `finished` (decision 153 ruling 7).
        if (slots.owing(.headers_owed)) |slot| {
            slot.headers_owed = false;
            return .{ .headers = slot.id };
        }
        if (slots.owing(.body_owed)) |slot| {
            slot.body_owed = false;
            return .{ .body = .{ .id = slot.id, .len = slot.response.body_len } };
        }
        if (slots.oldest_reportable()) |slot| {
            const ended: event.Ended = .{ .id = slot.id, .request = slot.request, .response = slot.response, .response_began = slot.response_began };
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
    const request: event.Request = .{ .method = "GET", .path = "/" };
    var response: event.Response = .{};
    const id = slots.take(&request, &response).?;
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

test "decision 153: a piece's body_taken goes out before its exchange's finished" {
    var slots: Slots = undefined;
    slots.init();
    const request: event.Request = .{ .method = "PUT", .path = "/", .streamed = .{ .request = true } };
    var response: event.Response = .{};
    const id = slots.take(&request, &response).?;
    const slot = slots.of_id(id).?;
    try slots_module.hand(slot, "piece", true);
    slot.stage = .sent;
    slot.piece_sent = slot.piece.len;
    slot.piece_written();
    slots_module.end(slot, .response);
    var owed: Owed = .{};
    try testing.expectEqual(id, owed.next(&slots, .h2, false).?.body_taken);
    try testing.expectEqual(id, owed.next(&slots, .h2, false).?.finished.id);
    try testing.expectEqual(null, owed.next(&slots, .h2, false));
}

test "decision 153 ruling 7: a streamed response's head, then its piece, and its end only after the release" {
    var slots: Slots = undefined;
    slots.init();
    const request: event.Request = .{ .method = "GET", .path = "/", .streamed = .{ .response = true } };
    var piece: [4]u8 = undefined;
    var response: event.Response = .{ .body = &piece };
    const id = slots.take(&request, &response).?;
    const slot = slots.of_id(id).?;
    slot.stage = .sent;
    slot.headers_owed = true;
    try testing.expectEqual(3, response_write.hold_piece(slot, "abc"));
    slots_module.end(slot, .response);
    var owed: Owed = .{};
    try testing.expectEqual(id, owed.next(&slots, .h2, false).?.headers);
    const piece_event = owed.next(&slots, .h2, false).?.body;
    try testing.expectEqual(id, piece_event.id);
    try testing.expectEqual(3, piece_event.len);
    // The exchange ended, and its `finished` waits for the piece to come back.
    try testing.expectEqual(null, owed.next(&slots, .h2, false));
    try testing.expectEqual(3, response_write.release_piece(slot));
    try testing.expectEqual(id, owed.next(&slots, .h2, false).?.finished.id);
}
