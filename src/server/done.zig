//! The `done` events a server connection owes (decision 103): the requests whose responses were
//! made whole, in the order they were, until `receive` reports each.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const event = @import("event.zig");

const Number = event.Number;

pub const Owed = struct {
    ids: [constants.done_owed_max]Number = undefined,
    first: usize = 0,
    len: usize = 0,

    /// Owes a `done` event for `id`. A connection holds `done_owed_max` requests at most, and
    /// `receive` reports every event owed before it reads another request, so the ring never fills.
    pub fn push(owed: *Owed, id: Number) void {
        assert(id != 0);
        assert(owed.len < owed.ids.len);
        owed.ids[(owed.first + owed.len) % owed.ids.len] = id;
        owed.len += 1;
    }

    /// The oldest `done` event owed, which the call takes, or null.
    pub fn take(owed: *Owed) ?Number {
        if (owed.len == 0) return null;
        const id = owed.ids[owed.first];
        owed.first = (owed.first + 1) % owed.ids.len;
        owed.len -= 1;
        return id;
    }

    /// Owes nothing more: the connection reads and writes nothing again.
    pub fn clear(owed: *Owed) void {
        owed.first = 0;
        owed.len = 0;
    }
};

const testing = std.testing;

test "decision 103: done events come out in the order the responses were made whole, once each" {
    var owed: Owed = .{};
    try testing.expectEqual(null, owed.take());
    // Past the ring's end and around it.
    for (0..constants.done_owed_max) |index| owed.push(index + 1);
    for (0..constants.done_owed_max) |index| try testing.expectEqual(index + 1, owed.take().?);
    owed.push(7);
    owed.push(9);
    try testing.expectEqual(7, owed.take().?);
    owed.clear();
    try testing.expectEqual(null, owed.take());
}
