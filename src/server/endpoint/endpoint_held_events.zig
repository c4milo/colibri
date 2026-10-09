//! What every kind of slot does with its connection's events (decision 119): an event of a
//! request the slot's table holds is passed on with its id naming the connection and with the
//! request's word, an ending takes the request out of the table, and a request waiting for room is
//! reported `writable` once its connection takes the write. Each function takes the kind of slot
//! as `Side`, whose `refuse` and `takes` ask that kind's connection. Split out of
//! `endpoint_held.zig` for length; `server.zig` does not export this file.
const event = @import("../event.zig");
const endpoint_held = @import("endpoint_held.zig");

const Held = endpoint_held.Held;
const Event = event.Event;
const Id = event.Id;
const ConnectionHandle = event.ConnectionHandle;

/// `reported`, as the program reads it, or null for an event of no request `table` holds.
pub fn pass(held: *Held, slot: u32, table: anytype, reported: Event, comptime Side: type) ?Event {
    const handle = held.slots.handle_of(slot);
    switch (reported) {
        .request => |request| {
            var head = request;
            head.id.connection = handle;
            if (table.find(request.id.number) != null) return null;
            _ = table.add(request.id.number) orelse {
                // The table holds as many requests as the connection, so this fails closed for a
                // connection that held more: the request is refused, and never reported.
                Side.refuse(held, slot, request.id.number);
                return null;
            };
            return .{ .request = head };
        },
        .body => |body| {
            const entry = table.find(body.id.number) orelse return null;
            return .{ .body = .{ .id = id_on(handle, body.id), .user_data = entry.user_data, .octets = body.octets, .end = body.end } };
        },
        .trailers => |trailers| {
            const entry = table.find(trailers.id.number) orelse return null;
            return .{ .trailers = .{ .id = id_on(handle, trailers.id), .user_data = entry.user_data, .fields = trailers.fields } };
        },
        .done => |done| {
            const entry = table.find(done.id.number) orelse return null;
            const user_data = entry.user_data;
            table.remove(done.id.number);
            return .{ .done = .{ .id = id_on(handle, done.id), .user_data = user_data } };
        },
        .cancelled => |cancelled| {
            if (table.find(cancelled.id.number) == null) return null;
            return ending(handle, table, cancelled.id.number, cancelled.reason);
        },
        // A connection reports none of these: the endpoint does.
        .writable, .send, .close, .ended, .closed => unreachable,
    }
}

/// The `writable` of the first request of `slot` whose wait the connection now takes, which waits
/// no more. A request whose room counter moved and which the connection still cannot take waits for
/// the next move, so `writable` comes once for each move of room at most.
pub fn writable_of(held: *Held, slot: u32, table: anytype, comptime Side: type) ?Event {
    const room = held.room[slot];
    var open = table.in_use.iterator(.{});
    // Bounded by the table's capacity.
    while (open.next()) |index| {
        const entry = &table.entries[index];
        const since = entry.waiting_since orelse continue;
        if (since == room) continue;
        if (!Side.takes(held, slot, entry)) {
            entry.waiting_since = room;
            continue;
        }
        entry.waiting_since = null;
        const id: Id = .{ .connection = held.slots.handle_of(slot), .number = entry.number };
        return .{ .writable = .{ .id = id, .user_data = entry.user_data } };
    }
    return null;
}

/// The number of a request whose `cancelled` the program's own `cancel` owes, or null.
pub fn owed_cancel(table: anytype) ?event.Number {
    var open = table.in_use.iterator(.{});
    // Bounded by the table's capacity.
    while (open.next()) |index| {
        if (table.entries[index].cancel_owed) return table.entries[index].number;
    }
    return null;
}

/// Request `number`'s `cancelled` for `reason`, which ends it: it leaves the table.
pub fn ending(handle: ConnectionHandle, table: anytype, number: event.Number, reason: event.CancelReason) Event {
    const user_data = table.find(number).?.user_data;
    table.remove(number);
    return .{ .cancelled = .{ .id = .{ .connection = handle, .number = number }, .user_data = user_data, .reason = reason } };
}

/// `id`, naming the connection `handle` holds.
fn id_on(handle: ConnectionHandle, id: Id) Id {
    return .{ .connection = handle, .number = id.number };
}
