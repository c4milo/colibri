//! What every kind of slot does with its connection's events (decision 119): an event of a
//! request the slot's table holds is passed on with its id naming the connection and with the
//! request's word, an ending takes the request out of the table, and a request waiting for room is
//! reported `writable` once its connection takes the write. Each function takes the kind of slot
//! as `Side`, whose `refuse` and `takes` ask that kind's connection. Split out of
//! `engine_state.zig` for length; `server.zig` does not export this file.
const event = @import("../event.zig");
const engine_state = @import("engine_state.zig");

const State = engine_state.State;
const Event = event.Event;
const ConnectionEvent = event.ConnectionEvent;
const RequestId = event.RequestId;
const ConnectionHandle = event.ConnectionHandle;

/// Writes `reported`, as the program reads it, into the engine's `event`, and returns false for
/// an event of no request `table` holds. A connection's `done` and `cancelled` each become the
/// request's one `finished` (decision 126).
pub fn pass(state: *State, slot: u32, table: anytype, reported: *const ConnectionEvent, comptime Side: type) bool {
    const handle = state.slots.handle_of(slot);
    switch (reported.*) {
        .request => |*request| {
            if (table.find(request.id.number) != null) return false;
            _ = table.add(request.id.number) orelse {
                // The table holds as many requests as the connection, so this fails closed for a
                // connection that held more: the request is refused, and never reported.
                Side.refuse(state, slot, request.id.number);
                return false;
            };
            state.event = .{ .request = request.* };
            state.event.request.id.connection = handle;
        },
        .body => |*body| {
            const entry = table.find(body.id.number) orelse return false;
            state.event = .{ .body = .{ .id = id_on(handle, body.id), .user_data = entry.user_data, .bytes = body.bytes, .end = body.end } };
        },
        .trailers => |*trailers| {
            const entry = table.find(trailers.id.number) orelse return false;
            state.event = .{ .trailers = .{ .id = id_on(handle, trailers.id), .user_data = entry.user_data, .headers = trailers.headers } };
        },
        .done => |*done| {
            const entry = table.find(done.id.number) orelse return false;
            const user_data = entry.user_data;
            table.remove(done.id.number);
            state.event = .{ .finished = .{ .id = id_on(handle, done.id), .user_data = user_data, .result = .sent } };
        },
        .cancelled => |*cancelled| {
            if (table.find(cancelled.id.number) == null) return false;
            state.event = ending(handle, table, cancelled.id.number, cancelled.reason);
        },
    }
    return true;
}

/// Writes the `writable` of the first request of `slot` whose wait the connection now takes, which
/// waits no more, into the engine's `event`, and returns whether one did. A request whose room
/// counter moved and which the connection still cannot take waits for the next move, so
/// `writable` comes once for each move of room at most.
pub fn writable_of(state: *State, slot: u32, table: anytype, comptime Side: type) bool {
    if (table.waiting == 0) return false;
    const room = state.room[slot];
    var open = table.in_use.iterator(.{});
    // Bounded by the table's capacity.
    while (open.next()) |index| {
        const entry = &table.entries[index];
        const since = entry.waiting_since orelse continue;
        if (since == room) continue;
        if (!Side.takes(state, slot, entry)) {
            entry.waiting_since = room;
            continue;
        }
        table.stop_waiting(entry);
        const id: RequestId = .{ .connection = state.slots.handle_of(slot), .number = entry.number };
        state.event = .{ .writable = .{ .id = id, .user_data = entry.user_data } };
        return true;
    }
    return false;
}

/// The number of a request whose cancelled `finished` the program's own `cancel` owes, or null.
pub fn owed_cancel(table: anytype) ?event.Number {
    if (table.cancels_owed == 0) return null;
    var open = table.in_use.iterator(.{});
    // Bounded by the table's capacity.
    while (open.next()) |index| {
        if (table.entries[index].cancel_owed) return table.entries[index].number;
    }
    return null;
}

/// Request `number`'s `finished`, cancelled for `reason`, which ends it: it leaves the table.
pub fn ending(handle: ConnectionHandle, table: anytype, number: event.Number, reason: event.CancelReason) Event {
    const user_data = table.find(number).?.user_data;
    table.remove(number);
    return .{ .finished = .{ .id = .{ .connection = handle, .number = number }, .user_data = user_data, .result = .{ .cancelled = reason } } };
}

/// `id`, naming the connection `handle` holds.
fn id_on(handle: ConnectionHandle, id: RequestId) RequestId {
    return .{ .connection = handle, .number = id.number };
}
