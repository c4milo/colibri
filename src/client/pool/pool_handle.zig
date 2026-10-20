//! A pool's connection handles (decision 125): the slot and the generation that each event and
//! each call about a connection name, and the connection a handle names. The TCP slots come
//! first, and the QUIC connection has the slot after them, as an endpoint numbers its slots
//! (decision 119). The module's root does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const pool_module = @import("pool.zig");

const ConnectionHandle = pool_module.ConnectionHandle;
const Transport = pool_module.Transport;

/// The slot of `transport`'s connection. Until design §8 step 22.6 one TCP connection carries the
/// exchanges, in the first slot.
pub fn slot_of(pool: anytype, transport: Transport) u32 {
    return switch (transport) {
        .tcp => 0,
        .quic => @intCast(pool.tcp.len),
    };
}

/// The handle of `transport`'s current connection.
pub fn handle_of(pool: anytype, transport: Transport) ConnectionHandle {
    return .{ .slot = slot_of(pool, transport), .generation = pool.links.get(transport).generation };
}

/// The handle of the connection whose `close` `transport` owes.
pub fn closing_handle(pool: anytype, transport: Transport) ConnectionHandle {
    const link = pool.links.get(transport);
    assert(link.close_owed);
    return .{ .slot = slot_of(pool, transport), .generation = link.close_generation };
}

/// The transport whose current connection `handle` names, or null: the handle names a slot no
/// connection of the pool holds, an earlier connection of its slot, or one that is over.
pub fn resolve(pool: anytype, handle: ConnectionHandle) ?Transport {
    const transport: Transport = if (handle.slot == slot_of(pool, .tcp))
        .tcp
    else if (pool.capacity.quic and handle.slot == slot_of(pool, .quic))
        .quic
    else
        return null;
    const link = pool.links.get(transport);
    if (link.generation != handle.generation) return null;
    return switch (link.state) {
        .opening, .running => transport,
        .none, .closed => null,
    };
}
