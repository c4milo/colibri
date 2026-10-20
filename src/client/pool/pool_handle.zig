//! A pool's slots and connection handles (decision 125): the slot of each connection, its link,
//! and the slot and the generation that each event and each call about a connection name. The
//! TCP slots come first, and the QUIC connection has the slot after them, as an endpoint numbers
//! its slots (decision 119). The module's root does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const pool_module = @import("pool.zig");

const ConnectionHandle = pool_module.ConnectionHandle;
const Transport = pool_module.Transport;

/// The QUIC connection's slot: the one after the TCP slots.
pub fn quic_slot(pool: anytype) u32 {
    return @intCast(pool.tcp.len);
}

/// The slots a pool holds: its TCP slots, and the QUIC slot in a pool that holds QUIC.
pub fn slots_count(pool: anytype) u32 {
    return @intCast(pool.tcp.len + @intFromBool(pool.capacity.quic));
}

/// The slot visited `index`th of `slots_count`: the QUIC slot first, as the model's steps take
/// QUIC before TCP, then the TCP slots in order.
pub fn ordered(pool: anytype, index: u32) u32 {
    assert(index < slots_count(pool));
    if (!pool.capacity.quic) return index;
    return if (index == 0) quic_slot(pool) else index - 1;
}

/// The transport of `slot`'s connections. A pool with no QUIC holds the QUIC slot's link too,
/// which never opens.
pub fn transport_of(pool: anytype, slot: u32) Transport {
    assert(slot <= quic_slot(pool));
    return if (slot == quic_slot(pool)) .quic else .tcp;
}

/// The link of `slot`.
pub fn link(pool: anytype, slot: u32) @TypeOf(&pool.quic_link) {
    assert(slot <= quic_slot(pool));
    return if (slot == quic_slot(pool)) &pool.quic_link else &pool.tcp_links[slot];
}

/// The handle of `slot`'s current connection.
pub fn handle_of(pool: anytype, slot: u32) ConnectionHandle {
    return .{ .slot = slot, .generation = link(pool, slot).generation };
}

/// The handle of the connection whose `close` `slot` owes.
pub fn closing_handle(pool: anytype, slot: u32) ConnectionHandle {
    const held = link(pool, slot);
    assert(held.close_owed);
    return .{ .slot = slot, .generation = held.close_generation };
}

/// The slot whose current connection `handle` names, or null: the handle names a slot the pool
/// does not hold, an earlier connection of its slot, or one that is over.
pub fn resolve(pool: anytype, handle: ConnectionHandle) ?u32 {
    if (handle.slot >= slots_count(pool)) return null;
    const held = link(pool, handle.slot);
    if (held.generation != handle.generation) return null;
    return switch (held.state) {
        .opening, .running => handle.slot,
        .none, .closed => null,
    };
}
