//! What the tests of the pool over TCP share (decision 124): the two pool types each of them
//! runs on, and the versions each type takes. Test-only.
//!
//! Each function takes a pointer to the pool. Zig 0.16's x86_64 backend copies an argument passed
//! by value into the frame of each call, and a pool with QUIC holds its QUIC connection. A test
//! that passed the pool by value used about 9.5 MiB of stack.
const std = @import("std");
const protocols_module = @import("../protocols.zig");
const pool_module = @import("pool.zig");
const pool_handle = @import("pool_handle.zig");

const assert = std.debug.assert;

/// The pool of the default capacity, and one with no QUIC, which serves the same TCP
/// connections. Each test over TCP runs on both.
pub const pools = .{ pool_module.ConnectionPool(.{}), pool_module.ConnectionPool(.{ .quic = false }) };

/// `versions` with h3 off for a pool with no QUIC, whose `init` refuses h3, and as given for
/// any other pool.
pub fn versions_for(pool: anytype, versions: protocols_module.Protocols) protocols_module.Protocols {
    comptime assert(@typeInfo(@TypeOf(pool)) == .pointer);
    var given = versions;
    if (!pool.capacity.quic) given.h3 = false;
    return given;
}

/// The handle of the current connection of `transport` at `pool`, which a test passes where a
/// program passes the handle its `open` event named (decision 125).
pub fn connection_of(pool: anytype, transport: pool_module.Transport) pool_module.ConnectionHandle {
    comptime assert(@typeInfo(@TypeOf(pool)) == .pointer);
    return pool_handle.handle_of(pool, slot_of(pool, transport));
}

/// The slot of `transport`'s connections at `pool`, which a test compares with the handle an
/// event named (decision 125).
pub fn slot_of(pool: anytype, transport: pool_module.Transport) u32 {
    comptime assert(@typeInfo(@TypeOf(pool)) == .pointer);
    return switch (transport) {
        .tcp => 0,
        .quic => pool_handle.quic_slot(pool),
    };
}
