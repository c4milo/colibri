//! What the tests of the pool over TCP share (decision 124): the two pool types each of them
//! runs on, and the versions each type takes. Test-only.
const versions_module = @import("../versions.zig");
const pool_module = @import("pool.zig");
const pool_handle = @import("pool_handle.zig");

/// The pool of the default capacity, and one with no QUIC, which serves the same TCP
/// connections. Each test over TCP runs on both.
pub const pools = .{ pool_module.Pool, pool_module.PoolOf(.{ .quic = false }) };

/// `versions` with h3 off for a pool with no QUIC, whose `init` refuses h3, and as given for
/// any other pool.
pub fn versions_for(pool: anytype, versions: versions_module.Versions) versions_module.Versions {
    var given = versions;
    if (!pool.capacity.quic) given.h3 = false;
    return given;
}

/// The handle of the current connection of `transport` at `pool`, which a test passes where a
/// program passes the handle its `open` event named (decision 125).
pub fn connection_of(pool: anytype, transport: pool_module.Transport) pool_module.ConnectionHandle {
    return pool_handle.handle_of(pool, transport);
}

/// The slot of `transport`'s connections at `pool`, which a test compares with the handle an
/// event named (decision 125).
pub fn slot_of(pool: anytype, transport: pool_module.Transport) u32 {
    return pool_handle.slot_of(pool, transport);
}
