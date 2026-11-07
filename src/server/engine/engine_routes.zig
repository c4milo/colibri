//! The table that finds a QUIC datagram's connection from its Destination Connection ID in one
//! entry (decision 157, design §8 step 29d.17). Each connection ID the engine issues names its
//! own entry with the low bits of its first two octets, so a lookup reads one entry and compares
//! one ID, whatever the number of connections. The table is exact: an ID that ended has no entry.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");

const id_len = constants.policy.quic_id_len;
const ids_max = quic.constants.limits.connection_ids_max;
/// The IDs a connection issued, the field `quic.Connection` keeps them in.
const LocalIds = @FieldType(quic.Connection, "local_ids");
const Issued = std.meta.Elem(@FieldType(LocalIds, "active"));

/// The entries a table for `quic_connections` connections holds: `quic_route_spread` for each ID
/// the connections may hold at once, rounded up to a power of two so the index is a mask.
pub fn entries_for(quic_connections: usize) usize {
    if (quic_connections == 0) return 0;
    const wanted = constants.policy.quic_route_spread * quic_connections * ids_max;
    return std.math.ceilPowerOfTwoAssert(usize, wanted);
}

/// An ID's index uses its first two octets, so a table holds at most 65,536 entries.
const octet_bits = @bitSizeOf(u8);
const index_bits_max = @bitSizeOf(u16);

/// One ID the engine issued and the QUIC index of its connection, or nothing.
pub const Entry = struct {
    id: [id_len]u8 = @splat(0),
    quic_index: ?u32 = null,
};

/// The entries of one connection's IDs, which it frees when its IDs end.
pub const Held = struct {
    at: [ids_max]u32 = undefined,
    len: u32 = 0,
};

pub const Routes = struct {
    entries: []Entry,
    held: []Held,

    pub fn init(routes: *Routes, entries: []Entry, held: []Held) void {
        assert(entries.len == entries_for(held.len));
        assert(entries.len <= 1 << index_bits_max);
        routes.* = .{ .entries = entries, .held = held };
        @memset(entries, .{});
        @memset(held, .{});
    }

    /// The QUIC index of the connection that issued `dcid`, or null when none did.
    pub fn find(routes: *const Routes, dcid: []const u8) ?u32 {
        if (dcid.len != id_len or routes.entries.len == 0) return null;
        const entry = &routes.entries[routes.index_of(dcid[0..id_len])];
        const quic_index = entry.quic_index orelse return null;
        if (!std.mem.eql(u8, &entry.id, dcid)) return null;
        return quic_index;
    }

    /// Draws a new ID for the connection at `quic_index` into `id`, and gives it a free entry.
    /// RFC 9000 §5.1: the ID must not let an observer link it to the connection's other IDs.
    /// The draw names an entry at random, and the slot never appears in the ID.
    pub fn issue(routes: *Routes, quic_index: u32, random: tls.Random, id: *[id_len]u8) void {
        const held = &routes.held[quic_index];
        assert(held.len < ids_max);
        random.bytes(id);
        const mask: u32 = @intCast(routes.entries.len - 1);
        var index = routes.index_of(id);
        // Bounded by the table: it never fills (`entries_for`), so a free entry exists.
        for (0..routes.entries.len) |_| {
            if (routes.entries[index].quic_index == null) break;
            index = (index + 1) & mask;
        } else unreachable;
        write_index(id, index, mask);
        assert(routes.index_of(id) == index);
        routes.entries[index] = .{ .id = id.*, .quic_index = quic_index };
        held.at[held.len] = @intCast(index);
        held.len += 1;
    }

    /// Frees the entry of the ID the connection at `quic_index` issued last, which its
    /// connection refused.
    pub fn forget_last(routes: *Routes, quic_index: u32) void {
        const held = &routes.held[quic_index];
        assert(held.len > 0);
        held.len -= 1;
        routes.free(held.at[held.len]);
    }

    /// Frees the entry of each ID the connection at `quic_index` holds no more. `local` holds the
    /// IDs it issued and its peer has not retired (RFC 9000 §5.1.2). An ID only ends by its
    /// retirement, so equal counts mean no entry is stale.
    pub fn sync(routes: *Routes, quic_index: u32, local: *const LocalIds) void {
        const held = &routes.held[quic_index];
        const active = local.active[0..local.len];
        assert(active.len <= held.len);
        if (active.len == held.len) return;
        routes.drop_retired(held, active);
        assert(held.len == active.len);
    }

    fn drop_retired(routes: *Routes, held: *Held, active: []const Issued) void {
        var kept: u32 = 0;
        for (held.at[0..held.len]) |index| {
            if (is_active(&routes.entries[index].id, active)) {
                held.at[kept] = index;
                kept += 1;
            } else routes.free(index);
        }
        held.len = kept;
    }

    /// Frees every entry of the connection at `quic_index`, whose slot is released.
    pub fn release(routes: *Routes, quic_index: u32) void {
        const held = &routes.held[quic_index];
        for (held.at[0..held.len]) |index| routes.free(index);
        held.len = 0;
    }

    fn free(routes: *Routes, index: u32) void {
        assert(routes.entries[index].quic_index != null);
        routes.entries[index] = .{};
    }

    /// The entry an ID names: the low bits of its first two octets, read in network order.
    fn index_of(routes: *const Routes, id: *const [id_len]u8) u32 {
        const bits = @as(u32, id[0]) << octet_bits | id[1];
        return bits & @as(u32, @intCast(routes.entries.len - 1));
    }
};

/// Writes `index` into the low bits of `id`'s first two octets, and keeps its other bits.
fn write_index(id: *[id_len]u8, index: u32, mask: u32) void {
    assert(index & ~mask == 0);
    const bits = @as(u32, id[0]) << octet_bits | id[1];
    const written = (bits & ~mask) | index;
    id[0] = @truncate(written >> octet_bits);
    id[1] = @truncate(written);
}

fn is_active(id: *const [id_len]u8, active: []const Issued) bool {
    for (active) |*issued| {
        if (std.mem.eql(u8, issued.value(), id)) return true;
    }
    return false;
}

const testing = std.testing;

/// The QUIC connections the tests' table is for. Test-only.
const test_connections = 2;
const test_entries = entries_for(test_connections);
threadlocal var test_entry_storage: [test_entries]Entry align(@alignOf(Entry)) = undefined;
threadlocal var test_held_storage: [test_connections]Held align(@alignOf(Held)) = undefined;

/// A source that draws `byte` again and again, so two draws collide. Test-only.
const Same = struct {
    byte: u8,

    fn fill(same: *Same, octets: []u8) void {
        @memset(octets, same.byte);
    }

    fn random(same: *Same) tls.Random {
        return tls.Random.init(same, fill);
    }
};

fn test_routes() Routes {
    var routes: Routes = undefined;
    routes.init(&test_entry_storage, &test_held_storage);
    return routes;
}

test "decision 157: an ID's first two octets name its entry, and a lookup finds its connection" {
    var routes = test_routes();
    var same: Same = .{ .byte = 0xa5 };
    var id: [id_len]u8 = undefined;
    routes.issue(1, same.random(), &id);
    try testing.expectEqual(1, routes.find(&id).?);
    // The draw named the entry, so the octets stay as drawn.
    try testing.expectEqualSlices(u8, &@as([id_len]u8, @splat(0xa5)), &id);
    // §5.2: an ID no connection issued, or of another length, finds none.
    var other = id;
    other[id_len - 1] ^= 1;
    try testing.expectEqual(null, routes.find(&other));
    try testing.expectEqual(null, routes.find(id[0 .. id_len - 1]));
}

test "decision 157: a draw that names an entry in use moves to the next free one" {
    var routes = test_routes();
    var same: Same = .{ .byte = 0xff };
    var first: [id_len]u8 = undefined;
    var second: [id_len]u8 = undefined;
    routes.issue(0, same.random(), &first);
    routes.issue(1, same.random(), &second);
    // The last entry was in use, so the second ID names the first entry, and keeps its other bits.
    try testing.expectEqual(0, routes.index_of(&second));
    try testing.expect(!std.mem.eql(u8, &first, &second));
    try testing.expectEqualSlices(u8, first[2..], second[2..]);
    try testing.expectEqual(0, routes.find(&first).?);
    try testing.expectEqual(1, routes.find(&second).?);
}

test "decision 157: an ID the peer retired, an ID refused and a released slot free their entries" {
    var routes = test_routes();
    var same: Same = .{ .byte = 0x11 };
    var ids: [3][id_len]u8 = undefined;
    for (&ids) |*id| routes.issue(0, same.random(), id);
    var local: LocalIds = undefined;
    local.init(false);
    const token: [quic.constants.protocol.stateless_reset_token_len]u8 = @splat(0);
    // §5.1.1: the first ID went out in the handshake, and each later one carries a token.
    for (&ids, 0..) |*id, index| _ = local.issue(id, if (index == 0) null else &token).?;
    routes.sync(0, &local);
    for (&ids) |*id| try testing.expectEqual(0, routes.find(id).?);
    // RFC 9000 §5.1.2: the peer retired sequence number 1, so its ID routes nowhere.
    try local.retire(1, 0);
    routes.sync(0, &local);
    try testing.expectEqual(null, routes.find(&ids[1]));
    try testing.expectEqual(0, routes.find(&ids[2]).?);
    try testing.expectEqual(2, routes.held[0].len);
    routes.forget_last(0);
    try testing.expectEqual(null, routes.find(&ids[2]));
    routes.release(0);
    try testing.expectEqual(null, routes.find(&ids[0]));
    try testing.expectEqual(0, routes.held[0].len);
}

test "decision 157: the table has twice the entries of the IDs its connections hold" {
    try testing.expectEqual(0, entries_for(0));
    try testing.expectEqual(32, entries_for(test_connections));
    try testing.expect(entries_for(64) >= 2 * 64 * ids_max);
}
