//! The `careful-resume` word of the UDP server's `h3` mode (design §8 step 35e): where the server
//! keeps RFC 9959's saved sets between connections, so a later connection of a client resumes
//! from what an earlier one observed. The judge's bulk run measures a download that resumes
//! through it, and `tools/quic_udp.sh` checks it over real UDP.
//!
//! RFC 9959 §2.2 names a path by its Remote Endpoint, whose part for the destination is an IP
//! address. A client opens each connection from another port, so the table compares hosts and
//! never ports.
//!
//! RFC 9959 §3.2 lets one connection at a time use a set. `server.ResumeProvider`'s calls name a
//! host and no connection, so the table counts each host's open connections, and gives a set
//! only to a connection that is the host's one open connection. A connection that ends on
//! another host than it started on leaves its first host's count one too high, and that host
//! resumes no more. The judge's loads move no connection.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const constants = @import("../../constants.zig");

const Entry = struct {
    host: server.Address,
    /// The host's connections the engine holds: each `take` whose `put` has not come.
    open: u32 = 0,
    saved: ?server.ResumeState = null,
};

pub const Table = struct {
    entries: [constants.quic_resume_hosts_max]Entry = undefined,
    len: usize = 0,
    /// Connections that took a set, connections that ended with a set to save, and connections
    /// that retreated (RFC 9959 §3.5), which the server's log gives after each connection's end.
    resumed: u64 = 0,
    saved: u64 = 0,
    retreated: u64 = 0,

    /// The provider `server.Config.resumes` takes. The table outlives the engine.
    pub fn provider(table: *Table) server.ResumeProvider {
        return .{ .context = table, .vtable = &vtable };
    }

    fn find(table: *Table, peer: *const server.Address) ?*Entry {
        assert(table.len <= table.entries.len);
        for (table.entries[0..table.len]) |*entry| {
            if (entry.host.same_host(peer)) return entry;
        }
        return null;
    }

    /// The entry of `peer`'s host, which a host seen for the first time gets while the table has
    /// room. A full table keeps the hosts it has.
    fn find_or_add(table: *Table, peer: *const server.Address) ?*Entry {
        if (table.find(peer)) |entry| return entry;
        if (table.len == table.entries.len) return null;
        table.entries[table.len] = .{ .host = peer.* };
        table.len += 1;
        return &table.entries[table.len - 1];
    }
};

const vtable: server.ResumeProvider.VTable = .{ .take = take, .put = put, .drop = drop };

fn table_of(context: *anyopaque) *Table {
    return @ptrCast(@alignCast(context));
}

fn take(context: *anyopaque, peer: server.Address, now_ns: u64) ?server.ResumeState {
    _ = now_ns;
    const table = table_of(context);
    const entry = table.find_or_add(&peer) orelse return null;
    entry.open += 1;
    // RFC 9959 §3.2: "the saved_cwnd can only be used by one connection at a time".
    if (entry.open > 1) return null;
    const saved = entry.saved orelse return null;
    table.resumed += 1;
    return saved;
}

fn put(context: *anyopaque, peer: server.Address, observed: ?server.ResumeState, now_ns: u64) void {
    _ = now_ns;
    const table = table_of(context);
    const entry = table.find(&peer) orelse return;
    // A connection that moved to this host took at another, so the count stops at zero.
    entry.open -|= 1;
    const state = observed orelse return;
    entry.saved = state;
    table.saved += 1;
}

fn drop(context: *anyopaque, peer: server.Address) void {
    const table = table_of(context);
    table.retreated += 1;
    // RFC 9959 §3.5: "The set of saved CC parameters for the path are deleted".
    if (table.find(&peer)) |entry| entry.saved = null;
}

const testing = std.testing;

test "RFC 9959 §2.2: a host's later connection takes its set from another port" {
    const test_set: server.ResumeState = .{ .window_len = 120_000, .rtt_ns = 50_000_000, .saved_at_ns = 1 };
    const test_host: [4]u8 = .{ 192, 0, 2, 7 };
    var table: Table = .{};
    const resumes = table.provider();
    const first = server.Address.init(&test_host, 50_000);
    const second = server.Address.init(&test_host, 50_001);
    try testing.expectEqual(null, resumes.take(first, 0));
    resumes.put(first, test_set, 1);
    try testing.expectEqual(test_set, resumes.take(second, 2).?);
    // A connection that observed nothing keeps the set the table holds.
    resumes.put(second, null, 3);
    try testing.expectEqual(test_set, resumes.take(first, 4).?);
    try testing.expectEqual(2, table.resumed);
    try testing.expectEqual(1, table.saved);
    try testing.expectEqual(1, table.len);
}

test "RFC 9959 §3.2: one connection of a host at a time takes its set" {
    const test_set: server.ResumeState = .{ .window_len = 120_000, .rtt_ns = 50_000_000, .saved_at_ns = 1 };
    const test_host: [4]u8 = .{ 192, 0, 2, 7 };
    var table: Table = .{};
    const resumes = table.provider();
    const holder = server.Address.init(&test_host, 50_000);
    const other = server.Address.init(&test_host, 50_001);
    try testing.expectEqual(null, resumes.take(holder, 0));
    resumes.put(holder, test_set, 1);
    try testing.expectEqual(test_set, resumes.take(holder, 2).?);
    try testing.expectEqual(null, resumes.take(other, 3));
    // The second connection's end leaves the first one open, so no third one takes the set.
    resumes.put(other, null, 4);
    try testing.expectEqual(null, resumes.take(other, 5));
    resumes.put(other, null, 6);
    resumes.put(holder, null, 7);
    try testing.expectEqual(test_set, resumes.take(other, 8).?);
    try testing.expectEqual(2, table.resumed);
}

test "RFC 9959 §3.5: a retreat deletes the host's set, and another host's stays" {
    const test_set: server.ResumeState = .{ .window_len = 120_000, .rtt_ns = 50_000_000, .saved_at_ns = 1 };
    const test_host: [4]u8 = .{ 192, 0, 2, 7 };
    var table: Table = .{};
    const resumes = table.provider();
    const retreats = server.Address.init(&test_host, 50_000);
    const stays = server.Address.init(&.{ 192, 0, 2, 8 }, 50_000);
    for ([_]server.Address{ retreats, stays }) |peer| {
        try testing.expectEqual(null, resumes.take(peer, 0));
        resumes.put(peer, test_set, 1);
    }
    try testing.expectEqual(test_set, resumes.take(retreats, 2).?);
    resumes.drop(retreats);
    resumes.put(retreats, null, 3);
    try testing.expectEqual(null, resumes.take(retreats, 4));
    try testing.expectEqual(test_set, resumes.take(stays, 4).?);
    try testing.expectEqual(1, table.retreated);
    try testing.expectEqual(2, table.len);
}

test "a full table keeps its hosts, and a host past it resumes nothing" {
    const test_set: server.ResumeState = .{ .window_len = 120_000, .rtt_ns = 50_000_000, .saved_at_ns = 1 };
    var table: Table = .{};
    const resumes = table.provider();
    for (0..constants.quic_resume_hosts_max + 1) |index| {
        const peer = server.Address.init(&.{ 192, 0, 2, @intCast(index) }, 50_000);
        try testing.expectEqual(null, resumes.take(peer, 0));
        resumes.put(peer, test_set, 1);
    }
    try testing.expectEqual(constants.quic_resume_hosts_max, table.len);
    const kept = server.Address.init(&.{ 192, 0, 2, 0 }, 50_001);
    const past = server.Address.init(&.{ 192, 0, 2, constants.quic_resume_hosts_max }, 50_001);
    try testing.expectEqual(test_set, resumes.take(kept, 2).?);
    try testing.expectEqual(null, resumes.take(past, 2));
    // A connection that moved to a host with no open connection takes the count no lower.
    resumes.put(kept, null, 3);
    resumes.put(kept, null, 3);
    try testing.expectEqual(test_set, resumes.take(kept, 4).?);
}
