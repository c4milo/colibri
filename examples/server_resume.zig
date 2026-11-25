//! Part of `server_exchange.zig`: where the server keeps RFC 9959's saved sets between
//! connections (decision 149, design §8 step 35d).
//!
//! colibri holds nothing between connections, so a program that wants a later connection from a
//! client to start near an earlier one's rate keeps the sets itself, keyed by the client's address,
//! and gives the engine a `server.ResumeProvider` over them:
//! - `take` answers the set saved for an address when the connection is its host's one open
//!   connection, because RFC 9959 §3.2 lets one connection at a time use a set;
//! - `put` comes once when that connection ends, with the address `take` got, even after the
//!   connection moved, and with what it observed, which replaces the set, or with null, which
//!   keeps it;
//! - `drop` comes first when the connection retreated, and the set goes (§3.5).
//!
//! The calls name a host and no connection, so the table counts each host's open connections:
//! each `take` whose `put` has not come. It holds a few hosts in storage the program owns, with
//! no allocator, and counts the calls, which `server_exchange.zig` checks.
const std = @import("std");
const colibri = @import("colibri");
const server = colibri.server;

/// The clients whose sets the table holds at once. A program sizes it for the clients it expects.
const entries_max = 4;

const Entry = struct {
    address: server.Address,
    saved: ?server.ResumeState,
    /// The host's open connections: each `take` whose `put` has not come.
    open: u32,
};

var entries: [entries_max]Entry align(@alignOf(Entry)) = undefined;
var entries_len: usize = 0;
var context: u8 = 0;

/// How often the engine called each of the three, which `server_exchange.zig` checks.
pub var taken: u32 = 0;
pub var put_back: u32 = 0;
pub var dropped: u32 = 0;

const vtable: server.ResumeProvider.VTable = .{ .take = take, .put = put, .drop = drop };

/// The provider `Config.resumes` takes.
pub fn provider() server.ResumeProvider {
    return .{ .context = &context, .vtable = &vtable };
}

fn find(address: server.Address) ?*Entry {
    for (entries[0..entries_len]) |*entry| {
        // RFC 9959 §2.2: the remote endpoint is the destination's IP address. A client's next
        // connection comes from another port, so the port is no part of the key.
        if (entry.address.same_host(&address)) return entry;
    }
    return null;
}

fn take(_: *anyopaque, address: server.Address, now_ns: u64) ?server.ResumeState {
    _ = now_ns;
    taken += 1;
    const entry = find_or_add(address) orelse return null;
    entry.open += 1;
    // RFC 9959 §3.2: "Only one connection can use a specific set of saved CC parameters".
    if (entry.open > 1) return null;
    return entry.saved;
}

/// The entry of `address`'s host, which a host seen for the first time gets while the table has
/// room. A full table keeps the hosts it has: a program could evict the oldest instead.
fn find_or_add(address: server.Address) ?*Entry {
    if (find(address)) |entry| return entry;
    if (entries_len == entries_max) return null;
    entries[entries_len] = .{ .address = address, .saved = null, .open = 0 };
    entries_len += 1;
    return &entries[entries_len - 1];
}

fn put(_: *anyopaque, address: server.Address, observed: ?server.ResumeState, now_ns: u64) void {
    _ = now_ns;
    put_back += 1;
    // A host that a full table left out took nothing, so it saves nothing.
    const entry = find(address) orelse return;
    // Each `put` names the address of its own `take`, so the count is above zero.
    entry.open -= 1;
    if (observed) |state| entry.saved = state;
}

fn drop(_: *anyopaque, address: server.Address) void {
    dropped += 1;
    // RFC 9959 §3.5: "The set of saved CC parameters for the path are deleted".
    if (find(address)) |entry| entry.saved = null;
}

/// Checks that a client's next connection, from another port, gets the set that its first one
/// saved (RFC 9959 §2.2), and that a second open connection of the host gets none (§3.2). Then
/// it empties the table and the counts. `server_exchange.zig` calls it before its server starts.
pub fn check_another_port() !void {
    const host = [_]u8{ 127, 0, 0, 1 };
    const first: server.Address = .init(&host, first_port);
    const next: server.Address = .init(&host, first_port + 1);
    const other: server.Address = .init(&host, first_port + 2);
    const saved: server.ResumeState = .{ .window_len = check_window_len, .rtt_ns = check_rtt_ns, .saved_at_ns = 0 };
    if (take(&context, first, 0) != null) return error.SetWrong;
    put(&context, first, saved, 0);
    const taken_set = take(&context, next, 0) orelse return error.SetNotFound;
    if (taken_set.window_len != check_window_len) return error.SetWrong;
    // The host has two open connections, and the second one's end leaves the first one open.
    if (take(&context, other, 0) != null) return error.SetGivenTwice;
    put(&context, other, null, 0);
    if (take(&context, other, 0) != null) return error.SetGivenTwice;
    entries_len = 0;
    taken = 0;
    put_back = 0;
    dropped = 0;
}

/// The values of the check's set and the port of its first connection.
const first_port = 40000;
const check_window_len = 12000;
const check_rtt_ns = 25_000_000;
