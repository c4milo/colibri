//! Part of `server_exchange.zig`: where the server keeps RFC 9959's saved sets between
//! connections (decision 149, design §8 step 35d).
//!
//! colibri holds nothing between connections, so a program that wants a later connection from a
//! client to start near an earlier one's rate keeps the sets itself, keyed by the client's address,
//! and gives the endpoint a `server.ResumeProvider` over them:
//! - `take` answers the set saved for an address, and claims it for one connection, because RFC
//!   9959 §3.2 lets one connection at a time use a set;
//! - `put` comes once when that connection ends, with what it observed, which replaces the set,
//!   or with null, which keeps it; either way the claim ends;
//! - `drop` comes first when the connection retreated, and the set goes (§3.5).
//!
//! This table holds a few addresses in storage the program owns, with no allocator, and counts the
//! calls, which `server_exchange.zig` checks.
const std = @import("std");
const server = @import("server");

/// The clients whose sets the table holds at once. A program sizes it for the clients it expects.
const entries_max = 4;

const Entry = struct {
    address: server.Address,
    saved: ?server.ResumeState,
    claimed: bool,
};

var entries: [entries_max]Entry align(@alignOf(Entry)) = undefined;
var entries_len: usize = 0;
var context: u8 = 0;

/// How often the endpoint called each of the three, which `server_exchange.zig` checks.
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
        if (entry.address.eql(&address)) return entry;
    }
    return null;
}

fn take(_: *anyopaque, address: server.Address, now_ns: u64) ?server.ResumeState {
    _ = now_ns;
    taken += 1;
    const entry = find(address) orelse return null;
    // RFC 9959 §3.2: a set another connection holds is not given twice.
    if (entry.claimed) return null;
    entry.claimed = entry.saved != null;
    return entry.saved;
}

fn put(_: *anyopaque, address: server.Address, observed: ?server.ResumeState, now_ns: u64) void {
    _ = now_ns;
    put_back += 1;
    const entry = find(address) orelse {
        // A full table keeps the sets it has: a program could evict the oldest instead.
        if (observed == null or entries_len == entries_max) return;
        entries[entries_len] = .{ .address = address, .saved = observed, .claimed = false };
        entries_len += 1;
        return;
    };
    entry.claimed = false;
    if (observed) |state| entry.saved = state;
}

fn drop(_: *anyopaque, address: server.Address) void {
    dropped += 1;
    // RFC 9959 §3.5: "The set of saved CC parameters for the path are deleted".
    if (find(address)) |entry| entry.saved = null;
}
