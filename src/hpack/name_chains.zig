//! The chains of the encoder's mirror by name: for each name of the static table, and for every
//! other name together, the mirror's entries of it, newest first (RFC 7541 §2.3.2). The encoder
//! finds a line by reading one chain, where a scan of the whole table compared each entry's name.
//! A response's lines go into the table (decision 132), and a server's `date` line inserts a new
//! value each second, so a table may hold many entries of one name.
//!
//! An entry is named by its insert number, the count of the encoder's inserts before it, kept in
//! a `Number` that wraps. Its index is the count of inserts since it, so an insert or an eviction
//! changes no link. A link whose index is past the table's length names an entry the table
//! evicted, and every link after it is older still, so the walk ends there.
//!
//! Each entry a walk finds is read from the table and compared with the line, so a link that a
//! wrapped number makes look live costs a compare, and never a wrong index. A walk reads at most
//! as many links as the table holds entries.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const dynamic_table = @import("dynamic_table.zig");

const DynamicTable = dynamic_table.DynamicTable;
const Match = dynamic_table.Match;

/// An insert number. It wraps, and a table never holds as many entries as it can count, so the
/// difference of two numbers gives an entry's index while the entry is live.
const Number = u16;

/// One chain for each static index a name can start at, and chain 0 for the names the static
/// table does not hold.
const chain_count = constants.protocol.static_table_len + 1;

comptime {
    assert(constants.limits.dynamic_table_entries_max < std.math.maxInt(Number));
    assert(chain_count <= std.math.maxInt(u8));
}

pub const NameChains = struct {
    /// Each chain's newest entry: its insert number plus one, or 0 for none.
    heads: [chain_count]Number,
    /// For the entry whose insert number is the slot's, modulo the table's most entries, the next
    /// older entry of its chain: its insert number plus one, or 0 for none. An insert writes its
    /// slot before a walk can reach it, so `init` writes none.
    next: [constants.limits.dynamic_table_entries_max]Number,
    /// The count of inserts, wrapping: the number the next entry takes.
    inserted: Number,

    pub fn init(chains: *NameChains) void {
        chains.heads = @splat(0);
        chains.inserted = 0;
        assert(chains.heads[0] == 0);
    }

    /// Notes that the table just inserted a line whose name starts at static index `chain`, or
    /// one the static table does not hold, for 0. An entry numbered `maxInt(Number)` is stored as
    /// 0, which reads as no entry: its chain loses it, which costs a later line its index.
    pub fn insert(chains: *NameChains, chain: u32) void {
        assert(chain < chain_count);
        const number = chains.inserted;
        chains.next[number % constants.limits.dynamic_table_entries_max] = chains.heads[chain];
        chains.heads[chain] = number +% 1;
        chains.inserted = number +% 1;
    }

    /// The lowest indices of `table` holding the line and its name, from the chain `chain` alone.
    /// `table` is the mirror whose inserts the chains noted.
    pub fn find(chains: *const NameChains, table: *const DynamicTable, chain: u32, name: []const u8, value: []const u8) Match {
        assert(chain < chain_count);
        var match: Match = .{};
        var link = chains.heads[chain];
        var index_previous: u32 = 0;
        // Bounded by the entries the table holds: each pass reads an older one.
        for (0..table.len()) |_| {
            if (link == 0) break;
            const number: Number = link - 1;
            const index: u32 = chains.inserted -% number;
            // An index no greater than the last is a wrapped number, and one past the table's
            // length is an entry the table evicted. Every later link is older, so none is live.
            if (index <= index_previous or index > table.len()) break;
            index_previous = index;
            const entry = table.get(index).?;
            if (same(entry.name, name)) {
                if (match.name == null) match.name = index;
                if (same(entry.value, value)) {
                    match.exact = index;
                    return match;
                }
            }
            link = chains.next[number % constants.limits.dynamic_table_entries_max];
        }
        return match;
    }
};

/// Whether two strings are equal. The lengths are compared first, here, since most entries of a
/// chain differ in length from the line.
inline fn same(a: []const u8, b: []const u8) bool {
    return a.len == b.len and std.mem.eql(u8, a, b);
}

const testing = std.testing;

/// The table and the chains the tests fill, placed outside any stack frame.
threadlocal var test_table: DynamicTable align(@alignOf(DynamicTable)) = undefined;
threadlocal var test_chains: NameChains align(@alignOf(NameChains)) = undefined;

/// Inserts a line into both, as the encoder does.
fn test_insert(chain: u32, name: []const u8, value: []const u8) void {
    test_table.insert(name, value);
    test_chains.insert(chain);
}

test "RFC 7541 §2.3.2: a chain finds the newest entry of its name, and the newest exact one" {
    test_table.init(4096);
    test_chains.init();
    test_insert(31, "content-type", "text/plain");
    test_insert(28, "content-length", "2");
    test_insert(31, "content-type", "text/html");
    // Index 1 is the newest: content-type text/html, then content-length, then text/plain.
    try testing.expectEqual(Match{ .exact = 1, .name = 1 }, test_chains.find(&test_table, 31, "content-type", "text/html"));
    try testing.expectEqual(Match{ .exact = 3, .name = 1 }, test_chains.find(&test_table, 31, "content-type", "text/plain"));
    try testing.expectEqual(Match{ .exact = null, .name = 1 }, test_chains.find(&test_table, 31, "content-type", "image/png"));
    try testing.expectEqual(Match{ .exact = 2, .name = 2 }, test_chains.find(&test_table, 28, "content-length", "2"));
    try testing.expectEqual(Match{}, test_chains.find(&test_table, 33, "date", "x"));
}

test "names the static table does not hold share chain 0, and each is compared" {
    test_table.init(4096);
    test_chains.init();
    test_insert(0, "x-one", "a");
    test_insert(0, "x-two", "b");
    test_insert(0, "x-one", "c");
    try testing.expectEqual(Match{ .exact = 2, .name = 2 }, test_chains.find(&test_table, 0, "x-two", "b"));
    try testing.expectEqual(Match{ .exact = 3, .name = 1 }, test_chains.find(&test_table, 0, "x-one", "a"));
    try testing.expectEqual(Match{ .exact = null, .name = 1 }, test_chains.find(&test_table, 0, "x-one", "d"));
    try testing.expectEqual(Match{}, test_chains.find(&test_table, 0, "x-three", "a"));
}

test "RFC 7541 §4.4: an evicted entry ends its chain, and an emptied table finds nothing" {
    // Each entry takes 32 + 1 + 1 = 34 bytes of the §4.1 accounting, so 100 bytes hold two.
    test_table.init(100);
    test_chains.init();
    test_insert(0, "a", "1");
    test_insert(0, "a", "2");
    test_insert(0, "a", "3");
    try testing.expectEqual(@as(u32, 2), test_table.len());
    try testing.expectEqual(Match{ .exact = 2, .name = 1 }, test_chains.find(&test_table, 0, "a", "2"));
    try testing.expectEqual(Match{ .exact = null, .name = 1 }, test_chains.find(&test_table, 0, "a", "1"));
    // RFC 7541 §4.3: a size update to 0 evicts every entry.
    test_table.resize(0);
    test_table.resize(100);
    try testing.expectEqual(Match{}, test_chains.find(&test_table, 0, "a", "3"));
    test_insert(0, "a", "4");
    try testing.expectEqual(Match{ .exact = 1, .name = 1 }, test_chains.find(&test_table, 0, "a", "4"));
    try testing.expectEqual(Match{ .exact = null, .name = 1 }, test_chains.find(&test_table, 0, "a", "3"));
}

test "the chains find what a scan of the table finds, over inserts that wrap the numbers" {
    test_table.init(4096);
    test_chains.init();
    const names = [_][]const u8{ "content-type", "content-length", "date", "x-one", "x-two" };
    const chains = [_]u32{ 31, 28, 33, 0, 0 };
    const values = [_][]const u8{ "a", "bb", "ccc", "dddd" };
    const numbers: usize = @as(usize, std.math.maxInt(Number)) + 1;
    // Three times the numbers a `Number` holds, so the numbers wrap and an entry is stored as
    // no entry three times.
    for (0..3 * numbers) |step| {
        const which = (step * 7) % names.len;
        test_insert(chains[which], names[which], values[(step * 3) % values.len]);
        if (step % 4099 != 0) continue;
        // The inserts since the last entry numbered `maxInt(Number)`, which its chain lost. While
        // the table holds it, its chain cannot reach it or any older entry of its name.
        const since_lost = (step + 1) % numbers;
        try expect_as_scan(&names, &chains, &values, step + 1 < numbers or since_lost > test_table.len());
    }
}

/// Requires the chains to find, for each name and value, what a scan of the table finds: anything
/// a chain finds is at the scan's index, and with `whole` the two finds are equal.
fn expect_as_scan(names: []const []const u8, chains: []const u32, values: []const []const u8, whole: bool) !void {
    for (names, chains) |name, chain| {
        for (values) |value| {
            const scanned = test_table.find(name, value);
            const chained = test_chains.find(&test_table, chain, name, value);
            if (chained.exact) |index| try testing.expectEqual(scanned.exact.?, index);
            if (chained.name) |index| try testing.expectEqual(scanned.name.?, index);
            if (whole) try testing.expectEqual(scanned, chained);
        }
    }
}
