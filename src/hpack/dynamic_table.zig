//! The dynamic table of RFC 7541 §2.3.2 and §4: a first-in, first-out list of field lines whose
//! accounted size never exceeds its capacity. The decoder and the encoder each keep one, and the
//! encoder's is a mirror of what its peer's decoder holds.
//!
//! The table owns no memory (decision 35). Its entries' octets are stored in a fixed buffer of
//! `dynamic_table_capacity_max` octets, oldest first, and its entry records in a ring of
//! `dynamic_table_entries_max`. Eviction advances the start of the live octets; an insert that
//! would run past the buffer's end first moves the live octets to its start, which happens at most
//! once per buffer of octets inserted.
//!
//! Index 1 is the newest entry and `len()` the oldest (§2.3.2), before the static table's length
//! is added to give the fused address space of §2.3.3, which the decoder does.
//!
//! Invariant 11: the accounted size is recomputed from the entries after every insert and every
//! eviction, and must equal the sum of `entry_size` over them.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");
const constants = @import("constants.zig");

const entry_size = wire.table_size.entry_size;

/// One field line: a name and a value, unencoded.
pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

/// Where an entry's octets are: its name, then its value, at `offset`.
const Entry = struct {
    offset: u32,
    name_len: u32,
    value_len: u32,
};

/// The lowest indices at which a field is found: the newest exact match, and the newest entry
/// sharing its name.
pub const Match = struct {
    exact: ?u32 = null,
    name: ?u32 = null,
};

pub const DynamicTable = struct {
    octets: [constants.dynamic_table_capacity_max]u8,
    entries: [constants.dynamic_table_entries_max]Entry,
    /// The oldest entry's slot in `entries`; the newest is `count - 1` slots after it, wrapping.
    first: u32,
    count: u32,
    /// The live octets: `octets[octets_start..octets_end]`, oldest entry first.
    octets_start: u32,
    octets_end: u32,
    /// The size of RFC 7541 §4.1: the sum of `entry_size` over the entries.
    size: u64,
    /// The maximum size in force (RFC 7541 §4.2), at most `dynamic_table_capacity_max`.
    capacity: u64,

    pub fn init(table: *DynamicTable, capacity: u64) void {
        assert(capacity <= constants.dynamic_table_capacity_max);
        table.first = 0;
        table.count = 0;
        table.octets_start = 0;
        table.octets_end = 0;
        table.size = 0;
        table.capacity = capacity;
        assert(table.len() == 0 and table.size == 0);
    }

    /// Entries held.
    pub fn len(table: *const DynamicTable) u32 {
        return table.count;
    }

    /// The entry at `index`, 1 for the newest and `len()` for the oldest (RFC 7541 §2.3.2), or
    /// null past the oldest. The slices are valid until the next insert or resize.
    pub fn get(table: *const DynamicTable, index: u64) ?Field {
        if (index == 0 or index > table.count) return null;
        const slot = (table.first + table.count - @as(u32, @intCast(index))) % constants.dynamic_table_entries_max;
        return table.field(&table.entries[slot]);
    }

    /// The lowest indices at which `name` and `value` are found, scanning newest first.
    pub fn find(table: *const DynamicTable, name: []const u8, value: []const u8) Match {
        var match: Match = .{};
        for (1..table.count + 1) |index| {
            const entry = table.get(index).?;
            if (!std.mem.eql(u8, entry.name, name)) continue;
            if (match.name == null) match.name = @intCast(index);
            if (std.mem.eql(u8, entry.value, value)) {
                match.exact = @intCast(index);
                return match;
            }
        }
        return match;
    }

    /// Changes the maximum size, evicting from the oldest end until the table fits (RFC 7541
    /// §4.3).
    pub fn resize(table: *DynamicTable, capacity: u64) void {
        assert(capacity <= constants.dynamic_table_capacity_max);
        table.capacity = capacity;
        table.evict_until_fits(0);
        assert(table.size <= table.capacity);
    }

    /// Adds a field as the newest entry, evicting from the oldest end first (RFC 7541 §4.4). An
    /// entry larger than the capacity is not added, and the table is left empty.
    pub fn insert(table: *DynamicTable, name: []const u8, value: []const u8) void {
        assert(name.len <= constants.name_len_max and value.len <= constants.value_len_max);
        const size = entry_size(name.len, value.len);
        // RFC 7541 §4.4: evict until the table is at or below (maximum size - new entry size), or
        // it is empty.
        table.evict_until_fits(size);
        // RFC 7541 §4.4: an entry larger than the maximum size empties the table and is not added.
        if (size > table.capacity) {
            assert(table.count == 0);
            return;
        }
        table.make_room(@intCast(name.len + value.len));
        const slot = (table.first + table.count) % constants.dynamic_table_entries_max;
        table.entries[slot] = .{
            .offset = table.octets_end,
            .name_len = @intCast(name.len),
            .value_len = @intCast(value.len),
        };
        @memcpy(table.octets[table.octets_end..][0..name.len], name);
        @memcpy(table.octets[table.octets_end + name.len ..][0..value.len], value);
        table.octets_end += @intCast(name.len + value.len);
        table.count += 1;
        table.size += size;
        assert(table.count <= constants.dynamic_table_entries_max);
        table.check_accounting();
    }

    fn field(table: *const DynamicTable, entry: *const Entry) Field {
        const name_end = entry.offset + entry.name_len;
        return .{
            .name = table.octets[entry.offset..name_end],
            .value = table.octets[name_end .. name_end + entry.value_len],
        };
    }

    /// Evicts oldest entries until `size` more octets fit under the capacity, or none are left.
    fn evict_until_fits(table: *DynamicTable, size: u64) void {
        // Each pass evicts one entry, so the table's own count bounds the loop.
        for (0..constants.dynamic_table_entries_max) |_| {
            if (table.count == 0 or table.size + size <= table.capacity) break;
            table.evict_oldest();
        }
        assert(table.count == 0 or table.size + size <= table.capacity);
    }

    fn evict_oldest(table: *DynamicTable) void {
        assert(table.count > 0);
        const entry = &table.entries[table.first];
        assert(entry.offset == table.octets_start);
        table.octets_start += entry.name_len + entry.value_len;
        table.size -= entry_size(entry.name_len, entry.value_len);
        table.first = (table.first + 1) % constants.dynamic_table_entries_max;
        table.count -= 1;
        if (table.count == 0) {
            table.octets_start = 0;
            table.octets_end = 0;
        }
        table.check_accounting();
    }

    /// Moves the live octets to the buffer's start when `needed` more would run past its end.
    fn make_room(table: *DynamicTable, needed: u32) void {
        if (table.octets_end + needed <= constants.dynamic_table_capacity_max) return;
        const live = table.octets_end - table.octets_start;
        std.mem.copyForwards(u8, table.octets[0..live], table.octets[table.octets_start..table.octets_end]);
        for (0..table.count) |offset| {
            const slot = (table.first + offset) % constants.dynamic_table_entries_max;
            table.entries[slot].offset -= table.octets_start;
        }
        table.octets_start = 0;
        table.octets_end = live;
        // The accounted size bounds the live octets: every entry that fits under the capacity
        // fits in the buffer once the dead octets before the oldest entry are gone.
        assert(table.octets_end + needed <= constants.dynamic_table_capacity_max);
    }

    /// Invariant 11: the accounted size is the sum over the entries. The bound against the
    /// capacity is asserted by `insert` and `resize` once their evictions are done, since the sum
    /// is over the bound between one eviction and the next.
    fn check_accounting(table: *const DynamicTable) void {
        var sum: u64 = 0;
        for (0..table.count) |offset| {
            const slot = (table.first + offset) % constants.dynamic_table_entries_max;
            const entry = &table.entries[slot];
            sum += entry_size(entry.name_len, entry.value_len);
        }
        assert(sum == table.size);
    }
};

const testing = std.testing;

/// The table the tests run in, placed outside any stack frame.
var test_table: DynamicTable = undefined;

fn expect_entry(index: u64, name: []const u8, value: []const u8) !void {
    const entry = test_table.get(index) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings(name, entry.name);
    try testing.expectEqualStrings(value, entry.value);
}

test "RFC 7541 Appendix C.3: three inserts, newest at index 1, sizes 57, 110 and 164" {
    test_table.init(4096);
    test_table.insert(":authority", "www.example.com");
    try testing.expectEqual(57, test_table.size);
    test_table.insert("cache-control", "no-cache");
    try testing.expectEqual(110, test_table.size);
    test_table.insert("custom-key", "custom-value");
    try testing.expectEqual(164, test_table.size);
    try testing.expectEqual(3, test_table.len());
    try expect_entry(1, "custom-key", "custom-value");
    try expect_entry(2, "cache-control", "no-cache");
    try expect_entry(3, ":authority", "www.example.com");
    try testing.expectEqual(null, test_table.get(0));
    try testing.expectEqual(null, test_table.get(4));
}

test "RFC 7541 Appendix C.5: at capacity 256 the oldest entry is evicted to make room" {
    test_table.init(256);
    test_table.insert(":status", "302");
    test_table.insert("cache-control", "private");
    test_table.insert("date", "Mon, 21 Oct 2013 20:13:21 GMT");
    test_table.insert("location", "https://www.example.com");
    try testing.expectEqual(222, test_table.size);
    test_table.insert(":status", "307");
    try testing.expectEqual(222, test_table.size);
    try testing.expectEqual(4, test_table.len());
    try expect_entry(1, ":status", "307");
    try expect_entry(4, "cache-control", "private");
}

test "an entry larger than the capacity empties the table and is not added (§4.4)" {
    test_table.init(80);
    test_table.insert("a", "b");
    test_table.insert("c", "d");
    try testing.expectEqual(2, test_table.len());
    const long: [60]u8 = @splat('v');
    test_table.insert("name", &long);
    try testing.expectEqual(0, test_table.len());
    try testing.expectEqual(0, test_table.size);
    test_table.insert("e", "f");
    try expect_entry(1, "e", "f");
}

test "an entry that exactly fills the capacity is added, and two that exactly fill it both stay" {
    test_table.init(34);
    test_table.insert("a", "b");
    try testing.expectEqual(1, test_table.len());
    test_table.init(68);
    test_table.insert("a", "b");
    test_table.insert("c", "d");
    try testing.expectEqual(2, test_table.len());
    try testing.expectEqual(68, test_table.size);
}

test "resize evicts to the new capacity, and a resize to 0 empties the table (§4.3)" {
    test_table.init(4096);
    test_table.insert(":authority", "www.example.com");
    test_table.insert("cache-control", "no-cache");
    test_table.resize(60);
    try testing.expectEqual(1, test_table.len());
    try expect_entry(1, "cache-control", "no-cache");
    test_table.resize(0);
    try testing.expectEqual(0, test_table.len());
    test_table.resize(4096);
    test_table.insert("a", "b");
    try testing.expectEqual(1, test_table.len());
}

test "find reports the newest exact match and the newest name match" {
    test_table.init(4096);
    test_table.insert("k", "old");
    test_table.insert("k", "new");
    test_table.insert("other", "x");
    try testing.expectEqual(Match{ .exact = 2, .name = 2 }, test_table.find("k", "new"));
    try testing.expectEqual(Match{ .exact = 3, .name = 2 }, test_table.find("k", "old"));
    try testing.expectEqual(Match{ .exact = null, .name = 2 }, test_table.find("k", "none"));
    try testing.expectEqual(Match{}, test_table.find("absent", "x"));
    test_table.insert("k", "new");
    try testing.expectEqual(Match{ .exact = 1, .name = 1 }, test_table.find("k", "new"));
}

test "the octet buffer wraps: many inserts past its end keep every live entry readable" {
    test_table.init(constants.dynamic_table_capacity_max);
    const value: [1000]u8 = @splat('v');
    var expected_count: u32 = 0;
    for (0..64) |round| {
        var name: [4]u8 = @splat('n');
        name[3] = @intCast('a' + round % 26);
        test_table.insert(&name, &value);
        expected_count = @min(expected_count + 1, constants.dynamic_table_capacity_max / (4 + 1000 + 32));
        try testing.expectEqual(expected_count, test_table.len());
        try expect_entry(1, &name, &value);
    }
    try expect_entry(test_table.len(), test_table.get(test_table.len()).?.name, &value);
}
