//! QPACK's dynamic table (RFC 9204 §3.2). Part of design §8 step 11.
//!
//! A first-in, first-out list of field lines the encoder fills over the encoder stream. It is
//! **not** HPACK's table with different numbers: [decision 12](../../docs/decisions.md) records
//! why they cannot be one. HPACK fuses the static and dynamic tables into one address space
//! (RFC 7541 §2.3.3); RFC 9204 §3 opens by saying the opposite, that the two are addressed
//! separately, with a `T` bit to say which. What the two do share is §3.2.1's size arithmetic,
//! which lives in `wire.table_size` and is decision 11.
//!
//! **Three ways to name an entry, and they are not interchangeable.** §3.2.4's absolute index is
//! fixed for the entry's life, counting from the first ever inserted. §3.2.5's relative index
//! counts backwards, from the newest entry on the encoder stream and from the Base in a field
//! line representation — two different origins with one name, which is the part worth reading
//! twice. §3.2.6's post-base index counts forwards from the Base. All three resolve to an
//! absolute index here, and nothing else in the module resolves one.
//!
//! The caller owns the storage (decision 35): the octets and the entry slots are inside the
//! struct, and `dynamic_table_capacity_max` bounds both.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");
const constants = @import("constants.zig");

const entry_size = wire.table_size.entry_size;

pub const Error = error{
    /// RFC 9204 §3.2.2: an entry larger than the capacity, which the decoder MUST treat as a
    /// connection error of QPACK_ENCODER_STREAM_ERROR.
    EntryTooLarge,
    /// RFC 9204 §3.2.3: a capacity above the maximum this endpoint advertised, which an encoder
    /// MUST NOT set.
    CapacityTooLarge,
};

/// One field line: a name and a value, unencoded (RFC 9204 §3.2.1 measures both before any
/// Huffman coding).
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

/// The absolute indices at which a field is found: the newest exact match, and the newest entry
/// sharing its name (RFC 9204 §3.2.4).
pub const Match = struct {
    exact: ?u64 = null,
    name: ?u64 = null,
};

pub const DynamicTable = struct {
    octets: [constants.dynamic_table_capacity_max]u8,
    entries: [constants.dynamic_table_entries_max]Entry,
    /// The oldest entry's slot; the newest is `count - 1` slots after it, wrapping.
    first: u32,
    count: u32,
    /// The live octets: `octets[octets_start..octets_end]`, oldest entry first.
    octets_start: u32,
    octets_end: u32,
    /// RFC 9204 §3.2.1's size, and §3.2.2's capacity, which starts at zero.
    size: u64,
    capacity: u64,
    /// RFC 9204 §3.2.3's maximum, which the decoder advertises and the encoder may not exceed.
    capacity_max: u64,
    /// RFC 9204 §3.2.4: how many entries have ever been inserted, and how many have been
    /// dropped. An absolute index is fixed for an entry's life, so these only ever rise and the
    /// live entries are the absolute indices in `[dropped, inserted)`.
    inserted: u64,
    dropped: u64,

    /// RFC 9204 §3.2.2: the initial capacity of the dynamic table is zero, and the encoder sends
    /// a Set Dynamic Table Capacity instruction to begin using it.
    pub fn init(table: *DynamicTable, capacity_max: u64) void {
        assert(capacity_max <= constants.dynamic_table_capacity_max);
        table.first = 0;
        table.count = 0;
        table.octets_start = 0;
        table.octets_end = 0;
        table.size = 0;
        table.capacity = 0;
        table.capacity_max = capacity_max;
        table.inserted = 0;
        table.dropped = 0;
    }

    /// RFC 9204 §2.1.4 and §4.5.1.1's insert count: how many entries have ever been inserted,
    /// which is also the absolute index the next one will take.
    pub fn insert_count(table: *const DynamicTable) u64 {
        return table.inserted;
    }

    /// RFC 9204 §4.5.1.1's `MaxEntries`: the most entries the table could hold, which is the
    /// maximum capacity over §3.2.1's smallest entry. The Required Insert Count is encoded
    /// modulo twice this, which is what keeps the prefix short on a long-lived connection.
    pub fn max_entries(table: *const DynamicTable) u64 {
        return table.capacity_max / constants.entry_overhead_len;
    }

    /// RFC 9204 §4.3.1's Set Dynamic Table Capacity. Reducing it evicts from the oldest end
    /// until the table fits (§3.2.2).
    pub fn set_capacity(table: *DynamicTable, capacity: u64) Error!void {
        // §3.2.3: an encoder MUST NOT set a capacity that exceeds the maximum the decoder
        // advertised, so a decoder that sees one refuses the instruction.
        if (capacity > table.capacity_max) return Error.CapacityTooLarge;
        table.capacity = capacity;
        table.evict_until_fits(0);
        assert(table.size <= table.capacity);
    }

    /// Adds a field as the newest entry (RFC 9204 §3.2.2), evicting from the oldest end first.
    pub fn insert(table: *DynamicTable, name: []const u8, value: []const u8) Error!void {
        const size = entry_size(name.len, value.len);
        // §3.2.2: it is an error if the encoder attempts to add an entry larger than the
        // capacity, and the decoder MUST treat it as a connection error. Unlike RFC 7541 §4.4,
        // which empties the table instead, so this is not HPACK's rule with a new name.
        if (size > table.capacity) return Error.EntryTooLarge;
        // §3.2.2: evict until the size is at or below the capacity less the new entry's size.
        table.evict_until_fits(size);
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
        // §3.2.4: indices increase by one with each insertion and are never reused.
        table.inserted += 1;
        assert(table.count <= constants.dynamic_table_entries_max);
        assert(table.inserted - table.dropped == table.count);
    }

    /// The entry with absolute index `absolute` (RFC 9204 §3.2.4), or null when it was never
    /// inserted or has been evicted.
    pub fn get_absolute(table: *const DynamicTable, absolute: u64) ?Field {
        if (absolute < table.dropped or absolute >= table.inserted) return null;
        const from_oldest: u32 = @intCast(absolute - table.dropped);
        const slot = (table.first + from_oldest) % constants.dynamic_table_entries_max;
        return table.field(&table.entries[slot]);
    }

    /// RFC 9204 §3.2.5, in a field line representation: a relative index of 0 refers to the
    /// entry with absolute index `base - 1`.
    pub fn get_relative_to_base(table: *const DynamicTable, base: u64, relative: u64) ?Field {
        if (base == 0 or relative >= base) return null;
        return table.get_absolute(base - 1 - relative);
    }

    /// RFC 9204 §3.2.5, in an encoder instruction: a relative index of 0 refers to the most
    /// recently inserted entry, so the origin moves as the instructions are read.
    ///
    /// It is the representation form with the Base at the insert count, and that is arithmetic
    /// rather than coincidence: relative 0 on the encoder stream is absolute `inserted - 1`, and
    /// relative 0 in a representation is absolute `base - 1`. Writing it once is what keeps the
    /// two from drifting; what still differs is which origin a caller must pass, which is the
    /// part §3.2.5 warns about.
    pub fn get_relative_to_insertion(table: *const DynamicTable, relative: u64) ?Field {
        return table.get_relative_to_base(table.inserted, relative);
    }

    /// RFC 9204 §3.2.6: a post-Base index of 0 refers to the entry with absolute index `base`,
    /// and they count forwards from there.
    pub fn get_post_base(table: *const DynamicTable, base: u64, index: u64) ?Field {
        return table.get_absolute(base +| index);
    }

    /// The newest absolute index holding the field, and the newest holding its name. The newest
    /// is the one to take: RFC 9204 §2.1.1 makes an older entry likelier to be evicted, and an
    /// eviction would strand the reference.
    pub fn find(table: *const DynamicTable, name: []const u8, value: []const u8) Match {
        var match: Match = .{};
        // Bounded by the entry count, which is a named limit.
        for (0..table.count) |step| {
            const absolute = table.inserted - 1 - step;
            const held = table.get_absolute(absolute).?;
            if (!std.mem.eql(u8, held.name, name)) continue;
            if (match.name == null) match.name = absolute;
            if (std.mem.eql(u8, held.value, value)) {
                match.exact = absolute;
                return match;
            }
        }
        return match;
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
        // Each pass evicts one entry, so the entry count bounds the loop.
        for (0..constants.dynamic_table_entries_max) |_| {
            if (table.count == 0 or table.size + size <= table.capacity) break;
            table.evict_oldest();
        }
    }

    /// Drops the oldest entry (RFC 9204 §3.2.2 evicts from the end of the table).
    fn evict_oldest(table: *DynamicTable) void {
        assert(table.count > 0);
        const entry = table.entries[table.first];
        table.octets_start += entry.name_len + entry.value_len;
        table.size -= entry_size(entry.name_len, entry.value_len);
        table.first = (table.first + 1) % constants.dynamic_table_entries_max;
        table.count -= 1;
        // §3.2.4: a dropped entry's absolute index is never reused, so the floor only rises.
        table.dropped += 1;
        if (table.count == 0) {
            table.octets_start = 0;
            table.octets_end = 0;
        }
    }

    /// Moves the live octets to the front where `len` more will not fit after them. The entries
    /// hold offsets rather than slices, so moving them is a copy and a rebase.
    fn make_room(table: *DynamicTable, len: u32) void {
        if (table.octets_end + len <= constants.dynamic_table_capacity_max) return;
        const live = table.octets_end - table.octets_start;
        std.mem.copyForwards(u8, table.octets[0..live], table.octets[table.octets_start..table.octets_end]);
        // Bounded by the entry count, which is a named limit.
        for (0..table.count) |step| {
            const slot = (table.first + step) % constants.dynamic_table_entries_max;
            table.entries[slot].offset -= table.octets_start;
        }
        table.octets_start = 0;
        table.octets_end = live;
        assert(table.octets_end + len <= constants.dynamic_table_capacity_max);
    }
};

const testing = std.testing;

/// The table the tests drive, placed outside any stack frame. Test-only.
var test_table: DynamicTable = undefined;
/// A capacity that holds a handful of small entries, and the size one of them takes: §3.2.1's
/// overhead plus a one-octet name and a one-octet value.
const test_entries: u64 = 4;
const test_capacity: u64 = test_entries * small_entry_len;
const small_entry_len: u64 = constants.entry_overhead_len + test_name_len + test_value_len;
const test_name_len: u64 = 1;
const test_value_len: u64 = 1;

/// Fills the table with `count` entries named `a`, `b`, … each with a one-octet value.
fn fill(count: u8) !void {
    for (0..count) |step| {
        const name = [_]u8{'a' + @as(u8, @intCast(step))};
        try test_table.insert(&name, "v");
    }
}

test "§3.2.2: the table starts empty with a capacity of zero" {
    test_table.init(constants.dynamic_table_capacity_max);
    try testing.expectEqual(0, test_table.capacity);
    try testing.expectEqual(0, test_table.insert_count());
    // §3.2.2: nothing fits until the encoder sets a capacity, so the first insert is refused.
    try testing.expectError(Error.EntryTooLarge, test_table.insert("a", "v"));
    try test_table.set_capacity(test_capacity);
    try test_table.insert("a", "v");
    try testing.expectEqual(1, test_table.insert_count());
    try testing.expectEqual(small_entry_len, test_table.size);
}

test "§3.2.3: a capacity above what the decoder advertised is refused" {
    test_table.init(test_capacity);
    try test_table.set_capacity(test_capacity);
    // §3.2.3: an encoder MUST NOT set a capacity that exceeds the maximum, but MAY use a lower one.
    try testing.expectError(Error.CapacityTooLarge, test_table.set_capacity(test_capacity + 1));
    try testing.expectEqual(test_capacity, test_table.capacity);
    try test_table.set_capacity(small_entry_len);
    try testing.expectEqual(small_entry_len, test_table.capacity);
}

test "§3.2.4: an absolute index is fixed for the entry's life and never reused" {
    test_table.init(constants.dynamic_table_capacity_max);
    try test_table.set_capacity(test_capacity);
    try fill(4);
    // §3.2.4: the first entry inserted has absolute index 0 and they increase by one.
    try testing.expectEqualStrings("a", test_table.get_absolute(0).?.name);
    try testing.expectEqualStrings("d", test_table.get_absolute(3).?.name);
    try testing.expectEqual(null, test_table.get_absolute(4));
    // A fifth evicts the oldest, and index 0 is gone rather than renamed.
    try test_table.insert("e", "v");
    try testing.expectEqual(null, test_table.get_absolute(0));
    try testing.expectEqualStrings("b", test_table.get_absolute(1).?.name);
    try testing.expectEqualStrings("e", test_table.get_absolute(4).?.name);
    try testing.expectEqual(5, test_table.insert_count());
    try testing.expectEqual(1, test_table.dropped);
}

test "§3.2.5: a relative index means one thing on the encoder stream and another in a section" {
    test_table.init(constants.dynamic_table_capacity_max);
    try test_table.set_capacity(test_capacity);
    try fill(4);
    // In an encoder instruction, relative 0 is the most recently inserted entry.
    try testing.expectEqualStrings("d", test_table.get_relative_to_insertion(0).?.name);
    try testing.expectEqualStrings("a", test_table.get_relative_to_insertion(3).?.name);
    try testing.expectEqual(null, test_table.get_relative_to_insertion(4));
    // In a field line representation, relative 0 is the entry with absolute index Base - 1. With
    // a Base of 3 that is `c`, not `d`, which is the whole point of §4.5.1's stable references.
    try testing.expectEqualStrings("c", test_table.get_relative_to_base(3, 0).?.name);
    try testing.expectEqualStrings("a", test_table.get_relative_to_base(3, 2).?.name);
    try testing.expectEqual(null, test_table.get_relative_to_base(3, 3));
    // A Base of 0 names nothing below it.
    try testing.expectEqual(null, test_table.get_relative_to_base(0, 0));
}

test "§3.2.6: a post-Base index counts forward from the Base" {
    test_table.init(constants.dynamic_table_capacity_max);
    try test_table.set_capacity(test_capacity);
    try fill(4);
    // With a Base of 2, post-Base 0 is absolute 2 and 1 is absolute 3 — the entries the encoder
    // inserted while encoding the section it is referencing.
    try testing.expectEqualStrings("c", test_table.get_post_base(2, 0).?.name);
    try testing.expectEqualStrings("d", test_table.get_post_base(2, 1).?.name);
    try testing.expectEqual(null, test_table.get_post_base(2, 2));
    // The two schemes meet at the Base and do not overlap: relative 0 is below it, post-Base 0
    // is at it.
    try testing.expectEqualStrings("b", test_table.get_relative_to_base(2, 0).?.name);
}

test "§3.2.2: eviction makes room from the oldest end, and an oversized entry is an error" {
    test_table.init(constants.dynamic_table_capacity_max);
    try test_table.set_capacity(test_capacity);
    try fill(4);
    try testing.expectEqual(4, test_table.count);
    // §3.2.2: entries are evicted until the size is at or below the capacity less the new entry.
    try test_table.insert("e", "v");
    try testing.expectEqual(4, test_table.count);
    try testing.expect(test_table.size <= test_table.capacity);
    // An entry larger than the whole capacity is a connection error, and the table is unchanged
    // rather than emptied — which is where RFC 9204 §3.2.2 and RFC 7541 §4.4 part company.
    const long = [_]u8{'x'} ** 64;
    try testing.expectError(Error.EntryTooLarge, test_table.insert(&long, &long));
    try testing.expectEqual(4, test_table.count);
    try testing.expectEqualStrings("e", test_table.get_absolute(4).?.name);
    // Reducing the capacity evicts down to it (§3.2.2), and reducing it to zero empties the
    // table, which the same paragraph names as the way to do that.
    try test_table.set_capacity(small_entry_len);
    try testing.expectEqual(1, test_table.count);
    try test_table.set_capacity(0);
    try testing.expectEqual(0, test_table.count);
    try testing.expectEqual(0, test_table.size);
    // The absolute indices did not restart: §3.2.4 fixes them for the connection.
    try testing.expectEqual(5, test_table.insert_count());
    try test_table.set_capacity(test_capacity);
    try test_table.insert("f", "v");
    try testing.expectEqualStrings("f", test_table.get_absolute(5).?.name);
}

test "§3.2: duplicate entries are ordinary, and the newest is what a lookup finds" {
    test_table.init(constants.dynamic_table_capacity_max);
    try test_table.set_capacity(test_capacity);
    // §3.2: the table can contain duplicate entries, and they MUST NOT be treated as an error.
    try test_table.insert("a", "v");
    try test_table.insert("a", "w");
    try test_table.insert("a", "v");
    try testing.expectEqual(3, test_table.count);
    // The newest match is the one to take: an older entry is nearer eviction.
    const match = test_table.find("a", "v");
    try testing.expectEqual(2, match.exact);
    try testing.expectEqual(2, match.name);
    // A name the table holds with another value gives a name match and no exact one.
    const partial = test_table.find("a", "z");
    try testing.expectEqual(null, partial.exact);
    try testing.expectEqual(2, partial.name);
    // A name it does not hold gives neither.
    const absent = test_table.find("q", "v");
    try testing.expectEqual(null, absent.exact);
    try testing.expectEqual(null, absent.name);
}

test "§4.5.1.1: MaxEntries follows the advertised maximum" {
    test_table.init(constants.dynamic_table_capacity_max);
    try testing.expectEqual(constants.dynamic_table_entries_max, test_table.max_entries());
    // §4.5.1.1's example: a table of 100 octets encodes the Required Insert Count modulo 6, so
    // MaxEntries is 3 and the full range is twice it.
    test_table.init(100);
    try testing.expectEqual(3, test_table.max_entries());
}

test "the octets survive wrapping, so an entry read after many inserts is still whole" {
    test_table.init(constants.dynamic_table_capacity_max);
    try test_table.set_capacity(test_capacity);
    // Enough inserts that the octet buffer is rebased more than once, with names long enough to
    // tell apart. Each pass evicts one, so the live entries move through the storage.
    const rounds: u8 = 200;
    for (0..rounds) |step| {
        var name: [4]u8 = undefined;
        _ = std.fmt.bufPrint(&name, "{d:0>4}", .{step % 1000}) catch unreachable;
        try test_table.insert(&name, "v");
        const newest = test_table.get_absolute(test_table.insert_count() - 1).?;
        try testing.expectEqualStrings(&name, newest.name);
        try testing.expectEqualStrings("v", newest.value);
    }
    try testing.expectEqual(rounds, test_table.insert_count());
    try testing.expect(test_table.size <= test_table.capacity);
}
