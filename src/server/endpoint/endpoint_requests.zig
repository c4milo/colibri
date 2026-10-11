//! A slot's open requests, as the endpoint reports them (decision 119): each request's number on
//! its connection and the word of `user_data` the program set at its head, from its `request` event
//! until its one `done` or `cancelled`. A connection that ends reports `cancelled` for each request
//! still here. `server.zig` does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");

const Number = event.Number;

/// What a request's response found no room for: its head, more of its content, or its trailer
/// section, or a head or trailer section larger than the room its earlier frames leave, which
/// waits for the response to hold nothing unacknowledged. The endpoint reports `writable` once
/// the connection can take it.
pub const Wait = enum { head, content, trailers, empty };

/// One open request.
pub const Entry = struct {
    number: Number,
    user_data: usize = 0,
    /// The `cancelled` owed for the program's own `cancel`, reported before anything else of this
    /// request.
    cancel_owed: bool = false,
    /// The value of the slot's room counter when the last write found no room, or null when the
    /// request waits for no room (`writable`), and what that write was.
    waiting_since: ?u32 = null,
    waiting_for: Wait = .content,
    /// The octets of content the program waits to write, which an h2 stream's window may hold only
    /// whole when it is shorter than decision 110's floor.
    waiting_len: u32 = 0,
};

/// A table of `capacity` open requests. A mask of the entries in use lets a scan skip the rest,
/// and `places` names the entry a request's number is open at, so a lookup reads one entry. A
/// connection's request numbers are `step` apart: an h2 stream's by 2 (RFC 9113 §5.1.1), and a
/// QUIC request stream's by 4 (RFC 9000 §2.1).
pub fn Table(comptime capacity: usize, comptime step: Number) type {
    comptime assert(capacity > 0 and step > 0);
    return struct {
        const Self = @This();
        const Mask = std.bit_set.IntegerBitSet(capacity);
        /// An entry's index, or `none`.
        const Index = std.math.IntFittingRange(0, capacity);
        const none: Index = capacity;

        entries: [capacity]Entry,
        in_use: Mask,
        /// For each place, the entry of the open request whose number names the place, or `none`.
        /// Numbers `capacity` steps apart name one place, and the first of them to open holds it.
        places: [capacity]Index,
        /// The open requests that hold no place: another request held theirs when they opened.
        /// While there is none, a number is open only at its place, and no lookup scans.
        placeless: u32,
        /// The open requests whose `cancel_owed` is set, and those that wait for room. A poll
        /// reads the table for either only while it counts one.
        cancels_owed: u32,
        waiting: u32,

        pub fn init(table: *Self) void {
            table.in_use = .initEmpty();
            table.places = @splat(none);
            table.placeless = 0;
            table.cancels_owed = 0;
            table.waiting = 0;
        }

        /// The program cancelled request `number`, which is open: its `cancelled` is owed.
        pub fn owe_cancel(table: *Self, number: Number) void {
            const entry = table.find(number).?;
            table.cancels_owed += @intFromBool(!entry.cancel_owed);
            entry.cancel_owed = true;
        }

        /// A write of request `number`, which is open, found no room when the slot's room counter
        /// read `since`.
        pub fn wait(table: *Self, number: Number, since: u32, waiting_for: Wait, waiting_len: u32) void {
            const entry = table.find(number).?;
            table.waiting += @intFromBool(entry.waiting_since == null);
            entry.waiting_since = since;
            entry.waiting_for = waiting_for;
            entry.waiting_len = waiting_len;
        }

        /// The request at `entry` waits for no room.
        pub fn stop_waiting(table: *Self, entry: *Entry) void {
            assert(table.waiting >= @intFromBool(entry.waiting_since != null));
            table.waiting -= @intFromBool(entry.waiting_since != null);
            entry.waiting_since = null;
        }

        /// The place `number` names.
        fn place_of(number: Number) usize {
            return @intCast((number / step) % capacity);
        }

        pub fn len(table: *const Self) usize {
            return table.in_use.count();
        }

        /// Opens request `number`, or returns null when the table is full.
        pub fn add(table: *Self, number: Number) ?*Entry {
            assert(table.find(number) == null);
            const free = table.in_use.complement().findFirstSet() orelse return null;
            table.in_use.set(free);
            table.entries[free] = .{ .number = number };
            take_place(table, place_of(number), free);
            return &table.entries[free];
        }

        /// The open request `number`, or null.
        pub fn find(table: *Self, number: Number) ?*Entry {
            const index = table.index_of(number) orelse return null;
            return &table.entries[index];
        }

        fn index_of(table: *const Self, number: Number) ?usize {
            const held = table.places[place_of(number)];
            if (held != none and table.entries[held].number == number) return held;
            if (table.placeless == 0) return null;
            return scan(table, number);
        }

        /// The open request at the lowest index, which a connection's end cancels first.
        pub fn first(table: *Self) ?*Entry {
            const index = table.in_use.findFirstSet() orelse return null;
            return &table.entries[index];
        }

        /// Closes request `number`, whose ending the endpoint reported.
        pub fn remove(table: *Self, number: Number) void {
            const index = table.index_of(number).?;
            assert(table.in_use.isSet(index));
            table.in_use.unset(index);
            const entry = &table.entries[index];
            assert(table.cancels_owed >= @intFromBool(entry.cancel_owed));
            table.cancels_owed -= @intFromBool(entry.cancel_owed);
            table.stop_waiting(entry);
            leave_place(table, place_of(number), index);
            assert(table.index_of(number) == null);
        }
    };
}

/// The entry `number` is open at, found by reading each entry in use: the lookup of a request
/// that holds no place.
fn scan(table: anytype, number: Number) ?usize {
    var open = table.in_use.iterator(.{});
    // Bounded by the capacity.
    while (open.next()) |index| {
        if (table.entries[index].number == number) return index;
    }
    return null;
}

/// The request opened at entry `index` takes `place` when no open request holds it.
fn take_place(table: anytype, place: usize, index: usize) void {
    if (table.places[place] == table.places.len) {
        table.places[place] = @intCast(index);
    } else {
        table.placeless += 1;
    }
}

/// The request that ended at entry `index` gives `place` up, when it held it.
fn leave_place(table: anytype, place: usize, index: usize) void {
    if (table.places[place] == index) {
        table.places[place] = @intCast(table.places.len);
    } else {
        assert(table.placeless > 0);
        table.placeless -= 1;
    }
}

const testing = std.testing;
const test_capacity: usize = 3;
/// The tests' numbers are any, so each names a place of its own until `test_capacity` are apart.
const test_step: Number = 1;

test "decision 119: a request keeps its word from its head until its ending, and a full table refuses" {
    var table: Table(test_capacity, test_step) = undefined;
    table.init();
    try testing.expectEqual(null, table.find(4));
    const head = table.add(4).?;
    head.user_data = 0xa1;
    _ = table.add(8).?;
    _ = table.add(12).?;
    try testing.expectEqual(null, table.add(16));
    try testing.expectEqual(0xa1, table.find(4).?.user_data);
    table.remove(8);
    try testing.expectEqual(null, table.find(8));
    try testing.expectEqual(2, table.len());
    // The freed entry takes the next request.
    try testing.expectEqual(0, table.add(16).?.user_data);
    try testing.expectEqual(16, table.find(16).?.number);
}

test "decision 119: a connection's end finds its open requests lowest index first" {
    var table: Table(test_capacity, test_step) = undefined;
    table.init();
    try testing.expectEqual(null, table.first());
    _ = table.add(1).?;
    _ = table.add(2).?;
    table.remove(1);
    try testing.expectEqual(2, table.first().?.number);
    table.remove(table.first().?.number);
    try testing.expectEqual(null, table.first());
}

test "a request whose place another holds is found by a scan, and takes no place when the holder leaves" {
    var table: Table(test_capacity, test_step) = undefined;
    table.init();
    // 1 and 4 name one place of three: 1 holds it, and 4 holds none.
    _ = table.add(1).?;
    table.add(4).?.user_data = 0xb2;
    try testing.expectEqual(1, table.placeless);
    try testing.expectEqual(0xb2, table.find(4).?.user_data);
    try testing.expectEqual(null, table.find(7));
    table.remove(1);
    try testing.expectEqual(null, table.find(1));
    try testing.expectEqual(0xb2, table.find(4).?.user_data);
    // A later request takes the place, and 4 is still found.
    _ = table.add(7).?;
    try testing.expectEqual(7, table.find(7).?.number);
    try testing.expectEqual(4, table.find(4).?.number);
    table.remove(4);
    try testing.expectEqual(0, table.placeless);
    table.remove(7);
    try testing.expectEqual(0, table.len());
    for (table.places) |place| try testing.expectEqual(test_capacity, place);
}

test "a table full of numbers a step apart gives each a place" {
    const Full = Table(4, 2);
    var table: Full = undefined;
    table.init();
    // An h2 client's streams: 1, 3, 5 and 7, then 9 once 1 has ended.
    for ([_]Number{ 1, 3, 5, 7 }) |number| _ = table.add(number).?;
    try testing.expectEqual(0, table.placeless);
    table.remove(1);
    _ = table.add(9).?;
    try testing.expectEqual(0, table.placeless);
    for ([_]Number{ 3, 5, 7, 9 }) |number| try testing.expectEqual(number, table.find(number).?.number);
    try testing.expectEqual(null, table.find(1));
}

/// The table before it kept places, which read every entry in use: the reference of the test below.
const Scanned = struct {
    numbers: [test_capacity]?Number = @splat(null),

    fn index_of(scanned: *const Scanned, number: Number) ?usize {
        for (scanned.numbers, 0..) |held, index| {
            if (held == number) return index;
        }
        return null;
    }

    fn add(scanned: *Scanned, number: Number) ?usize {
        const free = scanned.index_of_free() orelse return null;
        scanned.numbers[free] = number;
        return free;
    }

    fn index_of_free(scanned: *const Scanned) ?usize {
        for (scanned.numbers, 0..) |held, index| {
            if (held == null) return index;
        }
        return null;
    }
};

test "the table holds each request where a table that scans holds it, over many opens and endings" {
    var table: Table(test_capacity, test_step) = undefined;
    table.init();
    var scanned: Scanned = .{};
    // Few numbers, so they share places and are opened again after they end. The walk below is
    // fixed: each number comes round in turn, and a request ends at two visits of three.
    const numbers_max = 8;
    const visits = 4096;
    var visits_placeless: usize = 0;
    var visits_full: usize = 0;
    for (0..visits) |visit| {
        visits_placeless += @intFromBool(table.placeless > 0);
        visits_full += @intFromBool(table.len() == test_capacity);
        const number: Number = (visit * 5 + visit / 7) % numbers_max;
        const expected = scanned.index_of(number);
        const found = table.find(number);
        try testing.expectEqual(expected != null, found != null);
        if (found) |entry| try testing.expectEqual(&table.entries[expected.?], entry);
        if (expected) |index| {
            if (visit % 3 == 0) continue;
            table.remove(number);
            scanned.numbers[index] = null;
        } else {
            const index = scanned.add(number);
            const entry = table.add(number);
            try testing.expectEqual(index != null, entry != null);
            if (entry) |added| try testing.expectEqual(&table.entries[index.?], added);
        }
        try testing.expectEqual(scanned.index_of(number) != null, table.find(number) != null);
    }
    // The walk reaches both lookups, and a table that refuses a request.
    try testing.expect(visits_placeless > 0 and visits_placeless < visits);
    try testing.expect(visits_full > 0);
}

test "the table counts the cancels it owes and the requests that wait, until each ends" {
    var table: Table(test_capacity, test_step) = undefined;
    table.init();
    _ = table.add(1).?;
    _ = table.add(2).?;
    // A second cancel of one request, and a second wait, count once.
    table.owe_cancel(1);
    table.owe_cancel(1);
    try testing.expectEqual(1, table.cancels_owed);
    table.wait(2, 5, .content, 9);
    table.wait(2, 6, .head, 0);
    try testing.expectEqual(1, table.waiting);
    try testing.expectEqual(6, table.find(2).?.waiting_since.?);
    try testing.expectEqual(.head, table.find(2).?.waiting_for);
    // A request that found room waits no more, and one that never waited changes no count.
    table.stop_waiting(table.find(2).?);
    table.stop_waiting(table.find(1).?);
    try testing.expectEqual(0, table.waiting);
    try testing.expectEqual(null, table.find(2).?.waiting_since);
    // A request that ends takes what it counted with it.
    table.wait(2, 7, .content, 1);
    table.remove(2);
    table.remove(1);
    try testing.expectEqual(0, table.waiting);
    try testing.expectEqual(0, table.cancels_owed);
    // The entries a later request takes start with neither.
    _ = table.add(3).?;
    try testing.expect(!table.find(3).?.cancel_owed and table.find(3).?.waiting_since == null);
}
