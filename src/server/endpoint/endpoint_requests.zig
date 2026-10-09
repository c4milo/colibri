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

/// A table of `capacity` open requests, which a mask of the entries in use lets a lookup skip.
pub fn Table(comptime capacity: usize) type {
    comptime assert(capacity > 0);
    return struct {
        const Self = @This();
        const Mask = std.bit_set.IntegerBitSet(capacity);

        entries: [capacity]Entry,
        in_use: Mask,

        pub fn init(table: *Self) void {
            table.in_use = .initEmpty();
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
            return &table.entries[free];
        }

        /// The open request `number`, or null.
        pub fn find(table: *Self, number: Number) ?*Entry {
            const index = table.index_of(number) orelse return null;
            return &table.entries[index];
        }

        fn index_of(table: *const Self, number: Number) ?usize {
            var open = table.in_use.iterator(.{});
            // Bounded by the capacity.
            while (open.next()) |index| {
                if (table.entries[index].number == number) return index;
            }
            return null;
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
            assert(table.index_of(number) == null);
        }
    };
}

const testing = std.testing;
const test_capacity: usize = 3;

test "decision 119: a request keeps its word from its head until its ending, and a full table refuses" {
    var table: Table(test_capacity) = undefined;
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
    var table: Table(test_capacity) = undefined;
    table.init();
    try testing.expectEqual(null, table.first());
    _ = table.add(1).?;
    _ = table.add(2).?;
    table.remove(1);
    try testing.expectEqual(2, table.first().?.number);
    table.remove(table.first().?.number);
    try testing.expectEqual(null, table.first());
}
