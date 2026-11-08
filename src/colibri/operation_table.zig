//! The operations a driver holds in flight (decision 159), and the storage that a turn writes
//! them into. Each owner of an operation has a fixed slot for each kind that it can hold in
//! flight: a TCP socket's receive, send, close and connect, the listener's accept, and the UDP
//! socket's receive and its sends. An `OperationId` carries the slot in its low 24 bits and the
//! slot's generation in its high byte. Each issue of a slot moves its generation on, so a
//! completion for an earlier issue names no operation that the driver holds.
const std = @import("std");
const assert = std.debug.assert;
const host = @import("host.zig");

const OperationId = host.OperationId;

/// The bits of an `OperationId` that name the slot. The rest is the generation.
pub const slot_bits = 24;
const slot_mask: u32 = (1 << slot_bits) - 1;

pub fn Table(comptime slot_count: u32) type {
    comptime assert(slot_count > 0 and slot_count <= slot_mask);
    return struct {
        const Self = @This();

        generations: [slot_count]u8,
        in_flight: std.StaticBitSet(slot_count),
        /// The operations in flight: the slots that `in_flight` sets.
        count: u32,

        pub const empty: Self = .{ .generations = @splat(0), .in_flight = .initEmpty(), .count = 0 };

        /// Takes `slot` for one new operation, and returns its id.
        pub fn issue(table: *Self, slot: u32) OperationId {
            assert(slot < slot_count);
            assert(!table.in_flight.isSet(slot));
            table.generations[slot] +%= 1;
            table.in_flight.set(slot);
            table.count += 1;
            assert(table.count <= slot_count);
            return table.id(slot);
        }

        /// The slot of the operation `operation` names, or null when the driver holds no such
        /// operation: its slot is free, or its generation is an earlier one.
        pub fn find(table: *const Self, operation: OperationId) ?u32 {
            const bits = @intFromEnum(operation);
            const slot = bits & slot_mask;
            if (slot >= slot_count) return null;
            if (!table.in_flight.isSet(slot)) return null;
            if (table.generations[slot] != bits >> slot_bits) return null;
            return slot;
        }

        /// Frees `slot` after its operation's final completion.
        pub fn finish(table: *Self, slot: u32) void {
            assert(table.in_flight.isSet(slot));
            assert(table.count > 0);
            table.in_flight.unset(slot);
            table.count -= 1;
        }

        /// The id of the operation in flight in `slot`, which a cancel names.
        pub fn id(table: *const Self, slot: u32) OperationId {
            assert(table.in_flight.isSet(slot));
            return @enumFromInt((@as(u32, table.generations[slot]) << slot_bits) | slot);
        }
    };
}

/// The storage that the host gave a turn, and how much of it the turn wrote. A turn that finds it
/// full returns `.now`, so the host calls the turn again before it waits.
pub const Outbox = struct {
    operations: []host.Operation,
    len: u32 = 0,
    full: bool = false,

    /// Whether one more operation fits. A false answer records that the turn left work.
    pub fn room(out: *Outbox) bool {
        if (out.len < out.operations.len) return true;
        out.full = true;
        return false;
    }

    /// Writes one operation. The caller asked `room` first.
    pub fn put(out: *Outbox, operation: host.Operation) void {
        assert(out.len < out.operations.len);
        out.operations[out.len] = operation;
        out.len += 1;
    }
};

const testing = std.testing;

test "decision 159: a completion of an earlier issue of a slot names no operation" {
    var table: Table(4) = .empty;
    const first = table.issue(2);
    try testing.expectEqual(2, table.find(first).?);
    table.finish(2);
    // The slot is free, so its last id names nothing.
    try testing.expectEqual(null, table.find(first));
    const second = table.issue(2);
    try testing.expect(first != second);
    // The slot is in flight again, under the next generation.
    try testing.expectEqual(null, table.find(first));
    try testing.expectEqual(2, table.find(second).?);
    try testing.expectEqual(1, table.count);
    // A slot past the table, and a free slot, name nothing.
    try testing.expectEqual(null, table.find(@enumFromInt(7)));
    try testing.expectEqual(null, table.find(@enumFromInt(1)));
}

test "decision 159: a generation wraps after 256 issues of one slot" {
    var table: Table(1) = .empty;
    const first = table.issue(0);
    table.finish(0);
    for (0..255) |_| {
        _ = table.issue(0);
        table.finish(0);
    }
    // The byte wrapped, so the 257th issue has the first one's id again.
    try testing.expectEqual(first, table.issue(0));
}

test "decision 159: an outbox records that a turn found it full" {
    var operations: [1]host.Operation = undefined;
    var out: Outbox = .{ .operations = &operations };
    try testing.expect(out.room());
    out.put(.{ .id = @enumFromInt(0), .kind = .{ .close = .{ .socket = @enumFromInt(0) } } });
    try testing.expect(!out.full);
    try testing.expect(!out.room());
    try testing.expect(out.full);
}
