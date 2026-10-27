//! The tests that hold `stream_incoming.zig`'s index to the list it replaced (decision 61 as
//! amended on 2026-10-17). The list is kept here as the reference: each stream's blocks in offset
//! order, found by a walk from its first. Random writes, reads, peeks, discards and releases over
//! several streams must give the same octets, the same ends and the same free blocks from both,
//! and no bucket's chain may hold more blocks than there are streams that hold any.
const std = @import("std");
const assert = std.debug.assert;
const stream_incoming = @import("stream_incoming.zig");

const testing = std.testing;
const block_len = stream_incoming.block_len;
const no_block: u16 = std.math.maxInt(u16);

/// A window of eight blocks per stream. Test-only.
const capacity_blocks: usize = 8;
const capacity: usize = capacity_blocks * block_len;
const TestPool = stream_incoming.Pool(capacity);
var pool: TestPool align(@alignOf(TestPool)) = .{};
const block_count = @typeInfo(@TypeOf(pool.blocks)).array.len;

/// The list the index replaced, kept as the reference. Test-only.
const ListBlock = struct { stream_id: u64, number: u64, next: u16, present: std.StaticBitSet(block_len) };
var list_blocks: [block_count]ListBlock align(@alignOf(ListBlock)) = undefined;
var list_octets: [block_count][block_len]u8 = undefined;
var list_free: u16 = 0;

const List = struct {
    first: u16 = no_block,

    fn block_for(list: *List, stream_id: u64, number: u64) !u16 {
        var previous: u16 = no_block;
        var current = list.first;
        for (0..block_count) |_| {
            if (current == no_block or list_blocks[current].number >= number) break;
            previous = current;
            current = list_blocks[current].next;
        }
        if (current != no_block and list_blocks[current].number == number) return current;
        const index = list_free;
        if (index == no_block) return stream_incoming.Error.PoolExhausted;
        list_free = list_blocks[index].next;
        list_blocks[index] = .{ .stream_id = stream_id, .number = number, .next = current, .present = .initEmpty() };
        if (previous == no_block) list.first = index else list_blocks[previous].next = index;
        return index;
    }

    fn write(list: *List, stream_id: u64, read_offset: u64, offset: u64, data: []const u8) !void {
        const end = offset + data.len;
        var at = @max(offset, read_offset);
        while (at < end) {
            const index = try list.block_for(stream_id, at / block_len);
            const within: usize = @intCast(at % block_len);
            const len: usize = @intCast(@min(end - at, block_len - within));
            const from: usize = @intCast(at - offset);
            @memcpy(list_octets[index][within..][0..len], data[from..][0..len]);
            list_blocks[index].present.setRangeValue(.{ .start = within, .end = within + len }, true);
            at += len;
        }
    }

    /// What `read` copies, and with `take` gives back what it read to the end.
    fn copy(list: *List, read_offset: u64, output: []u8, take: bool) usize {
        var at = read_offset;
        var written: usize = 0;
        var current = list.first;
        while (written < output.len and current != no_block and list_blocks[current].number == at / block_len) {
            const within: usize = @intCast(at % block_len);
            var run: usize = 0;
            while (written + run < output.len and within + run < block_len and list_blocks[current].present.isSet(within + run)) run += 1;
            @memcpy(output[written..][0..run], list_octets[current][within..][0..run]);
            written += run;
            at += run;
            if (within + run < block_len) break;
            const next = list_blocks[current].next;
            if (take) list.drop_first();
            current = next;
        }
        return written;
    }

    fn drop_first(list: *List) void {
        const index = list.first;
        list.first = list_blocks[index].next;
        list_blocks[index].next = list_free;
        list_free = index;
    }

    fn release(list: *List) void {
        while (list.first != no_block) list.drop_first();
    }
};

/// A stream on both sides, and how much of it the application read.
const Side = struct { id: u64, read: u64 = 0, incoming: stream_incoming.Incoming = .{}, list: List = .{} };
const streams_len: usize = 3;
var sides: [streams_len]Side align(@alignOf(Side)) = undefined;
/// The id the next stream a release makes takes: each id names a stream once (RFC 9000 §2.1).
var next_id: u64 = 0;
const id_step: u64 = 4;

/// The octet at each offset of each stream, so an octet read from the wrong place shows.
fn octet_at(stream_id: u64, offset: u64) u8 {
    return @truncate(offset *% octet_stride +% stream_id);
}
const octet_stride: u64 = 7;

/// SplitMix64, so a seed replays (non-negotiable 5). Test-only.
const Draw = struct {
    state: u64,
    fn next(draw: *Draw) u64 {
        draw.state +%= increment;
        var z = draw.state;
        z = (z ^ (z >> shift_first)) *% multiplier_first;
        z = (z ^ (z >> shift_second)) *% multiplier_second;
        return z ^ (z >> shift_third);
    }
    fn below(draw: *Draw, bound: u64) u64 {
        return draw.next() % bound;
    }
};
const increment: u64 = 0x9e37_79b9_7f4a_7c15;
const multiplier_first: u64 = 0xbf58_476d_1ce4_e5b9;
const multiplier_second: u64 = 0x94d0_49bb_1331_11eb;
const shift_first: u6 = 30;
const shift_second: u6 = 27;
const shift_third: u6 = 31;

var frame: [capacity]u8 = undefined;
var output_index: [capacity]u8 = undefined;
var output_list: [capacity]u8 = undefined;

fn start() stream_incoming.Storage {
    const storage = pool.storage();
    storage.reset();
    for (&list_blocks, 0..) |*block, index| block.next = if (index + 1 < block_count) @intCast(index + 1) else no_block;
    list_free = 0;
    next_id = 0;
    for (&sides) |*side| side.* = .{ .id = take_id() };
    return storage;
}

fn take_id() u64 {
    const id = next_id;
    next_id += id_step;
    return id;
}

/// Writes octets inside the stream's window on both sides, as flow control admits them.
fn write(storage: stream_incoming.Storage, side: *Side, draw: *Draw) !void {
    const offset = side.read + draw.below(capacity);
    const len = @min(1 + draw.below(write_len_max), side.read + capacity - offset);
    for (frame[0..len], 0..) |*octet, index| octet.* = octet_at(side.id, offset + index);
    try side.incoming.write(storage, side.id, side.read, offset, frame[0..len]);
    try side.list.write(side.id, side.read, offset, frame[0..len]);
}

/// Reads or peeks on both sides, and fails at the first octet that differs.
fn copy(storage: stream_incoming.Storage, side: *Side, draw: *Draw, take: bool) !void {
    const len = 1 + draw.below(capacity);
    const got = if (take)
        side.incoming.read(storage, side.id, side.read, output_index[0..len])
    else
        side.incoming.peek(storage, side.id, side.read, output_index[0..len]);
    const want = side.list.copy(side.read, output_list[0..len], take);
    try testing.expectEqualSlices(u8, output_list[0..want], output_index[0..got]);
    if (take) side.read += got;
}

/// Drops what a peek showed, on both sides.
fn discard(storage: stream_incoming.Storage, side: *Side, draw: *Draw) void {
    const arrived = side.incoming.contiguous_end(storage, side.id, side.read) - side.read;
    if (arrived == 0) return;
    const len = 1 + draw.below(arrived);
    side.incoming.discard(storage, side.id, side.read, len);
    var skipped: [capacity]u8 = undefined;
    assert(side.list.copy(side.read, skipped[0..len], true) == len);
    side.read += len;
}

/// Free blocks on the index's side, and on the list's.
const FreeCounts = struct { index: usize = 0, list: usize = 0 };
fn free_counts(storage: stream_incoming.Storage) FreeCounts {
    var counts: FreeCounts = .{};
    var index = storage.header.free_head;
    while (index != no_block) : (counts.index += 1) index = storage.blocks[index].next;
    index = list_free;
    while (index != no_block) : (counts.list += 1) index = list_blocks[index].next;
    return counts;
}

/// The most blocks one bucket's chain holds.
fn longest_chain(storage: stream_incoming.Storage) usize {
    var longest: usize = 0;
    for (storage.buckets) |head| {
        var len: usize = 0;
        var index = head;
        while (index != no_block) : (len += 1) index = storage.blocks[index].next;
        longest = @max(longest, len);
    }
    return longest;
}

/// Runs one seed's operations, comparing the two after each.
fn run_seed(seed: u64) !void {
    const storage = start();
    var draw: Draw = .{ .state = seed };
    for (0..operations_per_seed) |_| {
        const side = &sides[draw.below(streams_len)];
        switch (@as(Operation, @enumFromInt(draw.below(operation_kinds)))) {
            .write, .write_more => try write(storage, side, &draw),
            .read => try copy(storage, side, &draw, true),
            .peek => try copy(storage, side, &draw, false),
            .discard => discard(storage, side, &draw),
            .release => {
                side.incoming.release(storage, side.id, side.read);
                side.list.release();
                side.* = .{ .id = take_id() };
            },
        }
        const counts = free_counts(storage);
        try testing.expectEqual(counts.list, counts.index);
        var holding: usize = 0;
        for (&sides) |*each| {
            try testing.expectEqual(each.list.copy(each.read, &output_list, false) + each.read, each.incoming.contiguous_end(storage, each.id, each.read));
            try testing.expectEqual(each.list.first == no_block, each.incoming.is_empty());
            if (!each.incoming.is_empty()) holding += 1;
        }
        try testing.expect(longest_chain(storage) <= holding);
    }
}
const operations_per_seed: usize = 400;
/// What one step does. A write is drawn twice as often as each other step, so streams fill.
const Operation = enum { write, write_more, read, peek, discard, release };
const operation_kinds: u64 = @typeInfo(Operation).@"enum".fields.len;
/// The longest write: half a window.
const write_len_max: u64 = (capacity_blocks / write_parts) * block_len;
const write_parts: usize = 2;
const seeds: u64 = 64;

test "decision 61 as amended: the index gives what the list gave, over random operations on three streams" {
    for (0..seeds) |seed| try run_seed(seed);
}

test "RFC 9000 §21.7: one octet in each block of a stream's window leaves every chain one block long" {
    const storage = pool.storage();
    storage.reset();
    var incoming: stream_incoming.Incoming = .{};
    const id: u64 = 0;
    for (0..capacity_blocks) |number| {
        const offset = number * block_len + block_len - 1;
        frame[0] = octet_at(id, offset);
        try incoming.write(storage, id, 0, offset, frame[0..1]);
    }
    try testing.expectEqual(capacity_blocks, incoming.held);
    try testing.expectEqual(1, longest_chain(storage));
    try testing.expectEqual(0, incoming.contiguous_end(storage, id, 0));
    incoming.release(storage, id, 0);
    try testing.expectEqual(0, longest_chain(storage));
}

test "decision 61 as amended: the first blocks of several streams fall in different buckets" {
    const storage = pool.storage();
    storage.reset();
    var incomings: [streams_len]stream_incoming.Incoming = @splat(.{});
    for (&incomings, 0..) |*incoming, index| {
        const id = index * id_step;
        frame[0] = octet_at(id, 0);
        try incoming.write(storage, id, 0, 0, frame[0..1]);
    }
    try testing.expectEqual(1, longest_chain(storage));
}

/// Fills `ids` with streams past 0 whose first block falls in the bucket of stream 0's: it writes
/// each candidate's first block and keeps those that make that chain longer. Test-only.
fn colliding_ids(storage: stream_incoming.Storage, ids: []u64) !void {
    storage.reset();
    var holder: stream_incoming.Incoming = .{};
    try fill_first_block(storage, &holder, 0);
    var found: usize = 0;
    var id: u64 = id_step;
    for (0..candidates_max) |_| {
        if (found == ids.len) return;
        var candidate: stream_incoming.Incoming = .{};
        try fill_first_block(storage, &candidate, id);
        if (longest_chain(storage) == found + holder.held + candidate.held) {
            ids[found] = id;
            found += 1;
        } else {
            candidate.release(storage, id, 0);
        }
        id += id_step;
    }
    return error.TestUnexpectedResult;
}
/// Candidates the search may try: each falls in a given bucket about once in `block_count`, so
/// this many find two with room to spare.
const candidates_max: usize = candidate_rounds * block_count;
const candidate_rounds: usize = 64;

/// Writes the whole first block of stream `id`. Test-only.
fn fill_first_block(storage: stream_incoming.Storage, incoming: *stream_incoming.Incoming, id: u64) !void {
    for (frame[0..block_len], 0..) |*octet, offset| octet.* = octet_at(id, offset);
    try incoming.write(storage, id, 0, 0, frame[0..block_len]);
}

/// Fails unless stream `id` reads its own first block whole, whatever shares its bucket.
fn expect_first_block(storage: stream_incoming.Storage, incoming: *stream_incoming.Incoming, id: u64, take: bool) !void {
    const got = if (take)
        incoming.read(storage, id, 0, output_index[0..block_len])
    else
        incoming.peek(storage, id, 0, output_index[0..block_len]);
    try testing.expectEqual(block_len, got);
    for (output_index[0..block_len], 0..) |octet, offset| try testing.expectEqual(octet_at(id, offset), octet);
}

test "decision 61 as amended: streams whose blocks share a bucket each keep their own, whichever goes first" {
    const storage = pool.storage();
    var found: [2]u64 = undefined;
    try colliding_ids(storage, &found);
    storage.reset();
    const ids = [_]u64{ 0, found[0], found[1] };
    var incomings: [ids.len]stream_incoming.Incoming = @splat(.{});
    for (ids, &incomings) |id, *incoming| try fill_first_block(storage, incoming, id);
    // One chain holds all three: the last written first, then the second, then stream 0.
    try testing.expectEqual(ids.len, longest_chain(storage));
    for (ids, &incomings) |id, *incoming| try expect_first_block(storage, incoming, id, false);
    // The middle of the chain goes back to the pool first, then its head, then by a release
    // the last block.
    try expect_first_block(storage, &incomings[1], ids[1], true);
    try testing.expectEqual(2, longest_chain(storage));
    try expect_first_block(storage, &incomings[2], ids[2], true);
    try testing.expectEqual(1, longest_chain(storage));
    try expect_first_block(storage, &incomings[0], ids[0], false);
    incomings[0].release(storage, ids[0], 0);
    try testing.expectEqual(0, longest_chain(storage));
    try testing.expect(incomings[0].is_empty());
}
