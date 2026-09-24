//! The tests of `stream_incoming.zig`: octets written in any order and read in order, blocks taken
//! from the pool and given back, and a pool that runs out.
const std = @import("std");
const constants = @import("../constants.zig");
const stream_incoming = @import("stream_incoming.zig");

const Incoming = stream_incoming.Incoming;
const block_len = stream_incoming.block_len;
const testing = std.testing;

/// A pool of four blocks' capacity, which the two per stream beyond it make larger, and room to
/// read three blocks at once. Test-only.
const capacity_blocks: usize = 4;
const TestPool = stream_incoming.Pool(capacity_blocks * block_len);
var test_pool: TestPool = .{};
const output_blocks: usize = 3;
var output: [output_blocks * block_len]u8 = undefined;

const stream_a: u64 = 0;
const stream_b: u64 = 4;

/// The octet at each offset, so an octet read from the wrong place shows. Test-only.
const octet_stride: u64 = 7;
fn octet_at(offset: u64) u8 {
    return @truncate(offset *% octet_stride);
}

/// Octets `from` to `to` of a stream, as a frame would carry them. Test-only.
var frame_buffer: [output_blocks * block_len]u8 = undefined;
fn frame(from: u64, to: u64) []const u8 {
    const len: usize = @intCast(to - from);
    for (frame_buffer[0..len], 0..) |*octet, index| octet.* = octet_at(from + index);
    return frame_buffer[0..len];
}

fn fresh() stream_incoming.Storage {
    const storage = test_pool.storage();
    storage.reset();
    return storage;
}

/// Blocks on the free list. Test-only.
fn free_blocks(storage: stream_incoming.Storage) usize {
    var count: usize = 0;
    var index = storage.header.free_head;
    while (index != std.math.maxInt(u16)) : (count += 1) index = storage.blocks[index].next;
    return count;
}

fn expect_octets(from: u64, octets: []const u8) !void {
    for (octets, 0..) |octet, index| try testing.expectEqual(octet_at(from + index), octet);
}

test "decision 61: octets written in order read back in order, and the blocks go back" {
    const storage = fresh();
    const all = free_blocks(storage);
    var incoming: Incoming = .{};
    const end: u64 = block_len + block_len / 2;
    try incoming.write(storage, stream_a, 0, 0, frame(0, end));
    try testing.expectEqual(all - 2, free_blocks(storage));
    try testing.expectEqual(end, incoming.contiguous_end(storage, 0));
    const read = incoming.read(storage, 0, &output);
    try testing.expectEqual(end, read);
    try expect_octets(0, output[0..read]);
    // The first block was read to its end; the second still holds unread offsets.
    try testing.expectEqual(all - 1, free_blocks(storage));
}

test "RFC 9000 §2.2: octets out of order wait for the gap, and a repeat changes nothing" {
    const storage = fresh();
    var incoming: Incoming = .{};
    const gap_end: u64 = block_len + 100;
    const end: u64 = 2 * block_len;
    try incoming.write(storage, stream_a, 0, gap_end, frame(gap_end, end));
    // Nothing is readable while the octets before the gap have not arrived.
    try testing.expectEqual(0, incoming.contiguous_end(storage, 0));
    try testing.expectEqual(0, incoming.read(storage, 0, &output));
    try incoming.write(storage, stream_a, 0, 0, frame(0, gap_end));
    // The same octets again, overlapping both writes.
    try incoming.write(storage, stream_a, 0, 50, frame(50, gap_end + 50));
    try testing.expectEqual(end, incoming.contiguous_end(storage, 0));
    const read = incoming.read(storage, 0, &output);
    try testing.expectEqual(end, read);
    try expect_octets(0, output[0..read]);
}

test "decision 61: a read stops where the output ends and goes on from there" {
    const storage = fresh();
    var incoming: Incoming = .{};
    const end: u64 = 2 * block_len;
    try incoming.write(storage, stream_a, 0, 0, frame(0, end));
    const short = incoming.read(storage, 0, output[0..100]);
    try testing.expectEqual(100, short);
    const rest = incoming.read(storage, short, &output);
    try testing.expectEqual(end - short, rest);
    try expect_octets(short, output[0..rest]);
    // Octets below what was read are not kept again when a retransmission carries them.
    const all = free_blocks(storage);
    try incoming.write(storage, stream_a, end, 0, frame(0, end));
    try testing.expectEqual(all, free_blocks(storage));
}

test "decision 61: streams share the pool, and a released stream gives its blocks back" {
    const storage = fresh();
    const all = free_blocks(storage);
    var first: Incoming = .{};
    var second: Incoming = .{};
    try first.write(storage, stream_a, 0, 0, frame(0, block_len));
    try second.write(storage, stream_b, 0, block_len, frame(block_len, 2 * block_len));
    try testing.expectEqual(block_len, first.contiguous_end(storage, 0));
    try testing.expectEqual(0, second.contiguous_end(storage, 0));
    second.release(storage);
    try testing.expect(second.is_empty());
    try testing.expectEqual(all - 1, free_blocks(storage));
    try testing.expectEqual(block_len, first.read(storage, 0, &output));
    try testing.expectEqual(all, free_blocks(storage));
}

test "decision 61: a pool with no block free refuses the write" {
    const storage = fresh();
    var incoming: Incoming = .{};
    const all = free_blocks(storage);
    // One octet at the start of every block the pool has.
    for (0..all) |number| {
        const offset = number * block_len;
        try incoming.write(storage, stream_a, 0, offset, frame(offset, offset + 1));
    }
    const past = all * block_len;
    try testing.expectError(error.PoolExhausted, incoming.write(storage, stream_a, 0, past, frame(past, past + 1)));
    try testing.expectEqual(1, incoming.contiguous_end(storage, 0));
}

test "decision 61: two blocks per stream beyond the capacity" {
    const blocks = @typeInfo(@TypeOf(test_pool.blocks)).array.len;
    const edges: usize = 2;
    try testing.expectEqual(capacity_blocks + edges * constants.streams_per_connection_max, blocks);
}

test "decision 80: a peek copies what a read would, and leaves every block in place" {
    const storage = fresh();
    const all = free_blocks(storage);
    var incoming: Incoming = .{};
    const gap_start: u64 = 2 * block_len + 10;
    try incoming.write(storage, stream_a, 0, 0, frame(0, gap_start));
    try incoming.write(storage, stream_a, 0, gap_start + 1, frame(gap_start + 1, gap_start + 5));
    const taken = free_blocks(storage);
    // The peek stops at the gap, as a read would, and gives nothing back.
    const peeked = incoming.peek(storage, 0, &output);
    try testing.expectEqual(gap_start, peeked);
    try expect_octets(0, output[0..peeked]);
    try testing.expectEqual(taken, free_blocks(storage));
    // A peek from inside the stream, and one cut short by the output.
    try testing.expectEqual(gap_start - 100, incoming.peek(storage, 100, &output));
    try expect_octets(100, output[0 .. gap_start - 100]);
    try testing.expectEqual(block_len + 5, incoming.peek(storage, 0, output[0 .. block_len + 5]));
    try testing.expectEqual(all - 3, taken);
    // A whole block missing: the peek stops at its start, not in the block after it.
    var other: Incoming = .{};
    try other.write(storage, stream_b, 0, 0, frame(0, block_len));
    try other.write(storage, stream_b, 0, 2 * block_len, frame(2 * block_len, 2 * block_len + 5));
    try testing.expectEqual(block_len, other.peek(storage, 0, &output));
}

test "decision 80: a discard gives back the blocks it passes, as a read of them would" {
    const storage = fresh();
    const all = free_blocks(storage);
    var incoming: Incoming = .{};
    const end: u64 = 2 * block_len + 10;
    try incoming.write(storage, stream_a, 0, 0, frame(0, end));
    // Short of a block's end, nothing goes back; at it, that block does.
    incoming.discard(storage, 0, block_len - 1);
    try testing.expectEqual(all - 3, free_blocks(storage));
    incoming.discard(storage, block_len - 1, 1);
    try testing.expectEqual(all - 2, free_blocks(storage));
    // What is left reads from where the discard stopped.
    const read = incoming.read(storage, block_len, &output);
    try testing.expectEqual(end - block_len, read);
    try expect_octets(block_len, output[0..read]);
    try testing.expectEqual(all - 1, free_blocks(storage));
}
