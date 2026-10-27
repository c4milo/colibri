//! The octets a peer sent on its streams, held until the application reads them (decision 61).
//! Part of design §8 step 9e.
//!
//! One pool per connection holds every stream's unread octets, in blocks of `block_len`. A block
//! belongs to one stream and one run of `block_len` offsets in it. Frames arrive in any order and
//! the same octets may arrive again (RFC 9000 §2.2), so a block marks which of its octets have
//! arrived. The application reads from the lowest offset it has not read, up to the first octet
//! that has not arrived, and a block it has read to the end goes back to the pool.
//!
//! **How a block is found.** The pool finds a stream's block by its number through an index of
//! buckets, one for each block, each a chain of the blocks whose stream and number fall in it
//! (decision 61 as amended on 2026-10-17). A stream's live blocks lie inside its window, which
//! spans fewer numbers than there are buckets, so a chain holds at most one block of each stream.
//! Finding a block therefore takes at most one probe for each stream that holds blocks. A list
//! walked from the stream's first block took one for each block of the stream: up to 1,026 for a
//! window of 1 MiB, which a peer reaches with frames of one octet (RFC 9000 §21.7).
//!
//! **Why one pool is enough.** RFC 9000 §4.1's connection limit bounds the sum of every stream's
//! highest offset, and what the application read comes off the same sum, so the octets between
//! each stream's read offset and its highest offset never pass the connection window. Decision 61
//! caps that window at the pool's capacity. A stream's span may start and end inside a block, so
//! the pool holds two blocks per stream beyond its capacity, and a peer inside its limits never
//! finds it full.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const bit_runs = @import("../bit_runs.zig");

pub const block_len: usize = constants.stream_receive_block_len;

/// Blocks a span of offsets may touch beyond those its length fills: it may start and end inside
/// one.
const span_edges: usize = 2;

/// A block's place in the pool, and the value that names no block.
const Index = u16;
const no_block: Index = std.math.maxInt(Index);

/// Spreads the streams over the buckets, so streams whose blocks have the same numbers, as every
/// stream's first blocks do, fall in different ones: the 64-bit golden ratio, which is odd.
const stream_spread: u64 = 0x9e37_79b9_7f4a_7c15;

pub const Error = error{
    /// No block is free. Flow control bounds what a peer may send to what the pool holds, so this
    /// is colibri's own accounting gone wrong, and the connection closes on it.
    PoolExhausted,
};

/// One block of the pool.
pub const Block = struct {
    /// The stream it holds octets of, by its 62-bit identifier (RFC 9000 §2.1).
    stream_id: u64,
    /// Which run of `block_len` offsets it holds: its first octet is at `number * block_len`.
    number: u64,
    /// The next block of its bucket's chain, or the next free block.
    next: Index,
    /// Which of its octets have arrived.
    present: std.StaticBitSet(block_len),
};

/// What the pool keeps beside its blocks.
pub const Header = struct {
    free_head: Index,
};

/// A pool of `capacity` octets, which is the most every stream of one connection may hold unread
/// at once, and so the connection's and each stream's window cap (decision 61). The caller places
/// it (decision 35).
pub fn Pool(comptime capacity: usize) type {
    comptime assert(capacity > 0 and capacity % block_len == 0);
    const count = capacity / block_len + span_edges * constants.streams_per_connection_max;
    comptime assert(count < no_block);
    return struct {
        header: Header = undefined,
        blocks: [count]Block = undefined,
        buckets: [count]Index = undefined,
        octets: [count][block_len]u8 = undefined,

        pub fn storage(pool: *@This()) Storage {
            return .{ .header = &pool.header, .blocks = &pool.blocks, .buckets = &pool.buckets, .octets = &pool.octets, .capacity = capacity };
        }
    };
}

/// The pool a caller gets by asking for no size in particular (decision 61).
pub const DefaultPool = Pool(constants.receive_pool_len_default);

/// A pool as the connection holds it, whatever its capacity.
pub const Storage = struct {
    header: *Header,
    blocks: []Block,
    /// The first block of each bucket's chain.
    buckets: []Index,
    octets: [][block_len]u8,
    capacity: u64,

    /// Every block free and every bucket empty, which is how a connection starts.
    pub fn reset(storage: Storage) void {
        assert(storage.blocks.len == storage.octets.len and storage.blocks.len == storage.buckets.len);
        // Bounded by the pool's blocks.
        for (storage.blocks, 0..) |*block, index| {
            const following = index + 1;
            block.next = if (following < storage.blocks.len) @intCast(following) else no_block;
        }
        @memset(storage.buckets, no_block);
        storage.header.free_head = 0;
    }

    /// The bucket of the block `number` of `stream_id`. Consecutive numbers of one stream fall in
    /// consecutive buckets.
    fn bucket_of(storage: Storage, stream_id: u64, number: u64) usize {
        return @intCast((number +% stream_id *% stream_spread) % @as(u64, storage.buckets.len));
    }

    /// The block `number` of `stream_id`, or null when the stream holds none there.
    fn find(storage: Storage, stream_id: u64, number: u64) ?Index {
        var current = storage.buckets[storage.bucket_of(stream_id, number)];
        // Bounded by the pool's blocks. A chain holds at most one block of each stream.
        for (0..storage.blocks.len) |_| {
            if (current == no_block) return null;
            const block = &storage.blocks[current];
            if (block.number == number and block.stream_id == stream_id) return current;
            current = block.next;
        }
        unreachable;
    }

    /// Takes a free block for `number` of `stream_id`, with none of its octets arrived, and puts it
    /// first in its bucket's chain.
    fn add(storage: Storage, stream_id: u64, number: u64) Error!Index {
        const index = storage.header.free_head;
        if (index == no_block) return Error.PoolExhausted;
        storage.header.free_head = storage.blocks[index].next;
        const bucket = &storage.buckets[storage.bucket_of(stream_id, number)];
        storage.blocks[index] = .{ .stream_id = stream_id, .number = number, .next = bucket.*, .present = .initEmpty() };
        bucket.* = index;
        return index;
    }

    /// Takes block `index` out of its bucket's chain and gives it back to the pool.
    fn remove(storage: Storage, index: Index) void {
        const removed = &storage.blocks[index];
        const bucket = &storage.buckets[storage.bucket_of(removed.stream_id, removed.number)];
        if (bucket.* == index) {
            bucket.* = removed.next;
        } else {
            var previous = bucket.*;
            // Bounded by the pool's blocks: the block is in this chain.
            for (0..storage.blocks.len) |_| {
                assert(previous != no_block);
                if (storage.blocks[previous].next == index) break;
                previous = storage.blocks[previous].next;
            }
            assert(storage.blocks[previous].next == index);
            storage.blocks[previous].next = removed.next;
        }
        removed.next = storage.header.free_head;
        storage.header.free_head = index;
    }
};

/// One stream's unread octets: how many blocks of the pool hold them.
pub const Incoming = struct {
    held: u32 = 0,

    pub fn is_empty(incoming: *const Incoming) bool {
        return incoming.held == 0;
    }

    /// Keeps `data`, which a STREAM frame carried at `offset`. Octets below `read_offset` were
    /// read already, and octets that arrived before are written again with the same values
    /// (RFC 9000 §2.2: "The data at a given offset MUST NOT change").
    pub fn write(incoming: *Incoming, storage: Storage, stream_id: u64, read_offset: u64, offset: u64, data: []const u8) Error!void {
        const end = offset + data.len;
        var at = @max(offset, read_offset);
        // Bounded: each pass writes to the end of a block or of the data, so the data spans at
        // most this many blocks.
        for (0..data.len / block_len + span_edges) |_| {
            if (at >= end) return;
            const index = try incoming.block_for(storage, stream_id, read_offset, at / block_len);
            const within: usize = @intCast(at % block_len);
            const len: usize = @intCast(@min(end - at, block_len - within));
            const from: usize = @intCast(at - offset);
            @memcpy(storage.octets[index][within..][0..len], data[from..][0..len]);
            storage.blocks[index].present.setRangeValue(.{ .start = within, .end = within + len }, true);
            at += len;
        }
        assert(at >= end);
    }

    /// The stream's block holding offsets from `number * block_len`, taken from the pool when the
    /// stream holds none there yet.
    fn block_for(incoming: *Incoming, storage: Storage, stream_id: u64, read_offset: u64, number: u64) Error!Index {
        if (storage.find(stream_id, number)) |index| return index;
        const index = try storage.add(stream_id, number);
        // Flow control keeps a stream's blocks inside its window, which spans fewer numbers than
        // there are buckets, so the stream holds no other block in this bucket.
        assert(number - read_offset / block_len < storage.blocks.len);
        incoming.held += 1;
        return index;
    }

    /// Copies the octets from `read_offset` up to the first that has not arrived into `output`,
    /// as many as fit, and returns how many. A block read to its end goes back to the pool.
    pub fn read(incoming: *Incoming, storage: Storage, stream_id: u64, read_offset: u64, output: []u8) usize {
        var at = read_offset;
        var written: usize = 0;
        // Bounded: each pass reads to the end of a block, to a gap or to the end of `output`.
        for (0..output.len / block_len + span_edges) |_| {
            if (written == output.len) break;
            const index = storage.find(stream_id, at / block_len) orelse break;
            const within: usize = @intCast(at % block_len);
            const run = present_run(&storage.blocks[index], within, output.len - written);
            @memcpy(output[written..][0..run], storage.octets[index][within..][0..run]);
            written += run;
            at += run;
            if (within + run < block_len) break;
            incoming.give_back(storage, index);
        }
        return written;
    }

    /// Copies the octets from `read_offset` up to the first that has not arrived into `output`,
    /// as many as fit, and returns how many. Unlike `read`, it gives no block back, so the same
    /// octets are there to copy or read again.
    pub fn peek(incoming: *const Incoming, storage: Storage, stream_id: u64, read_offset: u64, output: []u8) usize {
        _ = incoming;
        var at = read_offset;
        var written: usize = 0;
        // Bounded: each pass copies to the end of a block, to a gap or to the end of `output`.
        for (0..output.len / block_len + span_edges) |_| {
            if (written == output.len) break;
            const index = storage.find(stream_id, at / block_len) orelse break;
            const within: usize = @intCast(at % block_len);
            const run = present_run(&storage.blocks[index], within, output.len - written);
            @memcpy(output[written..][0..run], storage.octets[index][within..][0..run]);
            written += run;
            at += run;
            // A run that stops short of the block's end leaves `at` inside it, where the next
            // pass would find the same block and copy nothing.
            if (within + run < block_len) break;
        }
        return written;
    }

    /// Drops `len` octets from `read_offset`, as reading them would, without copying them. Every
    /// one of them has arrived: the caller drops only octets it has seen.
    pub fn discard(incoming: *Incoming, storage: Storage, stream_id: u64, read_offset: u64, len: u64) void {
        assert(incoming.contiguous_end(storage, stream_id, read_offset) >= read_offset + len);
        const end = read_offset + len;
        var number = read_offset / block_len;
        // Bounded by the blocks the octets span. A block goes back once every octet in it lies
        // below `end`.
        for (0..len / block_len + span_edges) |_| {
            if ((number + 1) * block_len > end) return;
            const index = storage.find(stream_id, number) orelse unreachable;
            incoming.give_back(storage, index);
            number += 1;
        }
    }

    /// The offset of the first octet at or above `read_offset` that has not arrived.
    pub fn contiguous_end(incoming: *const Incoming, storage: Storage, stream_id: u64, read_offset: u64) u64 {
        _ = incoming;
        var at = read_offset;
        // Bounded by the pool's blocks.
        for (0..storage.blocks.len) |_| {
            const index = storage.find(stream_id, at / block_len) orelse break;
            const within: usize = @intCast(at % block_len);
            const run = present_run(&storage.blocks[index], within, block_len - within);
            at += run;
            // A run that stops short of the block's end leaves `at` inside it, at the octet that
            // has not arrived.
            if (within + run < block_len) break;
        }
        return at;
    }

    /// Gives every block back, which a stream that was reset or closed no longer needs, given the
    /// stream's read offset. It probes the stream's own block numbers, not every bucket.
    pub fn release(incoming: *Incoming, storage: Storage, stream_id: u64, read_offset: u64) void {
        // A block below the one `read_offset` lies in was read to its end and went back, and flow
        // control keeps the rest inside the window, which spans fewer numbers than the pool has
        // blocks (decision 61). So the walk probes the numbers from there up until none is held.
        var number = read_offset / block_len;
        for (0..storage.blocks.len) |_| {
            if (incoming.held == 0) return;
            if (storage.find(stream_id, number)) |index| incoming.give_back(storage, index);
            number += 1;
        }
        assert(incoming.held == 0);
    }

    fn give_back(incoming: *Incoming, storage: Storage, index: Index) void {
        assert(incoming.held > 0);
        storage.remove(index);
        incoming.held -= 1;
    }
};

/// How many octets from `within` have arrived, up to `limit`.
fn present_run(block: *const Block, within: usize, limit: usize) usize {
    assert(within <= block_len);
    return bit_runs.first_unset(&block.present, within, @min(within + limit, block_len)) - within;
}

test {
    _ = @import("stream_incoming_test.zig");
    _ = @import("stream_incoming_index_test.zig");
}
