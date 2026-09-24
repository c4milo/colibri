//! The octets a peer sent on its streams, held until the application reads them (decision 61).
//! Part of design §8 step 9e.
//!
//! One pool per connection holds every stream's unread octets, in blocks of `block_len`. A block
//! belongs to one stream and one run of `block_len` offsets in it, and each stream keeps its blocks
//! in a list in offset order. Frames arrive in any order and the same octets may arrive again (RFC
//! 9000 §2.2), so a block marks which of its octets have arrived. The application reads from the
//! lowest offset it has not read, up to the first octet that has not arrived, and a block it has
//! read to the end goes back to the pool.
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

pub const block_len: usize = constants.stream_receive_block_len;

/// Blocks a span of offsets may touch beyond those its length fills: it may start and end inside
/// one.
const span_edges: usize = 2;

/// A block's place in the pool, and the value that names no block.
const Index = u16;
const no_block: Index = std.math.maxInt(Index);

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
    /// The stream's next block, in offset order, or the next free block.
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
        octets: [count][block_len]u8 = undefined,

        pub fn storage(pool: *@This()) Storage {
            return .{ .header = &pool.header, .blocks = &pool.blocks, .octets = &pool.octets, .capacity = capacity };
        }
    };
}

/// The pool a caller gets by asking for no size in particular (decision 61).
pub const DefaultPool = Pool(constants.receive_pool_len_default);

/// A pool as the connection holds it, whatever its capacity.
pub const Storage = struct {
    header: *Header,
    blocks: []Block,
    octets: [][block_len]u8,
    capacity: u64,

    /// Every block free, which is how a connection starts.
    pub fn reset(storage: Storage) void {
        assert(storage.blocks.len == storage.octets.len);
        // Bounded by the pool's blocks.
        for (storage.blocks, 0..) |*block, index| {
            const following = index + 1;
            block.next = if (following < storage.blocks.len) @intCast(following) else no_block;
        }
        storage.header.free_head = 0;
    }

    fn take(storage: Storage) Error!Index {
        const index = storage.header.free_head;
        if (index == no_block) return Error.PoolExhausted;
        storage.header.free_head = storage.blocks[index].next;
        return index;
    }

    fn give_back(storage: Storage, index: Index) void {
        storage.blocks[index].next = storage.header.free_head;
        storage.header.free_head = index;
    }
};

/// One stream's unread octets: the first of its blocks, in offset order.
pub const Incoming = struct {
    first: Index = no_block,

    pub fn is_empty(incoming: *const Incoming) bool {
        return incoming.first == no_block;
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
            const index = try incoming.block_for(storage, stream_id, at / block_len);
            const within: usize = @intCast(at % block_len);
            const len: usize = @intCast(@min(end - at, block_len - within));
            const from: usize = @intCast(at - offset);
            @memcpy(storage.octets[index][within..][0..len], data[from..][0..len]);
            storage.blocks[index].present.setRangeValue(.{ .start = within, .end = within + len }, true);
            at += len;
        }
        assert(at >= end);
    }

    /// The stream's block holding offsets from `number * block_len`, taken from the pool and put
    /// in order when the stream holds none yet.
    fn block_for(incoming: *Incoming, storage: Storage, stream_id: u64, number: u64) Error!Index {
        var previous: Index = no_block;
        var current = incoming.first;
        // Bounded by the pool's blocks, which is the longest a stream's list can be.
        for (0..storage.blocks.len) |_| {
            if (current == no_block or storage.blocks[current].number >= number) break;
            previous = current;
            current = storage.blocks[current].next;
        }
        if (current != no_block and storage.blocks[current].number == number) return current;
        const index = try storage.take();
        storage.blocks[index] = .{ .stream_id = stream_id, .number = number, .next = current, .present = .initEmpty() };
        if (previous == no_block) incoming.first = index else storage.blocks[previous].next = index;
        return index;
    }

    /// Copies the octets from `read_offset` up to the first that has not arrived into `output`,
    /// as many as fit, and returns how many. A block read to its end goes back to the pool.
    pub fn read(incoming: *Incoming, storage: Storage, read_offset: u64, output: []u8) usize {
        var at = read_offset;
        var written: usize = 0;
        // Bounded: each pass reads to the end of a block, to a gap or to the end of `output`.
        for (0..output.len / block_len + span_edges) |_| {
            if (written == output.len or incoming.first == no_block) break;
            const index = incoming.first;
            const block = &storage.blocks[index];
            if (block.number != at / block_len) break;
            const within: usize = @intCast(at % block_len);
            const run = present_run(block, within, output.len - written);
            @memcpy(output[written..][0..run], storage.octets[index][within..][0..run]);
            written += run;
            at += run;
            if (within + run < block_len) break;
            incoming.first = block.next;
            storage.give_back(index);
        }
        return written;
    }

    /// Copies the octets from `read_offset` up to the first that has not arrived into `output`,
    /// as many as fit, and returns how many. Unlike `read`, it gives no block back, so the same
    /// octets are there to copy or read again.
    pub fn peek(incoming: *const Incoming, storage: Storage, read_offset: u64, output: []u8) usize {
        var at = read_offset;
        var written: usize = 0;
        var current = incoming.first;
        // Bounded: each pass copies to the end of a block, to a gap or to the end of `output`.
        for (0..output.len / block_len + span_edges) |_| {
            if (written == output.len or current == no_block) break;
            const block = &storage.blocks[current];
            if (block.number != at / block_len) break;
            const within: usize = @intCast(at % block_len);
            const run = present_run(block, within, output.len - written);
            @memcpy(output[written..][0..run], storage.octets[current][within..][0..run]);
            written += run;
            at += run;
            // A run that stops short of the block's end leaves `at` inside it, so the next
            // block's number is not the one asked for and the walk ends there.
            current = block.next;
        }
        return written;
    }

    /// Drops `len` octets from `read_offset`, as reading them would, without copying them. Every
    /// one of them has arrived: the caller drops only octets it has seen.
    pub fn discard(incoming: *Incoming, storage: Storage, read_offset: u64, len: u64) void {
        assert(incoming.contiguous_end(storage, read_offset) >= read_offset + len);
        const end = read_offset + len;
        // Bounded by the pool's blocks. A block goes back once every octet in it lies below `end`.
        for (0..storage.blocks.len) |_| {
            const index = incoming.first;
            if (index == no_block) return;
            if ((storage.blocks[index].number + 1) * block_len > end) return;
            incoming.first = storage.blocks[index].next;
            storage.give_back(index);
        }
    }

    /// The offset of the first octet at or above `read_offset` that has not arrived.
    pub fn contiguous_end(incoming: *const Incoming, storage: Storage, read_offset: u64) u64 {
        var at = read_offset;
        var current = incoming.first;
        // Bounded by the pool's blocks.
        for (0..storage.blocks.len) |_| {
            if (current == no_block) break;
            const block = &storage.blocks[current];
            if (block.number != at / block_len) break;
            const within: usize = @intCast(at % block_len);
            // A run that stops short of the block's end leaves `at` inside it, so the next block's
            // number is not the one asked for and the walk ends there.
            at += present_run(block, within, block_len - within);
            current = block.next;
        }
        return at;
    }

    /// Gives every block back, which a stream that was reset or closed no longer needs.
    pub fn release(incoming: *Incoming, storage: Storage) void {
        // Bounded by the pool's blocks.
        for (0..storage.blocks.len) |_| {
            const index = incoming.first;
            if (index == no_block) return;
            incoming.first = storage.blocks[index].next;
            storage.give_back(index);
        }
        assert(incoming.first == no_block);
    }
};

/// How many octets from `within` have arrived, up to `limit`.
fn present_run(block: *const Block, within: usize, limit: usize) usize {
    var run: usize = 0;
    // Bounded by `limit`, which is at most a block.
    while (run < limit and within + run < block_len and block.present.isSet(within + run)) run += 1;
    return run;
}

test {
    _ = @import("stream_incoming_test.zig");
}
