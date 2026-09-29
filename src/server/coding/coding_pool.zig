//! The encoders a server codes response content with (decision 101, design §8 step 17e). They wait
//! in a pool the caller places, and a response holds one only while its content is coded. Each
//! slot holds an encoder of the level the caller chose at build time, because stdx's encoder is
//! one type per level, and a ring of `encoder_ring_len` coded octets that the response sends from
//! (the owner's ruling of 2026-09-28): h11 and h2 copy from it, and h3 sends from it in place until
//! the peer acknowledges the octets.
//!
//! A connection holds the pool as `Encoders`, whatever its size and level: a pointer to the pool
//! and the calls that reach its slots.
const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const gzip = @import("gzip");
const zlib = @import("zlib");
const http = @import("http");
const constants = @import("../constants.zig");
const coding_ring = @import("coding_ring.zig");

const Coding = http.content_coding.Coding;
pub const Features = codec.Features;
pub const Flush = codec.Flush;
pub const Progress = codec.Progress;

/// A slot's place in the pool.
pub const Index = u16;
/// The index that names no slot: the end of the free list.
const no_slot: Index = std.math.maxInt(Index);

/// A slot's ring of coded octets.
pub const Ring = coding_ring.Octets;

/// A pool as a connection holds it, whatever its size and level.
pub const Encoders = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        take: *const fn (context: *anyopaque, coding: Coding) ?Index,
        encode: *const fn (context: *anyopaque, index: Index, input: []const u8, output: []u8, flush: Flush) Progress,
        ring: *const fn (context: *anyopaque, index: Index) *Ring,
        give_back: *const fn (context: *anyopaque, index: Index) void,
    };

    /// Takes a free slot and starts its encoder on `coding`, or answers null when every slot is
    /// taken, and the response goes uncoded (decision 101).
    pub fn take(encoders: Encoders, coding: Coding) ?Index {
        return encoders.vtable.take(encoders.context, coding);
    }

    /// Codes as much of `input` into `output` as both allow, and with `flush` ends a block or the
    /// stream (stdx's decision 11).
    pub fn encode(encoders: Encoders, index: Index, input: []const u8, output: []u8, flush: Flush) Progress {
        return encoders.vtable.encode(encoders.context, index, input, output, flush);
    }

    /// Slot `index`'s ring, which its response writes coded octets into and sends from.
    pub fn ring(encoders: Encoders, index: Index) *Ring {
        return encoders.vtable.ring(encoders.context, index);
    }

    /// Frees slot `index` once its response reads nothing more from its ring.
    pub fn give_back(encoders: Encoders, index: Index) void {
        encoders.vtable.give_back(encoders.context, index);
    }
};

/// A pool of `count` encoders at deflate level `level`, 1, 6 or 9: the most coded responses the
/// connections given it send at once. The caller places it (decision 35) and calls `reset` once
/// before giving any connection its `encoders`.
pub fn EncoderPool(comptime count: usize, comptime level: u4) type {
    comptime assert(count > 0 and count < no_slot);
    return struct {
        const Self = @This();
        const Gzip = gzip.Encoder(.{ .level = level });
        const Zlib = zlib.Encoder(.{ .level = level });

        const Slot = struct {
            /// Whether a response holds the slot.
            taken: bool,
            /// The next free slot, while this one is free.
            next: Index,
            /// The coding the response that took the slot codes with.
            coding: Coding,
            encoder: union { gzip: Gzip, deflate: Zlib },
            ring: Ring,
        };

        free_head: Index,
        /// Slots no response holds.
        free_len: usize,
        features: Features,
        slots: [count]Slot,

        /// Every slot free, and the CPU features its encoders run on: `Features.target()`, what
        /// the build target guarantees, or `Features.detect()`, which asks the CPU, as colibri
        /// never does itself.
        pub fn reset(pool: *Self, features: Features) void {
            // Bounded by the pool's slots, each free and followed by the next.
            for (&pool.slots, 1..) |*slot, following| {
                slot.taken = false;
                slot.next = @intCast(following);
            }
            pool.slots[count - 1].next = no_slot;
            pool.free_head = 0;
            pool.free_len = count;
            pool.features = features;
        }

        /// The slots no response holds.
        pub fn free_count(pool: *const Self) usize {
            assert(pool.free_len <= count);
            assert((pool.free_len == 0) == (pool.free_head == no_slot));
            return pool.free_len;
        }

        /// The pool as connections hold it.
        pub fn encoders(pool: *Self) Encoders {
            return .{ .context = pool, .vtable = &vtable };
        }

        const vtable: Encoders.VTable = .{ .take = take, .encode = encode, .ring = ring, .give_back = give_back };

        fn of(context: *anyopaque) *Self {
            return @ptrCast(@alignCast(context));
        }

        fn take(context: *anyopaque, coding: Coding) ?Index {
            const pool = of(context);
            const index = pool.free_head;
            if (index == no_slot) return null;
            assert(index < count);
            const slot = &pool.slots[index];
            assert(!slot.taken);
            pool.free_head = slot.next;
            pool.free_len -= 1;
            slot.taken = true;
            slot.next = no_slot;
            slot.coding = coding;
            switch (coding) {
                .gzip => {
                    slot.encoder = .{ .gzip = undefined };
                    slot.encoder.gzip.init(pool.features);
                },
                .deflate => {
                    slot.encoder = .{ .deflate = undefined };
                    slot.encoder.deflate.init(pool.features);
                },
            }
            return index;
        }

        fn encode(context: *anyopaque, index: Index, input: []const u8, output: []u8, flush: Flush) Progress {
            const slot = &of(context).slots[index];
            assert(slot.taken);
            return switch (slot.coding) {
                .gzip => slot.encoder.gzip.encode(input, output, flush),
                .deflate => slot.encoder.deflate.encode(input, output, flush),
            };
        }

        fn ring(context: *anyopaque, index: Index) *Ring {
            const slot = &of(context).slots[index];
            assert(slot.taken);
            return &slot.ring;
        }

        fn give_back(context: *anyopaque, index: Index) void {
            const pool = of(context);
            assert(index < count);
            const slot = &pool.slots[index];
            // A slot given back twice would join the free list twice.
            assert(slot.taken);
            slot.taken = false;
            slot.next = pool.free_head;
            pool.free_head = index;
            pool.free_len += 1;
        }
    };
}

/// The pool a caller gets by asking for no size or level in particular.
pub const DefaultEncoderPool = EncoderPool(constants.encoders_default, constants.encoder_level_default);

const testing = std.testing;

/// A small pool, outside any stack frame, and a decoder that reads its output back. Test-only.
const TestPool = EncoderPool(test_slots, 1);
const test_slots: usize = 2;
threadlocal var test_pool: TestPool align(@alignOf(TestPool)) = undefined;
threadlocal var test_gzip_decoder: gzip.Decoder align(@alignOf(gzip.Decoder)) = undefined;
threadlocal var test_zlib_decoder: zlib.Decoder align(@alignOf(zlib.Decoder)) = undefined;
threadlocal var test_decoded: [test_decoded_len]u8 = undefined;
const test_decoded_len: usize = 4096;
const test_text = "colibri codes content with stdx, and a client reads it back octet for octet. " ** test_text_repeats;
const test_text_repeats: usize = 8;

/// Codes `test_text` through slot `index` into its ring in one call, and returns the coded octets.
fn code_all(encoders: Encoders, index: Index) ![]const u8 {
    const coded = encoders.ring(index);
    const progress = encoders.encode(index, test_text, coded, .finish);
    try testing.expectEqual(codec.Status.done, progress.status);
    try testing.expectEqual(test_text.len, progress.consumed);
    return coded[0..progress.written];
}

test "decision 101: a slot codes gzip and deflate, which stdx's decoders read back whole" {
    test_pool.reset(.none());
    const encoders = test_pool.encoders();
    const gzip_slot = encoders.take(.gzip).?;
    const deflate_slot = encoders.take(.deflate).?;
    try testing.expect(gzip_slot != deflate_slot);
    const gzipped = try code_all(encoders, gzip_slot);
    gzip.init(&test_gzip_decoder, .none());
    const unzipped = try gzip.decode_all(&test_gzip_decoder, gzipped, &test_decoded);
    try testing.expectEqualStrings(test_text, test_decoded[0..unzipped.written]);
    const deflated = try code_all(encoders, deflate_slot);
    zlib.init(&test_zlib_decoder, .none());
    const inflated = try zlib.decode_all(&test_zlib_decoder, deflated, &test_decoded);
    try testing.expectEqualStrings(test_text, test_decoded[0..inflated.written]);
}

test "decision 101: every slot taken leaves a response uncoded, and one given back is taken again" {
    test_pool.reset(.none());
    const encoders = test_pool.encoders();
    const first = encoders.take(.gzip).?;
    _ = encoders.take(.deflate).?;
    try testing.expectEqual(null, encoders.take(.gzip));
    try testing.expectEqual(0, test_pool.free_count());
    encoders.give_back(first);
    try testing.expectEqual(1, test_pool.free_count());
    try testing.expectEqual(first, encoders.take(.deflate).?);
    // A slot taken again starts a new stream on its new coding.
    const deflated = try code_all(encoders, first);
    zlib.init(&test_zlib_decoder, .none());
    const inflated = try zlib.decode_all(&test_zlib_decoder, deflated, &test_decoded);
    try testing.expectEqualStrings(test_text, test_decoded[0..inflated.written]);
}
