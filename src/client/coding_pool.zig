//! The pools the client decodes `zstd` and `br` with (decision 101 as amended on 2026-09-30,
//! design §8 step 17h): one for each coding, which the caller places and manages. A decoder holds
//! a large window, 8 MB for `zstd` (RFC 9659 §3) and 16 MiB for `br` (RFC 7932 §9.1), so an
//! exchange holds one only from its request to the end of its response, as h11's pool for `gzip`
//! and `deflate` does (decision 91).
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const zstd = @import("zstd");
const brotli = @import("brotli");
const constants = @import("constants.zig");

/// The CPU features the decoders run on, which the caller chooses (`Storage.reset`).
pub const Features = h11.coding.Features;

/// The `zstd` coding (RFC 8878 §7.2): one or more frames (§3.1), each decoded with RFC 9659 §3's
/// window of 8 MB.
pub const Zstd = struct {
    pub const Decoder = zstd.HttpDecoder;
    /// RFC 8878 §3.1: "Zstandard compressed data is made of one or more frames."
    pub const frames_repeat = true;
};

/// The `br` coding (RFC 7932 §13): one stream, whose window reaches `brotli_window_bits_max`.
pub const Brotli = struct {
    pub const Decoder = brotli.Decoder(.{ .window_bits_max = constants.brotli_window_bits_max });
    /// RFC 7932 §9.2: the last meta-block ends the stream, so octets after it belong to none.
    pub const frames_repeat = false;
};

pub const Error = error{
    /// The coded content breaks its format (RFC 8878, RFC 7932), uses a feature stdx refuses, such
    /// as a window past the limit, or goes on past its stream.
    CodingCorrupt,
};

/// Octets of one call: coded ones taken, and decoded ones written.
pub const Progress = h11.coding.Progress;

/// A slot's place in the pool.
const Index = u16;
/// The index that names no slot: the end of the free list, and an exchange with no decoder.
const no_slot: Index = std.math.maxInt(Index);

/// What a pool keeps beside its slots.
pub const Header = struct {
    free_head: Index,
    features: Features,
};

/// One decoder, and its place in the free list while no exchange holds it.
pub fn Slot(comptime Decoder: type) type {
    return struct {
        next: Index,
        decoder: Decoder,
    };
}

/// A pool of `count` decoders of `Codec`, the most responses in that coding the connections given
/// it decode at once. The caller places it (decision 35).
pub fn Pool(comptime Codec: type, comptime count: usize) type {
    comptime assert(count > 0 and count < no_slot);
    return struct {
        header: Header = undefined,
        slots: [count]Slot(Codec.Decoder) = undefined,

        pub fn storage(pool: *@This()) Storage(Codec) {
            return .{ .header = &pool.header, .slots = &pool.slots };
        }
    };
}

/// A pool as a connection holds it, whatever its size.
pub fn Storage(comptime Codec: type) type {
    return struct {
        const Self = @This();

        header: *Header,
        slots: []Slot(Codec.Decoder),

        /// Every slot free, and the CPU features its decoders run on. `Features.target()` is what
        /// the build target guarantees, and `Features.detect()` asks the CPU, which colibri never
        /// does itself. Called once, before the storage is given to any connection.
        pub fn reset(storage: Self, features: Features) void {
            assert(storage.slots.len > 0 and storage.slots.len < no_slot);
            // Bounded by the pool's slots.
            for (storage.slots, 0..) |*slot, index| {
                const following = index + 1;
                slot.next = if (following < storage.slots.len) @intCast(following) else no_slot;
            }
            storage.header.free_head = 0;
            storage.header.features = features;
        }

        /// The decoders no exchange holds.
        pub fn free_count(storage: Self) usize {
            var free: usize = 0;
            var index = storage.header.free_head;
            // Bounded by the pool's slots, each on the free list once.
            for (0..storage.slots.len) |_| {
                if (index == no_slot) break;
                free += 1;
                index = storage.slots[index].next;
            }
            assert(index == no_slot);
            return free;
        }

        fn take(storage: Self) ?Index {
            const index = storage.header.free_head;
            if (index == no_slot) return null;
            assert(index < storage.slots.len);
            storage.header.free_head = storage.slots[index].next;
            return index;
        }

        fn give_back(storage: Self, index: Index) void {
            assert(index < storage.slots.len);
            storage.slots[index].next = storage.header.free_head;
            storage.header.free_head = index;
        }
    };
}

/// One exchange's decoder of `Codec`: none, reserved as its request went out, or decoding its
/// response's content.
pub fn Held(comptime Codec: type) type {
    return struct {
        const Self = @This();

        storage: ?Storage(Codec) = null,
        slot: Index = no_slot,
        active: bool = false,
        /// The stream, or the last frame, ended with every check passed.
        stream_ended: bool = false,

        pub fn holds(held: *const Self) bool {
            return held.slot != no_slot;
        }

        /// Takes a decoder before the response names its coding, and returns false when every
        /// decoder is taken (decision 101).
        pub fn reserve(held: *Self, storage: Storage(Codec)) bool {
            assert(!held.holds() and !held.active);
            held.slot = storage.take() orelse return false;
            held.storage = storage;
            return true;
        }

        /// Starts the reserved decoder on the response's content.
        pub fn begin(held: *Self) void {
            assert(held.holds() and !held.active);
            held.active = true;
            held.start_stream();
        }

        pub fn start_stream(held: *Self) void {
            const storage = held.storage.?;
            storage.slots[held.slot].decoder.init(storage.header.features);
            held.stream_ended = false;
        }

        /// Decodes as much of the coded octets `input` into `output` as both allow.
        pub fn decode(held: *Self, input: []const u8, output: []u8) Error!Progress {
            return decode_held(Codec, held, input, output);
        }

        /// The content ended. Its stream must have ended with it, and the decoder goes back.
        pub fn finish(held: *Self) Error!void {
            assert(held.active);
            const ended = held.stream_ended;
            held.release();
            // RFC 8878 §3.1.1 and RFC 7932 §9.2: content that ends before its stream does is
            // corrupt.
            if (!ended) return error.CodingCorrupt;
        }

        /// Gives the decoder back, reserved or decoding.
        pub fn release(held: *Self) void {
            if (held.holds()) held.storage.?.give_back(held.slot);
            held.* = .{};
        }
    };
}

/// `Held(Codec).decode`, apart from the type so each stays small.
fn decode_held(comptime Codec: type, held: *Held(Codec), input: []const u8, output: []u8) Error!Progress {
    assert(held.active and input.len > 0 and output.len > 0);
    if (held.stream_ended) {
        // RFC 8878 §3.1: octets after a zstd frame start the next one. RFC 7932 §9.2: a br stream
        // ends with its last meta-block, so octets after it are no coding's.
        if (!Codec.frames_repeat) return error.CodingCorrupt;
        held.start_stream();
    }
    const decoder = &held.storage.?.slots[held.slot].decoder;
    // RFC 8878 §3.1.1 and RFC 7932 §9: content that breaks its format, or asks for a window past
    // the limit (RFC 9659 §3), fails the response (decision 101).
    const progress = decoder.decode(input, output) catch return error.CodingCorrupt;
    if (progress.status == .done) held.stream_ended = true;
    return .{ .consumed = progress.consumed, .written = progress.written };
}

/// The `zstd` pool the caller places, of `count` decoders, and as a connection holds it.
pub fn ZstdDecoderPool(comptime count: usize) type {
    return Pool(Zstd, count);
}
pub const ZstdDecoders = Storage(Zstd);

/// The `br` pool the caller places, of `count` decoders, and as a connection holds it.
pub fn BrotliDecoderPool(comptime count: usize) type {
    return Pool(Brotli, count);
}
pub const BrotliDecoders = Storage(Brotli);

comptime {
    // RFC 7932 §9.1: a window of (1 << WBITS) - 16 octets, WBITS from 10 to 24.
    assert(constants.brotli_window_bits_max >= brotli.constants.window_bits_min);
    assert(constants.brotli_window_bits_max <= brotli.constants.window_bits_max);
}

test {
    _ = @import("coding_pool_test.zig");
}
