//! The `gzip` and `deflate` transfer codings (RFC 9112 §7.2), which stdx decodes (decisions 90
//! and 91). A decoder holds a window of 32,768 octets (RFC 1951 §2), so a connection keeps none:
//! decoders wait in a pool the caller places, and a connection takes one only while a message
//! carries a compression coding, and gives it back when the message ends (decision 91). The
//! decoded octets go into the buffer the caller passes to `receive` (decision 98).
//!
//! `deflate` is the zlib format of RFC 1950, as RFC 9110 §8.4.1.2 defines it, and `gzip` the
//! format of RFC 1952 (§8.4.1.3). A gzip body may hold several members, each checked, one after
//! another (RFC 1952 §2.2). stdx sorts its refusals in two classes, and h11 keeps them apart
//! (decision 91): a body that breaks its RFC is corrupt, and one that uses a feature stdx refuses,
//! such as a zlib preset dictionary (RFC 1950 §2.3), is refused.
const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const gzip = @import("gzip");
const zlib = @import("zlib");
const constants = @import("constants.zig");
const message = @import("message/message.zig");

/// The CPU features the decoders run on, which the caller chooses (`Storage.reset`).
pub const Features = codec.Features;

pub const Error = error{
    /// The coded body breaks RFC 1950, 1951 or 1952, or the body ends before its coded stream
    /// does (decision 91).
    CodingCorrupt,
    /// The coded body uses a valid feature stdx refuses (decision 91).
    CodingFeatureRefused,
    /// Octets follow the end of the coded stream inside the body (decision 91).
    CodingTrailing,
    /// Every decoder of the pool is taken (decision 91).
    DecodersExhausted,
};

/// A slot's place in the pool.
const Index = u16;
/// The index that names no slot: the end of the free list, and a message with no decoder.
const no_slot: Index = std.math.maxInt(Index);

/// One decoder. The coding of the message that took it decides which container it reads.
pub const Slot = struct {
    /// The next free slot, while this one is free.
    next: Index,
    decoder: union { gzip: gzip.Decoder, zlib: zlib.Decoder },
};

/// What the pool keeps beside its slots.
pub const Header = struct {
    free_head: Index,
    features: Features,
};

/// A pool of `count` decoders, the most messages carrying `gzip` or `deflate` that the
/// connections given it decode at once. The caller places it (decision 35).
pub fn Pool(comptime count: usize) type {
    comptime assert(count > 0 and count < no_slot);
    return struct {
        header: Header = undefined,
        slots: [count]Slot = undefined,

        pub fn storage(pool: *@This()) Storage {
            return .{ .header = &pool.header, .slots = &pool.slots };
        }
    };
}

/// The pool a caller gets by asking for no size in particular (decision 91).
pub const DefaultPool = Pool(constants.decoders_default);

/// A pool as a connection holds it, whatever its size.
pub const Storage = struct {
    header: *Header,
    slots: []Slot,

    /// Every slot free, and the CPU features its decoders run on. `Features.target()` is what the
    /// build target guarantees; `Features.detect()` asks the CPU, which colibri never does itself.
    /// Called once, before the storage is given to any connection.
    pub fn reset(storage: Storage, features: Features) void {
        assert(storage.slots.len > 0 and storage.slots.len < no_slot);
        // Bounded by the pool's slots.
        for (storage.slots, 0..) |*slot, index| {
            const following = index + 1;
            slot.next = if (following < storage.slots.len) @intCast(following) else no_slot;
        }
        storage.header.free_head = 0;
        storage.header.features = features;
    }

    fn take(storage: Storage) ?Index {
        const index = storage.header.free_head;
        if (index == no_slot) return null;
        assert(index < storage.slots.len);
        storage.header.free_head = storage.slots[index].next;
        return index;
    }

    fn give_back(storage: Storage, index: Index) void {
        assert(index < storage.slots.len);
        storage.slots[index].next = storage.header.free_head;
        storage.header.free_head = index;
    }
};

/// One message's decoding: its coding, the decoder it took, and whether the coded stream ended.
pub const Decoding = struct {
    coding: message.Coding = .none,
    slot: Index = no_slot,
    /// The zlib stream, or the last gzip member, ended with every check passed.
    stream_ended: bool = false,

    pub fn active(decoding: *const Decoding) bool {
        return decoding.coding != .none;
    }
};

/// Octets of one call: coded ones taken, and decoded ones written.
pub const Progress = struct {
    consumed: usize,
    written: usize,
};

/// Takes a decoder for a message whose body carries `coding`.
pub fn start(decoding: *Decoding, storage: Storage, coding: message.Coding) Error!void {
    assert(coding != .none);
    assert(!decoding.active() and decoding.slot == no_slot);
    // RFC 9110 §15.6.4 and decision 91: every decoder taken is a temporary overload, which a server
    // answers 503 and a client fails on.
    const index = storage.take() orelse return error.DecodersExhausted;
    decoding.* = .{ .coding = coding, .slot = index };
    begin_stream(decoding, storage);
}

/// Starts the decoder on a stream, or on the next member of a gzip body.
fn begin_stream(decoding: *Decoding, storage: Storage) void {
    const slot = &storage.slots[decoding.slot];
    switch (decoding.coding) {
        .gzip => {
            slot.decoder = .{ .gzip = undefined };
            gzip.init(&slot.decoder.gzip, storage.header.features);
        },
        .deflate => {
            slot.decoder = .{ .zlib = undefined };
            zlib.init(&slot.decoder.zlib, storage.header.features);
        },
        .none => unreachable,
    }
    decoding.stream_ended = false;
}

/// Decodes as much of the coded octets `input` into `output` as both allow.
pub fn decode(decoding: *Decoding, storage: Storage, input: []const u8, output: []u8) Error!Progress {
    assert(decoding.active() and decoding.slot != no_slot);
    assert(input.len > 0 and output.len > 0);
    if (decoding.stream_ended) {
        // RFC 1952 §2.2: a gzip body is a series of members, so octets after one start the next,
        // whose header check refuses octets that are not one.
        if (decoding.coding == .gzip) {
            begin_stream(decoding, storage);
        } else {
            // RFC 9110 §8.4.1.2: deflate is one zlib stream (RFC 1950), so octets after it inside
            // the body belong to no coding, which decision 91 refuses as malformed.
            return error.CodingTrailing;
        }
    }
    const slot = &storage.slots[decoding.slot];
    const progress = switch (decoding.coding) {
        .gzip => gzip.decode(&slot.decoder.gzip, input, output) catch |failure| {
            return refused(gzip.refusal(failure));
        },
        .deflate => zlib.decode(&slot.decoder.zlib, input, output) catch |failure| {
            return refused(zlib.refusal(failure));
        },
        .none => unreachable,
    };
    if (progress.status == .done) decoding.stream_ended = true;
    return .{ .consumed = progress.consumed, .written = progress.written };
}

/// Decision 91: a corrupt body is a 400, and a feature stdx refuses is a 501 (RFC 9112 §6.1).
fn refused(refusal: codec.Refusal) Error {
    return switch (refusal) {
        .corrupt => error.CodingCorrupt,
        .unsupported => error.CodingFeatureRefused,
    };
}

/// The body ended. The coded stream must have ended with it, and the decoder goes back.
pub fn finish(decoding: *Decoding, storage: Storage) Error!void {
    assert(decoding.active());
    const ended = decoding.stream_ended;
    release(decoding, storage);
    // RFC 1950 §2.2 and RFC 1952 §2.3: a stream ends with its checksum, so a body that ends before
    // the checksum arrives is corrupt.
    if (!ended) return error.CodingCorrupt;
}

/// Gives the decoder back, whether the body ended or the connection did.
pub fn release(decoding: *Decoding, storage: ?Storage) void {
    if (decoding.slot != no_slot) storage.?.give_back(decoding.slot);
    decoding.* = .{};
}

const testing = std.testing;

/// Decoders in the pool the tests run on: two, so a third message finds none. Test-only.
const test_pool_count = 2;
/// The pool and the encoder the tests run on, placed outside any stack frame. Test-only.
threadlocal var test_pool: Pool(test_pool_count) align(@alignOf(Pool(test_pool_count))) = undefined;
threadlocal var test_gzip: gzip.Encoder(.{ .level = 1 }) align(@alignOf(gzip.Encoder(.{ .level = 1 }))) = undefined;
threadlocal var test_zlib: zlib.Encoder(.{ .level = 1 }) align(@alignOf(zlib.Encoder(.{ .level = 1 }))) = undefined;

/// Copies of the sentence in `test_text`: enough for DEFLATE to use back-references. Test-only.
const test_text_repeats = 8;
/// The text the tests code. Test-only.
const test_text = "colibri decodes gzip and deflate transfer codings. " ** test_text_repeats;
/// Room for any coded or decoded form of `test_text`: stored blocks never double it. Test-only.
const test_room = test_text.len * test_room_factor + test_room_margin;
const test_room_factor = 2;
const test_room_margin = 64;
/// RFC 1952 §2.3: a member ends with CRC32 and ISIZE, four octets each, so its CRC32 starts this
/// far from its end. Test-only.
const crc32_offset_from_end = 8;

fn gzip_of(text: []const u8, output: []u8) ![]u8 {
    test_gzip.init(Features.none());
    return output[0..try test_gzip.encode_all(text, output)];
}

fn zlib_of(text: []const u8, output: []u8) ![]u8 {
    test_zlib.init(Features.none());
    return output[0..try test_zlib.encode_all(text, output)];
}

/// Decodes `coded` in pieces of `piece_len` into `output`, as a body's runs arrive. Test-only.
fn decode_in_pieces(decoding: *Decoding, storage: Storage, coded: []const u8, piece_len: usize, output: []u8) !usize {
    var taken: usize = 0;
    var written: usize = 0;
    // Bounded: every pass takes or writes at least one octet.
    for (0..coded.len + output.len + 1) |_| {
        if (taken == coded.len) return written;
        const piece = coded[taken..@min(coded.len, taken + piece_len)];
        const progress = try decode(decoding, storage, piece, output[written..]);
        try testing.expect(progress.consumed + progress.written > 0);
        taken += progress.consumed;
        written += progress.written;
    }
    return error.TestUnexpectedResult;
}

test "RFC 9110 §8.4.1.3: a gzip body decodes in any pieces, and the decoder goes back" {
    const storage = test_pool.storage();
    storage.reset(Features.none());
    var coded_room: [test_room]u8 = undefined;
    const coded = try gzip_of(test_text, &coded_room);
    for ([_]usize{ 1, 7, coded.len }) |piece_len| {
        var decoding: Decoding = .{};
        try start(&decoding, storage, .gzip);
        var decoded: [test_room]u8 = undefined;
        const written = try decode_in_pieces(&decoding, storage, coded, piece_len, &decoded);
        try testing.expectEqualStrings(test_text, decoded[0..written]);
        try finish(&decoding, storage);
        try testing.expect(!decoding.active());
    }
    // Both slots are free again: two messages take one each, and a third finds none.
    var first: Decoding = .{};
    var second: Decoding = .{};
    var third: Decoding = .{};
    try start(&first, storage, .gzip);
    try start(&second, storage, .deflate);
    try testing.expectError(error.DecodersExhausted, start(&third, storage, .gzip));
    release(&first, storage);
    try start(&third, storage, .gzip);
}

test "RFC 1952 §2.2: a gzip body of two members decodes to both" {
    const storage = test_pool.storage();
    storage.reset(Features.none());
    var coded_room: [2 * test_room]u8 = undefined;
    const first = try gzip_of("first member, ", coded_room[0..test_room]);
    const second = try gzip_of("second member", coded_room[first.len..]);
    var decoding: Decoding = .{};
    try start(&decoding, storage, .gzip);
    var decoded: [test_room]u8 = undefined;
    const written = try decode_in_pieces(&decoding, storage, coded_room[0 .. first.len + second.len], 5, &decoded);
    try testing.expectEqualStrings("first member, second member", decoded[0..written]);
    try finish(&decoding, storage);
}

test "RFC 9110 §8.4.1.2: deflate is zlib, and octets after its stream are refused" {
    const storage = test_pool.storage();
    storage.reset(Features.none());
    var coded_room: [test_room]u8 = undefined;
    const coded = try zlib_of(test_text, &coded_room);
    var decoding: Decoding = .{};
    try start(&decoding, storage, .deflate);
    var decoded: [test_room]u8 = undefined;
    const written = try decode_in_pieces(&decoding, storage, coded, 3, &decoded);
    try testing.expectEqualStrings(test_text, decoded[0..written]);
    try testing.expectError(error.CodingTrailing, decode(&decoding, storage, "x", &decoded));
    release(&decoding, storage);
}

test "decision 91: a corrupt body, a refused feature and a stream cut short each have their verdict" {
    const storage = test_pool.storage();
    storage.reset(Features.none());
    var coded_room: [test_room]u8 = undefined;
    const coded = try gzip_of(test_text, &coded_room);
    var decoded: [test_room]u8 = undefined;
    var decoding: Decoding = .{};
    // RFC 1952 §2.3.1: a wrong CRC32 in the trailer.
    coded[coded.len - crc32_offset_from_end] +%= 1;
    try start(&decoding, storage, .gzip);
    try testing.expectError(error.CodingCorrupt, decode(&decoding, storage, coded, &decoded));
    release(&decoding, storage);
    // RFC 1950 §2.2: FDICT set, a preset dictionary, which stdx refuses. 0x78 0xbb has FCHECK valid.
    try start(&decoding, storage, .deflate);
    try testing.expectError(error.CodingFeatureRefused, decode(&decoding, storage, "\x78\xbb\x00\x00\x00\x01", &decoded));
    release(&decoding, storage);
    // A body that ends before the stream's checksum.
    coded[coded.len - crc32_offset_from_end] -%= 1;
    try start(&decoding, storage, .gzip);
    _ = try decode(&decoding, storage, coded[0 .. coded.len - 1], &decoded);
    try testing.expectError(error.CodingCorrupt, finish(&decoding, storage));
    try testing.expect(!decoding.active());
}
