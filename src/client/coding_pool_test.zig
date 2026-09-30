//! The tests of the `zstd` and `br` pools (`coding_pool.zig`, decision 101 as amended): each fixture
//! decodes in any pieces, and what RFC 8878, RFC 9659 and RFC 7932 refuse fails its response.
//! Split out of `coding_pool.zig` for length.
const std = @import("std");
const coding_pool = @import("coding_pool.zig");
const support = @import("coding_test_support.zig");

const testing = std.testing;
const ZstdHeld = coding_pool.Held(coding_pool.Zstd);
const BrotliHeld = coding_pool.Held(coding_pool.Brotli);

/// Where the tests decode: the text, and an octet more, which stays unwritten. Test-only.
threadlocal var output: [support.plain.len + 1]u8 = undefined;
/// The pieces coded content arrives in: one octet, a few, and whole. Test-only.
const piece_lens = [_]usize{ 1, piece_len_few, std.math.maxInt(usize) };
/// A piece that ends inside the fixtures' headers and blocks, as a transport's reads do. Test-only.
const piece_len_few: usize = 7;

/// Decodes `coded` in pieces of `piece_len`, as a response's content arrives. Test-only.
fn decode_in_pieces(held: anytype, coded: []const u8, piece_len: usize) ![]const u8 {
    var taken: usize = 0;
    var written: usize = 0;
    // Bounded: every pass takes or writes at least one octet.
    for (0..coded.len + output.len + 1) |_| {
        if (taken == coded.len) return output[0..written];
        const piece = coded[taken..@min(coded.len, taken +| piece_len)];
        const progress = try held.decode(piece, output[written..]);
        try testing.expect(progress.consumed + progress.written > 0);
        taken += progress.consumed;
        written += progress.written;
    }
    return error.TestUnexpectedResult;
}

test "RFC 8878 §3.1: zstd content of one frame, of two, or after a skippable frame decodes in any pieces" {
    support.reset_pools();
    const storage = support.zstd_pool.storage();
    for ([_][]const u8{ support.plain_zst, support.two_frames_zst, support.skippable_zst }) |coded| {
        for (piece_lens) |piece_len| {
            var held: ZstdHeld = .{};
            try testing.expect(held.reserve(storage));
            held.begin();
            try testing.expectEqualStrings(support.plain, try decode_in_pieces(&held, coded, piece_len));
            try held.finish();
            try testing.expectEqual(1, storage.free_count());
        }
    }
}

test "RFC 7932 §9.1: br content whose window is 16 MiB, WBITS 24, decodes in any pieces" {
    support.reset_pools();
    const storage = support.br_pool.storage();
    for (piece_lens) |piece_len| {
        var held: BrotliHeld = .{};
        try testing.expect(held.reserve(storage));
        held.begin();
        try testing.expectEqualStrings(support.plain, try decode_in_pieces(&held, support.plain_br, piece_len));
        try held.finish();
        try testing.expectEqual(1, storage.free_count());
    }
}

test "RFC 9659 §3 and RFC 7932 §9.1: a window past the coding's limit fails, and the decoder goes back" {
    support.reset_pools();
    var zstd_held: ZstdHeld = .{};
    try testing.expect(zstd_held.reserve(support.zstd_pool.storage()));
    zstd_held.begin();
    try testing.expectError(error.CodingCorrupt, decode_in_pieces(&zstd_held, support.window_16mb_zst, piece_lens[2]));
    zstd_held.release();
    try testing.expectEqual(1, support.zstd_pool.storage().free_count());
    // RFC 7932 §9.1: "bit pattern 0010001 is invalid", and `brotli --large_window` writes it.
    var br_held: BrotliHeld = .{};
    try testing.expect(br_held.reserve(support.br_pool.storage()));
    br_held.begin();
    try testing.expectError(error.CodingCorrupt, decode_in_pieces(&br_held, support.large_window_br, piece_lens[2]));
    br_held.release();
    try testing.expectEqual(1, support.br_pool.storage().free_count());
}

test "RFC 7932 §9.2 and RFC 8878 §3.1: octets after a stream, or a stream cut short, are corrupt" {
    support.reset_pools();
    var room: [support.plain_zst.len + support.plain_br.len + 1]u8 = undefined;
    // A br stream ends with its last meta-block, so an octet after it is no coding's.
    @memcpy(room[0..support.plain_br.len], support.plain_br);
    room[support.plain_br.len] = 0;
    var br_held: BrotliHeld = .{};
    try testing.expect(br_held.reserve(support.br_pool.storage()));
    br_held.begin();
    try testing.expectError(error.CodingCorrupt, decode_in_pieces(&br_held, room[0 .. support.plain_br.len + 1], piece_lens[2]));
    br_held.release();
    // Octets after a zstd frame must start another, and a zero octet starts no magic number.
    @memcpy(room[0..support.plain_zst.len], support.plain_zst);
    room[support.plain_zst.len] = 0;
    var zstd_held: ZstdHeld = .{};
    try testing.expect(zstd_held.reserve(support.zstd_pool.storage()));
    zstd_held.begin();
    try testing.expectError(error.CodingCorrupt, decode_in_pieces(&zstd_held, room[0 .. support.plain_zst.len + 1], piece_lens[2]));
    zstd_held.release();
    // A frame without its last octet, its checksum's, never ends.
    try testing.expect(zstd_held.reserve(support.zstd_pool.storage()));
    zstd_held.begin();
    _ = try decode_in_pieces(&zstd_held, support.plain_zst[0 .. support.plain_zst.len - 1], piece_lens[2]);
    try testing.expectError(error.CodingCorrupt, zstd_held.finish());
    try testing.expectEqual(1, support.zstd_pool.storage().free_count());
}

test "decision 101 as amended: a pool with no decoder free reserves none, and one given back is taken again" {
    support.reset_pools();
    const storage = support.br_pool.storage();
    var first: BrotliHeld = .{};
    var second: BrotliHeld = .{};
    try testing.expect(first.reserve(storage));
    try testing.expectEqual(0, storage.free_count());
    try testing.expect(!second.reserve(storage));
    try testing.expect(!second.holds());
    first.release();
    try testing.expect(second.reserve(storage));
    second.release();
    try testing.expectEqual(1, storage.free_count());
}
