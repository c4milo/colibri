//! What the client's `zstd` and `br` tests share (decision 101 as amended, design §8 step 17h): a
//! pool for each coding, of one decoder, placed outside any stack frame, and the fixtures in
//! `coding_fixtures/`, which the reference programs wrote (its README.md says how).
const coding_pool = @import("coding_pool.zig");

/// One decoder in each pool: 8 MB for `zstd` and 16 MiB for `br`. Test-only.
const decoders_each: usize = 1;
pub const ZstdPool = coding_pool.ZstdDecoderPool(decoders_each);
pub const BrotliPool = coding_pool.BrotliDecoderPool(decoders_each);
pub var zstd_pool: ZstdPool align(@alignOf(ZstdPool)) = undefined;
pub var br_pool: BrotliPool align(@alignOf(BrotliPool)) = undefined;

/// The content every fixture codes, and its codings.
pub const plain = @embedFile("coding_fixtures/plain.txt");
pub const plain_zst = @embedFile("coding_fixtures/plain.zst");
pub const two_frames_zst = @embedFile("coding_fixtures/two_frames.zst");
pub const skippable_zst = @embedFile("coding_fixtures/skippable.zst");
pub const window_16mb_zst = @embedFile("coding_fixtures/window_16mb.zst");
pub const plain_br = @embedFile("coding_fixtures/plain.br");
pub const large_window_br = @embedFile("coding_fixtures/large_window.br");

/// Both pools with every decoder free.
pub fn reset_pools() void {
    zstd_pool.storage().reset(.none());
    br_pool.storage().reset(.none());
}
