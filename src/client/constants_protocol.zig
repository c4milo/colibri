//! The values the RFCs fix for client, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.

/// The largest window a `br` decoder takes, as the bits RFC 7932 §9.1 names WBITS: 24, a window of
/// 16 MiB less 16 octets, the largest §9.1 allows, as the owner ruled on 2026-09-30 (decision 101
/// as amended). A `br` decoder holds this much.
pub const brotli_window_bits_max: u5 = 24;
