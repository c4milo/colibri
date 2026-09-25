//! Limits and format constants golden owns (docs/design.md §7). Never written inline (CLAUDE.md
//! non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;

/// The version of the manifest format, written on its first line. colibri's own formats are
/// versioned from the first commit (CLAUDE.md non-negotiable 6); a change to what a manifest line
/// holds is a new version, never a silent edit.
pub const manifest_version: u32 = 1;

/// The file every format directory's manifest is written to.
pub const manifest_file_name = "manifest.txt";

/// The marker file that makes `zig build golden` refuse to rewrite a format directory
/// (decision 26).
pub const frozen_marker_name = "FROZEN";

/// The extension every corpus case file carries.
pub const case_file_extension = ".bin";

/// Most octets one corpus case holds. A whole HTTP/1.1 message with a chunked body and a trailer
/// section needs a few hundred, which the owner raised it to on 2026-09-25 (design §8 step 15a).
pub const case_len_max: u32 = 256;

/// Most octets a case decodes to: the decoder's output buffer for the Huffman and string-literal
/// formats. Twice `case_len_max`, the ratio it had when `case_len_max` was 64.
pub const decoded_len_max: u32 = 512;

/// Most cases one format holds.
pub const cases_per_format_max: u32 = 32;

/// Most octets one format's manifest holds. A manifest line writes a case's octets in hex, so this
/// grew fourfold with `case_len_max`.
pub const manifest_len_max: u32 = 32768;

/// Most corpus mutations.
pub const mutations_max: u32 = 64;

comptime {
    // Every case in a format fits the manifest, at a generous line length per case.
    assert(manifest_len_max >= cases_per_format_max * 256);
    assert(decoded_len_max >= case_len_max);
}

test "a manifest line has room for the longest case's parameters" {
    try std.testing.expect(case_len_max * 2 < manifest_len_max / cases_per_format_max);
}
