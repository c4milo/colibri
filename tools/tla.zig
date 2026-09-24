//! colibri's TLA+ models (decision 67), checked by pepegrillo's TLC runner. Every model is a
//! directory of spec/tla/, and the first line of each configuration says whether TLC must find its
//! properties holding or violated.
//!
//! Run: `zig build tla`, or `zig build tla -- spec/tla/<model>/<configuration>.cfg` for one.

const std = @import("std");
const pepegrillo = @import("pepegrillo");

pub fn main(init: std.process.Init) !void {
    return pepegrillo.tla.main(init, .{
        // tlaplus's last release not marked prerelease. The release publishes no digest for this
        // asset, so the SHA-256 is the one computed on 2026-09-23 (decision 67).
        .tlc_release = "v1.7.4",
        .tlc_sha256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88",
    });
}
