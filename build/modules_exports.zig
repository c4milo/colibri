//! The modules colibri's package exports beside its own: stdx's codecs (decision 101), which a
//! dependent reaches with `dependency.module("gzip")`, so it codes request content, or anything
//! else, with the stdx the library pins; and stdx's `platform`, which a program calls once, at start,
//! to answer every TLS configuration's `aes_instructions` (decision 97 as amended on 2026-09-30).
const std = @import("std");

/// The stdx modules the package exports, by the names stdx gives them.
const stdx_modules = [_][]const u8{ "codec", "gzip", "zlib", "zstd", "brotli", "platform" };

pub fn add(b: *std.Build, stdx: *std.Build.Dependency) void {
    for (stdx_modules) |name| {
        b.modules.put(b.graph.arena, name, stdx.module(name)) catch @panic("OOM");
    }
}
