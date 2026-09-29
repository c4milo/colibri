//! The modules colibri's package exports beside its own (decision 101): stdx's codecs, which a
//! dependent reaches with `dependency.module("gzip")`, so it codes request content, or anything
//! else, with the stdx the library pins.
const std = @import("std");

/// The stdx modules the package exports, by the names stdx gives them.
const codec_modules = [_][]const u8{ "codec", "gzip", "zlib", "zstd", "brotli" };

pub fn add(b: *std.Build, stdx: *std.Build.Dependency) void {
    for (codec_modules) |name| {
        b.modules.put(b.graph.arena, name, stdx.module(name)) catch @panic("OOM");
    }
}
