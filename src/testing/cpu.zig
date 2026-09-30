//! The answer about the CPU that colibri's TLS values require (decision 97 as amended on
//! 2026-09-29): whether it has the AES instructions and the carry-less multiply. A program asks the
//! CPU it runs on, once at start, through stdx's `platform` module, and passes the answer to every
//! configuration (https://github.com/c4milo/stdx/issues/15). Until that module exists, these
//! programs answer for the build target: `zig build` builds each on the machine that runs it, the
//! QUIC Interop Runner's image included.
const std = @import("std");
const builtin = @import("builtin");
const tls = @import("tls");

/// aes and pclmul on x86-64, and aes on arm64, whose AES extension holds the 64-bit PMULL.
pub fn aes_instructions() tls.AesInstructions {
    const present = switch (builtin.cpu.arch) {
        .x86_64 => std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .aes, .pclmul }),
        .aarch64 => std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes),
        else => false,
    };
    return if (present) .present else .absent;
}
