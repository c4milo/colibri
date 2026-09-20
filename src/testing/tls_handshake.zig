//! The root of `zig build tls-handshake`: colibri's chapulin-backed TLS client against a real
//! server, which is the first half of design §8 step 5's check.
//!
//! It is a module of its own because an executable has one `main`, and the other two roots give
//! theirs to the h2 server and the h2 client.
//!
//! `tools/tls_handshake.sh` starts the peer, waits for it, and runs this. Nothing here is part of
//! `zig build test`: it needs a Go toolchain and a listening socket, which CLAUDE.md keeps out of
//! the unit tests.
const std = @import("std");

pub const chapulin = @import("tls/chapulin.zig");
pub const chapulin_client = @import("tls/chapulin_client.zig");
pub const handshake_check = @import("tls/handshake_check.zig");

comptime {
    // The chapulin object is linked whenever the build was given a checkout, and it imports
    // `ch_assert_fail`, which `tls/chapulin.zig` exports. Zig analyses a file only when something
    // references it, and in a build with no tests nothing here does, so the export would be
    // missing and the link would fail. This reference is what forces the analysis.
    _ = chapulin;
}

pub const main = handshake_check.main;

test {
    std.testing.refAllDecls(@This());
    _ = chapulin;
    _ = chapulin_client;
    _ = handshake_check;
}
