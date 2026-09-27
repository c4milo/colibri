//! The root of `zig build tls-handshake`: colibri's TLS client, `tls.record.Client`, against a real
//! server, which is the first half of design §8 step 5's check.
//!
//! It is a module of its own because an executable has one `main`, and the other two roots give
//! theirs to the h2 server and the h2 client.
//!
//! `tools/tls_handshake.sh` starts the peer, waits for it, and runs this. Nothing here is part of
//! `zig build test`: it needs a Go toolchain and a listening socket, which CLAUDE.md keeps out of
//! the unit tests.
const std = @import("std");

pub const hooks = @import("tls/hooks.zig");
pub const handshake_check = @import("tls/handshake_check.zig");

comptime {
    // The `tls` module links chapulin's TCP object (design §8 step 16b), which imports
    // `ch_assert_fail`, and `tls/hooks.zig` exports it. Zig analyses a file only when something
    // references it, and in a build with no tests nothing here does, so the export would be missing
    // and the link would fail. This reference is what forces the analysis.
    _ = hooks;
}

pub const main = handshake_check.main;

test {
    std.testing.refAllDecls(@This());
    _ = hooks;
    _ = handshake_check;
}
