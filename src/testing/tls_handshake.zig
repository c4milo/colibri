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

pub const handshake_check = @import("tls/handshake_check.zig");

pub const main = handshake_check.main;

test {
    std.testing.refAllDecls(@This());
    _ = handshake_check;
}
