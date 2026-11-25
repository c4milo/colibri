//! The root of `zig build quic-loopback`: design §8 step 9e's check that a colibri QUIC client and
//! a colibri QUIC server complete a handshake and move a stream over `tls.quic`'s sessions (design
//! §8 step 16b). It is a root of its own because an executable has one `main`.
const std = @import("std");

pub const keylog = @import("quic/keylog.zig");
pub const quic_session = @import("quic/quic_session.zig");
pub const loopback_endpoint = @import("quic/loopback_endpoint.zig");
pub const loopback_check = @import("quic/loopback_check.zig");
pub const hq = @import("quic/hq/hq.zig");

comptime {
    // chapulin's QUIC object imports `ch_keylog`, which this file exports. Zig analyses a file
    // only when something references it, so this reference keeps the export in a build with no
    // tests.
    _ = keylog;
}

pub const main = loopback_check.main;

test {
    std.testing.refAllDecls(@This());
    _ = keylog;
    _ = quic_session;
    _ = loopback_endpoint;
    _ = loopback_check;
    _ = hq;
}
