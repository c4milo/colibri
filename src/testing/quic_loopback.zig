//! The root of `zig build quic-loopback`: design §8 step 9e's check that a colibri QUIC client and
//! a colibri QUIC server complete a handshake and move a stream over chapulin. It is a root of its
//! own because an executable has one `main`, and because it links chapulin's
//! `TRANSPORT=quic-nonblocking` object, which the other roots do not (decision 10).
const std = @import("std");

pub const chapulin_quic_c = @import("quic/chapulin_quic_c.zig");
pub const chapulin_quic = @import("quic/chapulin_quic.zig");
pub const chapulin_quic_suite = @import("quic/chapulin_quic_suite.zig");
pub const loopback_endpoint = @import("quic/loopback_endpoint.zig");
pub const loopback_check = @import("quic/loopback_check.zig");
pub const hq = @import("quic/hq/hq.zig");

comptime {
    // The chapulin object imports `ch_assert_fail` and `ch_keylog`, which these two files export.
    // Zig analyses a file only when something references it, so these references are what keep
    // the exports in a build with no tests.
    _ = chapulin_quic_c;
    _ = chapulin_quic;
}

pub const main = loopback_check.main;

test {
    std.testing.refAllDecls(@This());
    _ = chapulin_quic_c;
    _ = chapulin_quic;
    _ = chapulin_quic_suite;
    _ = loopback_endpoint;
    _ = loopback_check;
    _ = hq;
}
