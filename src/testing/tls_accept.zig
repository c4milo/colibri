//! The root of `zig build tls-accept`: design §8 step 5's server-side TLS check, which runs one
//! handshake as the server, `tls.record.Server`, against a client that is not colibri's and then
//! moves one record each way. It is a root of its own because an executable has one `main`, and
//! the others belong to the h2 server, the h2 client and the client-side handshake check.
const std = @import("std");

pub const hooks = @import("tls/hooks.zig");
pub const check_file = @import("tls/check_file.zig");
pub const accept_check = @import("tls/accept_check.zig");

comptime {
    // The `tls` module links chapulin's TCP object (design §8 step 16b), which imports
    // `ch_assert_fail` and `ch_rand_bytes`, and `tls/hooks.zig` exports both. Zig analyses a file
    // only when something references it, and in a build with no tests nothing here does, so the
    // exports would be missing and the link would fail. This reference is what forces the analysis.
    _ = hooks;
}

pub const main = accept_check.main;

test {
    std.testing.refAllDecls(@This());
    _ = hooks;
    _ = check_file;
    _ = accept_check;
}
