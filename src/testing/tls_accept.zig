//! The root of `zig build tls-accept`: design §8 step 5's server-side TLS check, which runs one
//! handshake as the server against a client that is not colibri's and then moves one record each
//! way. It is a root of its own because an executable has one `main`, and the others belong to
//! the h2 server, the h2 client and the client-side handshake check.
//!
//! It links the `ROLE=server` chapulin object, which is why it cannot share the client check's
//! root: one binary carries one role (decision 10).
const std = @import("std");

pub const chapulin = @import("tls/chapulin.zig");
pub const chapulin_record = @import("tls/chapulin_record.zig");
pub const chapulin_server = @import("tls/chapulin_server.zig");
pub const check_file = @import("tls/check_file.zig");
pub const accept_check = @import("tls/accept_check.zig");

comptime {
    // The chapulin object is linked whenever the build was given a checkout, and it imports
    // `ch_assert_fail`, which `tls/chapulin.zig` exports. Zig analyses a file only when something
    // references it, and in a build with no tests nothing here does, so the export would be
    // missing and the link would fail. This reference is what forces the analysis.
    _ = chapulin;
}

pub const main = accept_check.main;

test {
    std.testing.refAllDecls(@This());
    _ = chapulin;
    _ = chapulin_record;
    _ = chapulin_server;
    _ = check_file;
    _ = accept_check;
}
