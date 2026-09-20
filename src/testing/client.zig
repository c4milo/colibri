//! The root of `zig build h2-client`: the test-only h2 client of docs/design.md §9, which is
//! `h2/h2_client.zig` and the session it drives. It is a module of its own, `testing_client`,
//! because an executable has one `main` and `testing.zig` gives its to the server.
const std = @import("std");

pub const chapulin = @import("tls/chapulin.zig");
pub const chapulin_client = @import("tls/chapulin_client.zig");
pub const h2_client = @import("h2/h2_client.zig");

comptime {
    // The chapulin object is linked whenever the build was given a checkout, and it imports
    // `ch_assert_fail`, which `tls/chapulin.zig` exports. Zig analyses a file only when something
    // references it, and in a build with no tests nothing here does, so the export would be
    // missing and the link would fail. This reference is what forces the analysis.
    _ = chapulin;
}

pub const main = h2_client.main;

test {
    std.testing.refAllDecls(@This());
    _ = chapulin;
    _ = chapulin_client;
    _ = h2_client;
}
