//! The root of `zig build h2-client`: the test-only h2 client of docs/design.md §9, which is
//! `h2/h2_client.zig` and the session it drives. It is a module of its own, `testing_client`,
//! because an executable has one `main` and `testing.zig` gives its to the server.
const std = @import("std");

pub const h2_client = @import("h2/h2_client.zig");

pub const main = h2_client.main;

test {
    std.testing.refAllDecls(@This());
    _ = h2_client;
}
