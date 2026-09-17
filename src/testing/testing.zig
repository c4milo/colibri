//! The test-only entry points of docs/design.md §9. Nothing here is packaged: the library never
//! imports this module, and it is the only place in the tree permitted to touch a socket
//! (invariant 2 is scoped to `src/` outside it).
//!
//! `h2_session` is one connection of the cleartext h2 server, with no socket in it, and
//! `h2_server` is the socket around it: `zig build h2-server` runs the pair for h2spec and
//! h2load (design §8 step 4).
const std = @import("std");

pub const constants = @import("constants.zig");
pub const h2_session = @import("h2_session.zig");
pub const Session = h2_session.Session;
pub const h2_server = @import("h2_server.zig");

/// The entry point of `zig build h2-server`, which is this module's executable form.
pub const main = h2_server.main;

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = h2_session;
    _ = h2_server;
}
