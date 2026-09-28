//! The test-only entry points of docs/design.md §9. Nothing here is packaged: the library never
//! imports this module, and it is the only place in the tree permitted to touch a socket
//! (invariant 2 is scoped to `src/` outside it).
//!
//! `server_session` is one connection of the server, with no socket in it, over colibri's `server`
//! module, which speaks h2 or h11 (design §8 step 17a), and `server` is the socket around it: `zig
//! build http-server` runs the pair for h2spec and h2load (design §8 steps 4 and 15d).
const std = @import("std");

pub const hooks = @import("tls/hooks.zig");
pub const server_identity = @import("tls/server_identity.zig");
pub const constants = @import("constants.zig");

comptime {
    // The `tls` module links chapulin's TCP object (design §8 step 16b), which imports
    // `ch_assert_fail`, and `tls/hooks.zig` exports it. Zig analyses a file only when something
    // references it, and in a build with no tests nothing here does, so the export would be missing
    // and the link would fail. This reference is what forces the analysis.
    _ = hooks;
}

pub const alpn = @import("alpn.zig");
pub const h11_echo = @import("h11/h11_echo.zig");
pub const server_session = @import("server_session.zig");
pub const Session = server_session.Session;
pub const server = @import("server.zig");
pub const server_options = @import("server_options.zig");

/// The entry point of `zig build http-server`, which is this module's executable form.
pub const main = server.main;

test {
    std.testing.refAllDecls(@This());
    _ = hooks;
    _ = server_identity;
    _ = constants;
    _ = alpn;
    _ = h11_echo;
    _ = server_session;
    _ = server;
    _ = server_options;
}
