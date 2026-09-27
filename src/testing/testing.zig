//! The test-only entry points of docs/design.md §9. Nothing here is packaged: the library never
//! imports this module, and it is the only place in the tree permitted to touch a socket
//! (invariant 2 is scoped to `src/` outside it).
//!
//! `session` is one connection of the server, with no socket in it, speaking h2 (`h2_session`) or
//! h11 (`h11_session`), and `server` is the socket around it: `zig build http-server` runs the
//! pair for h2spec and h2load (design §8 steps 4 and 15d).
const std = @import("std");

pub const hooks = @import("tls/hooks.zig");
pub const server_identity = @import("tls/server_identity.zig");
pub const constants = @import("constants.zig");

comptime {
    // The `tls` module links chapulin's TCP object (design §8 step 16b), which imports
    // `ch_assert_fail` and `ch_rand_bytes`, and `tls/hooks.zig` exports both. Zig analyses a file
    // only when something references it, and in a build with no tests nothing here does, so the
    // exports would be missing and the link would fail. This reference is what forces the analysis.
    _ = hooks;
}

pub const h2_session = @import("h2/h2_session.zig");
pub const h11_session = @import("h11/h11_session.zig");
pub const h11_client_session = @import("h11/h11_client_session.zig");
pub const h11_echo = @import("h11/h11_echo.zig");
pub const session = @import("session.zig");
pub const Session = session.Session;
pub const server = @import("server.zig");
pub const server_options = @import("server_options.zig");
pub const server_tls = @import("tls/server_tls.zig");
pub const tls_records = @import("tls/records.zig");
pub const client_exchange = @import("client/client_exchange.zig");
pub const h2_client_session = @import("h2/h2_client_session.zig");

/// The entry point of `zig build http-server`, which is this module's executable form.
pub const main = server.main;

test {
    std.testing.refAllDecls(@This());
    _ = hooks;
    _ = server_identity;
    _ = constants;
    _ = h2_session;
    _ = h11_session;
    _ = h11_client_session;
    _ = h11_echo;
    _ = session;
    _ = server;
    _ = server_options;
    _ = server_tls;
    _ = tls_records;
    _ = client_exchange;
    _ = h2_client_session;
}
