//! The test-only entry points of docs/design.md §9. Nothing here is packaged: the library never
//! imports this module, and it is the only place in the tree permitted to touch a socket
//! (invariant 2 is scoped to `src/` outside it).
//!
//! `server_session` is one worker's connections in the server, with no socket in them, over one
//! endpoint of colibri's `server` module, which speaks h2 or h11 (design §8 steps 17a and 21b.6),
//! and `server` is the socket side: `zig build http-server` runs the pair for h2spec and h2load
//! (design §8 steps 4 and 15d).
const std = @import("std");

pub const memset = @import("memset.zig");
pub const server_identity = @import("tls/server_identity.zig");
pub const constants = @import("constants.zig");

comptime {
    // Zig analyses a file only when something references it. This reference keeps `memset.zig`'s
    // export in the program `bench/run.sh` measures.
    _ = memset;
}

pub const alpn = @import("alpn.zig");
pub const h11_echo = @import("h11/h11_echo.zig");
pub const server_session = @import("server/server_session.zig");
pub const Session = server_session.WorkerSession;
pub const server = @import("server.zig");
pub const server_options = @import("server/server_options.zig");

/// The entry point of `zig build http-server`, which is this module's executable form.
pub const main = server.main;

test {
    std.testing.refAllDecls(@This());
    _ = memset;
    _ = server_identity;
    _ = constants;
    _ = alpn;
    _ = h11_echo;
    _ = server_session;
    _ = server;
    _ = server_options;
}
