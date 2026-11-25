//! The root of `zig build http-client`: the test-only client of docs/design.md §9, which is
//! `client/client_loop.zig` and the session it drives. It is a module of its own, `testing_client`,
//! because an executable has one `main` and `testing.zig` gives its to the server.
const std = @import("std");

pub const client_loop = @import("client/client_loop.zig");
pub const client_options = @import("client/client_options.zig");
pub const client_session = @import("client/client_session.zig");
pub const client_exchange = @import("client/client_exchange.zig");
pub const client_tls = @import("tls/client_tls.zig");
pub const pool_loop = @import("client/pool_loop.zig");
pub const pool_tcp = @import("client/pool_tcp.zig");

pub const main = client_loop.main;

test {
    std.testing.refAllDecls(@This());
    _ = client_loop;
    _ = client_options;
    _ = client_session;
    _ = client_exchange;
    _ = client_tls;
    _ = pool_loop;
    _ = pool_tcp;
}
