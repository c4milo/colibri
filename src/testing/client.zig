//! The root of `zig build http-client`: the test-only client of docs/design.md §9, which is
//! `client/client_loop.zig` and the session it drives. It is a module of its own, `testing_client`,
//! because an executable has one `main` and `testing.zig` gives its to the server.
const std = @import("std");

pub const hooks = @import("tls/hooks.zig");
pub const client_loop = @import("client/client_loop.zig");
pub const client_options = @import("client/client_options.zig");
pub const client_session = @import("client/client_session.zig");
pub const client_exchange = @import("client/client_exchange.zig");
pub const client_tls = @import("tls/client_tls.zig");

comptime {
    // The `tls` module links chapulin's TCP object (design §8 step 16b), which imports
    // `ch_assert_fail`, and `tls/hooks.zig` exports it. Zig analyses a file only when something
    // references it, and in a build with no tests nothing here does, so the export would be missing
    // and the link would fail. This reference is what forces the analysis.
    _ = hooks;
}

pub const main = client_loop.main;

test {
    std.testing.refAllDecls(@This());
    _ = hooks;
    _ = client_loop;
    _ = client_options;
    _ = client_session;
    _ = client_exchange;
    _ = client_tls;
}
