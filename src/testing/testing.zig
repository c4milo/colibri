//! The test-only entry points of docs/design.md §9. Nothing here is packaged: the library never
//! imports this module, and it is the only place in the tree permitted to touch a socket
//! (invariant 2 is scoped to `src/` outside it).
//!
//! `h2_session` is one connection of the cleartext h2 server, with no socket in it, and
//! `h2_server` is the socket around it: `zig build h2-server` runs the pair for h2spec and
//! h2load (design §8 step 4).
const std = @import("std");

pub const chapulin = @import("tls/chapulin.zig");
// The server adapter lives here and not in the client roots: `ch_srv_record_init` and
// `ch_srv_check` are exported by a `ROLE=server` object alone.
pub const chapulin_server = @import("tls/chapulin_server.zig");
pub const constants = @import("constants.zig");

comptime {
    // The chapulin object is linked whenever the build was given a checkout, and it imports
    // `ch_assert_fail`, which `tls/chapulin.zig` exports. Zig analyses a file only when something
    // references it, and in a build with no tests nothing here does, so the export would be
    // missing and the link would fail. This reference is what forces the analysis.
    _ = chapulin;
}

pub const h2_session = @import("h2/h2_session.zig");
pub const Session = h2_session.Session;
pub const h2_server = @import("h2/h2_server.zig");
pub const h2_tls = @import("h2/h2_tls.zig");
pub const h2_tls_records = @import("h2/h2_tls_records.zig");
pub const h2_client_exchange = @import("h2/h2_client_exchange.zig");
pub const h2_client_session = @import("h2/h2_client_session.zig");

/// The entry point of `zig build h2-server`, which is this module's executable form.
pub const main = h2_server.main;

test {
    std.testing.refAllDecls(@This());
    _ = chapulin;
    _ = chapulin_server;
    _ = constants;
    _ = h2_session;
    _ = h2_server;
    _ = h2_tls;
    _ = h2_tls_records;
    _ = h2_client_exchange;
    _ = h2_client_session;
}
