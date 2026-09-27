//! colibri's TLS (decisions 94 and 97, design §8 step 16): chapulin's sessions behind colibri's two
//! vtables. A program converts its values (`values.zig`) once for each object, starts a session per
//! connection, and hands the session's provider to the connection. The HTTP modules import none of
//! this: a cleartext program never links chapulin.
//!
//! Record mode serves h2 and h11 over the TCP object (`record/`). chapulin holds every key, and
//! colibri passes it pointers to the caller's keys and never reads one (non-negotiable 2). The
//! program defines chapulin's two hooks, `ch_rand_bytes` and `ch_assert_fail` (decision 94).
const std = @import("std");

pub const constants = @import("constants.zig");
pub const values = @import("values.zig");
pub const record = @import("record/record.zig");

pub const Anchor = values.Anchor;
pub const Pin = values.Pin;
pub const Trust = values.Trust;
pub const Client = values.Client;
pub const Server = values.Server;
pub const Ticket = values.Ticket;
pub const Resumption = values.Resumption;
pub const EcdsaP256Identity = values.EcdsaP256Identity;
pub const RsaPssIdentity = values.RsaPssIdentity;

test {
    std.testing.refAllDecls(@This());
    // The hooks a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
