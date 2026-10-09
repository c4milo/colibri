//! colibri's TLS (decisions 94 and 97, design §8 step 16): chapulin's sessions behind colibri's two
//! vtables. A program converts its values (`values.zig`) once for each object, starts a session per
//! connection, and hands the session's provider to the connection. The HTTP modules import none of
//! this: a cleartext program never links chapulin.
//!
//! Record mode serves h2 and h11 over the TCP object (`record/`), and QUIC mode serves h3 over the
//! QUIC object (`quic/`), filling `tls_provider.QuicProvider` and `crypto.Suite`. chapulin holds
//! every key, and colibri passes it pointers to the caller's keys and never reads one
//! (non-negotiable 2). Each session draws from the `Random` its caller passes to `start`, and the
//! program defines chapulin's one remaining hook, `ch_assert_fail` (decision 94 as amended).
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const values = @import("values.zig");
    pub const record = @import("record/record.zig");
    pub const quic = @import("quic/quic.zig");
};

pub const Random = files.values.Random;
pub const Cpu = files.values.Cpu;
pub const Timing = files.values.Timing;
pub const Anchor = files.values.Anchor;
pub const Pin = files.values.Pin;
pub const Trust = files.values.Trust;
pub const Client = files.values.Client;
pub const Server = files.values.Server;
pub const Ticket = files.values.Ticket;
pub const Resumption = files.values.Resumption;
pub const EcdsaP256Identity = files.values.EcdsaP256Identity;
pub const RsaPssIdentity = files.values.RsaPssIdentity;

pub const record = struct {
    pub const Client = files.record.Client;
    pub const ClientConfig = files.record.ClientConfig;
    pub const Server = files.record.Server;
    pub const ServerConfig = files.record.ServerConfig;
    pub const alert_record_len = files.record.alert_record_len;
};

pub const quic = struct {
    pub const Client = files.quic.Client;
    pub const ClientConfig = files.quic.ClientConfig;
    pub const Error = files.quic.Error;
    pub const Retry = files.quic.Retry;
    pub const Server = files.quic.Server;
    pub const ServerConfig = files.quic.ServerConfig;
    pub const State = files.quic.State;
    pub const token_key_len = files.quic.token_key_len;
};

test "decision 115: the root exports the names code outside the module uses" {
    try @import("crypto").core.public_names.expect(@This(), &.{
        "constants",      "Random", "Cpu",        "Timing",
        "Anchor",         "Pin",    "Trust",      "Client",
        "Server",         "Ticket", "Resumption", "EcdsaP256Identity",
        "RsaPssIdentity", "record", "quic",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = @import("crypto").core.public_names.reference(@This(), &.{});
    // The hooks a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
