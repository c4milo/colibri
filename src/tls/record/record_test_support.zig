//! What the record-mode tests share (`record_test.zig`, `record_keylog_test.zig`): a client and a
//! server of one TCP object, run against each other in memory over the test identity of
//! `src/testing/testdata/`.
const std = @import("std");
const builtin = @import("builtin");
const stdx = @import("stdx");
const platform = stdx.platform;
const tls_provider = @import("tls_provider");
const chapulin = @import("stdx").crypto.tls;
const testdata = @import("testdata");
const record = @import("record.zig");
const values = @import("../values.zig");
const constants = @import("../constants.zig");
const random_support = @import("../random_test_support.zig");

/// The program's one `stdx.crypto.init(features, random)`, which `values.Client.crypto` holds.
const Context = stdx.crypto.Context;

pub const leaf = testdata.leaf;
pub const root = testdata.root;
pub const root_name = testdata.root_name;
pub const root_spki = testdata.root_spki;
pub const private_key: *const [constants.protocol.p256_private_key_len]u8 = testdata.private_key;
pub const public_key: *const [constants.protocol.p256_public_key_len]u8 = testdata.public_key;

/// The test identity's key, as `tls.pem.key` fills it from `identity.key.pem` (decision 147).
pub const key: values.Key = p256_key: {
    var filled: values.Key = .{ .scheme = .ecdsa_secp256r1_sha256 };
    @memcpy(filled.private_key[0..private_key.len], private_key);
    @memcpy(filled.public_key[0..public_key.len], public_key);
    break :p256_key filled;
};

/// The instant the tests judge the chain at. Any instant inside the identity's validity works,
/// from `testdata.not_before_seconds` to `testdata.not_after_seconds`.
pub const now_seconds: u64 = testdata.now_seconds;
/// The CPU features the tests describe: the build target's, since a test runs where it was built
/// (decision 175). No test's result depends on its timing.
pub const cpu_features: platform.CpuFeatures = .target();
/// The build target's features without the AES instructions and the carry-less multiply, under
/// which no session runs AES-GCM.
pub const cpu_features_without_aes: platform.CpuFeatures = without_aes(cpu_features);
/// The context the tests' configurations hold: the build target's features and the stream the tests
/// share.
pub const crypto: Context = context_of(cpu_features);

/// A context of `described` and the stream the tests share, as a program makes one at start.
pub fn context_of(described: platform.CpuFeatures) Context {
    return stdx.crypto.init(described, random_support.stream.random());
}

fn without_aes(described: platform.CpuFeatures) platform.CpuFeatures {
    var cleared = described;
    cleared.aes = false;
    cleared.pclmul = false;
    cleared.pmull = false;
    return cleared;
}

/// Features that hold one SHA instruction each, whatever the build target has, and features of an
/// Arm Neoverse N2, whose MIDR_EL1 stdx reads (decision 175). The tests convert them and check that
/// the configurations keep them whole, and run no session under them.
pub const features_with_sha = [_]platform.CpuFeatures{
    .{ .sha256 = true },
    .{ .sha512 = true },
    .{ .sha3 = true },
    .{ .aes = true, .pmull = true, .sha3 = true, .dit = true, .midr = .{ .implementer = arm_implementer, .variant = 0, .architecture = midr_architecture, .part = neoverse_n2_part, .revision = 0 } },
};
/// MIDR_EL1's fields of an Arm Neoverse N2: Arm's implementer code, the architecture field that
/// names the ID registers, and the N2's part number (Arm's technical reference manual of the N2).
const arm_implementer = 0x41;
const midr_architecture = 0xf;
const neoverse_n2_part = 0xd49;

/// Sets PSTATE.DIT on the test's thread where the core has FEAT_DIT, as a program does on each
/// thread that runs TLS (decision 175). stdx then states the thread's timing to chapulin on arm64,
/// and a session runs the AES instructions where the features hold them. Elsewhere it does
/// nothing.
pub fn set_timing() void {
    _ = platform.set_data_independent_timing(platform.CpuFeatures.detect(), true);
}

/// Whether stdx's description of the CPU claims the AES instructions for a session under
/// `context`, by stdx's rule (its decision 87 as amended): the timing stated, on every x86-64 core
/// and on an arm64 thread whose PSTATE.DIT is set, and the features holding AES and the carry-less
/// multiply of the architecture. A test reads it to know the suite a handshake runs.
pub fn aes_claimed(context: Context) bool {
    set_timing();
    const held = context.features;
    return switch (builtin.cpu.arch) {
        .x86_64 => held.aes and held.pclmul,
        .aarch64 => held.dit and platform.data_independent_timing(held) and held.aes and held.pmull,
        else => false,
    };
}
/// The first and the last instant the identity is valid at, which chapulin counts inside.
pub const not_before_seconds = testdata.not_before_seconds;
pub const not_after_seconds = testdata.not_after_seconds;
/// Milliseconds in a second, for a ticket's age.
pub const ms_per_second: u64 = 1000;

pub const cookie_key: [constants.protocol.server_key_len]u8 = @splat(cookie_key_octet);
pub const ticket_key: [constants.protocol.server_key_len]u8 = @splat(ticket_key_octet);
/// The byte each test key repeats, which only has to differ from the other key's.
const cookie_key_octet: u8 = 0x07;
const ticket_key_octet: u8 = 0x09;
pub const chain = [_][]const u8{ leaf, root };
/// The test identity as a server holds it: the chain and its key.
pub const identities = [_]values.Identity{.{ .chain = &chain, .key = &key }};
pub const anchors = [_]values.Anchor{.{ .subject = root_name, .spki = root_spki }};
pub const protocols = [_][]const u8{ "h2", "http/1.1" };

/// The configurations, sessions and wires the tests use, placed outside any stack frame.
pub var client_config: record.ClientConfig align(@alignOf(record.ClientConfig)) = undefined;
pub var server_config: record.ServerConfig align(@alignOf(record.ServerConfig)) = undefined;
pub var client: record.Client align(@alignOf(record.Client)) = undefined;
pub var server: record.Server align(@alignOf(record.Server)) = undefined;
pub var to_server: Wire align(@alignOf(Wire)) = .{};
pub var to_client: Wire align(@alignOf(Wire)) = .{};
pub var scratch: [wire_len]u8 = undefined;

/// Bytes one direction holds in flight: a server's whole flight and the records after it.
pub const wire_len: usize = 65_536;
/// Calls each side makes before a handshake in memory must have completed.
const handshake_rounds_max = 8;

/// One direction's bytes, written at the back and consumed from the front.
pub const Wire = struct {
    octets: [wire_len]u8 = undefined,
    len: usize = 0,

    pub fn held(wire: *Wire) []u8 {
        return wire.octets[0..wire.len];
    }

    pub fn free(wire: *Wire) []u8 {
        return wire.octets[wire.len..];
    }

    pub fn take(wire: *Wire, consumed: usize) void {
        @memmove(wire.octets[0 .. wire.len - consumed], wire.octets[consumed..wire.len]);
        wire.len -= consumed;
    }
};

/// Whether the linked object holds AES-GCM beside ChaCha20 (decision 97), and whether it takes the
/// caller's description of its CPU, as chapulin's host object does (its decision 89, decision 97 as
/// amended for chapulin 0.2.0).
pub const aes_gcm = @hasField(chapulin.c.ch_srv_cfg, "cipher_suites");
pub const takes_cpu = @hasField(chapulin.c.ch_cfg, "cpu");

/// Whether a session whose configuration holds `context` holds AES-GCM: an object with AES-GCM,
/// where stdx's description claims the AES instructions when the object takes a description.
pub fn holds_aes_gcm(context: Context) bool {
    return aes_gcm and (!takes_cpu or aes_claimed(context));
}

/// The features a test may run a session under. Features with the AES instructions need the
/// instructions, which the build target has or does not, so a target without them runs the
/// features without them alone.
pub const feature_sets: []const platform.CpuFeatures = if (takes_cpu and cpu_features.aes) &.{ cpu_features, cpu_features_without_aes } else &.{cpu_features_without_aes};

/// The suites a session under the tests' context holds: the three colibri admits with AES-GCM, and
/// ChaCha20 alone without it.
pub fn suites_held() []const u16 {
    return if (holds_aes_gcm(crypto)) &tls_provider.constants.policy.cipher_suites_admitted else &.{chacha};
}
pub const chacha = tls_provider.constants.protocol.cipher_suite_chacha20_poly1305_sha256;

/// A server order naming `suite` alone, or none in an object that holds one suite and no order.
pub fn order_of(suite: *const [1]u16) []const u16 {
    return if (aes_gcm) suite else &.{};
}

/// The suite chapulin's own order runs when neither side names one: AES-256-GCM first when both
/// sessions hold AES-GCM (chapulin's decision 80), and ChaCha20 when either holds it alone.
pub fn default_suite_of(client_crypto: Context, server_crypto: Context) u16 {
    if (holds_aes_gcm(client_crypto) and holds_aes_gcm(server_crypto)) return tls_provider.constants.protocol.cipher_suite_aes_256_gcm_sha384;
    return chacha;
}

/// The suite chapulin's own order runs under the tests' context on both sides.
pub fn default_suite() u16 {
    return default_suite_of(crypto, crypto);
}

/// `web_pki` with a client order naming `suite` alone, or none in an object with no order.
pub fn offering(suite: *const [1]u16) values.Client {
    var offered = web_pki;
    offered.cipher_suites = order_of(suite);
    return offered;
}

/// What the tests vary on the server.
pub const ServerChoice = struct {
    tickets: bool = false,
    /// The key the server seals tickets under, when `tickets` is set.
    key: *const [constants.protocol.server_key_len]u8 = &ticket_key,
    /// The key the server held before `key` (https://github.com/c4milo/chapulin/issues/220).
    previous: ?*const [constants.protocol.server_key_len]u8 = null,
    /// The suites the server selects from, in its order; empty for chapulin's.
    suites: []const u16 = &.{},
    /// The server's context.
    crypto: Context = crypto,
};

pub fn configure(client_values: values.Client, choice: ServerChoice) !void {
    set_timing();
    try client_config.init(client_values);
    try server_config.init(.{
        .identities = &identities,
        .cookie_key = &cookie_key,
        .ticket_key = if (choice.tickets) choice.key else null,
        .ticket_key_previous = if (choice.tickets) choice.previous else null,
        .alpn = &protocols,
        .crypto = choice.crypto,
        .cipher_suites = choice.suites,
    });
}

/// `web_pki` under the context `held`, whose source its sessions draw from (decision 175).
pub fn web_pki_under(held: Context) values.Client {
    var offered = web_pki;
    offered.crypto = held;
    return offered;
}

pub const web_pki: values.Client = .{
    .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "localhost" } },
    .alpn = &protocols,
    .crypto = crypto,
};

/// Starts both sides and runs the handshake until both complete, leaving in `to_client` what the
/// server wrote after it, such as its ticket.
pub fn handshake_both(resumption: ?values.Resumption) !void {
    return handshake_at(now_seconds, resumption);
}

/// As `handshake_both`, with both sides' clocks at `seconds`.
pub fn handshake_at(seconds: u64, resumption: ?values.Resumption) !void {
    to_server = .{};
    to_client = .{};
    try client.start(&client_config, seconds, resumption);
    try server.start(&server_config, seconds);
    for (0..handshake_rounds_max) |_| {
        if (!client.state.completed) {
            const progress = try client.handshake(to_client.held(), to_server.free());
            to_client.take(progress.consumed);
            to_server.len += progress.written;
        }
        if (!server.state.completed) {
            const progress = try server.handshake(to_server.held(), to_client.free());
            to_server.take(progress.consumed);
            to_client.len += progress.written;
        }
        if (client.state.completed and server.state.completed) return;
    }
    return error.TestUnexpectedResult;
}

/// Opens every whole record `wire` holds through `provider`, gathering the plaintext.
pub fn open_all(provider: tls_provider.Provider, wire: *Wire, plaintext: []u8) !usize {
    var gathered: usize = 0;
    for (0..wire_len) |_| {
        const opened = try provider.decrypt_record(wire.held(), plaintext[gathered..]);
        if (opened.content == .incomplete) return gathered;
        wire.take(opened.consumed);
        gathered += opened.plaintext_len;
    }
    return error.TestUnexpectedResult;
}
