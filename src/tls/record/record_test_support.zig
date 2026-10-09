//! What the record-mode tests share (`record_test.zig`, `record_keylog_test.zig`): a client and a
//! server of one TCP object, run against each other in memory over the test identity of
//! `src/testing/testdata/`.
const std = @import("std");
const platform = @import("platform");
const tls_provider = @import("tls_provider");
const chapulin = @import("chapulin_tcp");
const testdata = @import("testdata");
const record = @import("record.zig");
const values = @import("../values.zig");
const constants = @import("../constants.zig");
const random_support = @import("../random_test_support.zig");

pub const leaf = testdata.leaf;
pub const root = testdata.root;
pub const root_name = testdata.root_name;
pub const root_spki = testdata.root_spki;
pub const private_key: *const [constants.p256_private_key_len]u8 = testdata.private_key;
pub const public_key: *const [constants.p256_public_key_len]u8 = testdata.public_key;

/// The instant the tests judge the chain at. Any instant inside the identity's validity works,
/// from `testdata.not_before_seconds` to `testdata.not_after_seconds`.
pub const now_seconds: u64 = testdata.now_seconds;
/// The CPU the tests describe: the build target's answer on the AES instructions, since a test runs
/// where it was built, and the thread's mode stated `data_independent`. No test's result depends
/// on its timing, and the statement lets a session run the paths a program that makes it runs.
pub const cpu: values.Cpu = described(if (testdata.aes_instructions_present) .yes else .no, .data_independent);
/// A description under which a session runs the AES instructions, and those under which it does
/// not: a probe that does not say yes, and a mode the program does not state.
pub const cpu_with_aes: values.Cpu = described(.yes, .data_independent);
pub const cpu_without_aes: values.Cpu = described(.no, .data_independent);
pub const cpu_unknown: values.Cpu = described(.not_known, .data_independent);
pub const cpu_not_stated: values.Cpu = described(.yes, .not_stated);

fn described(aes_clmul: platform.Answer, timing: values.Timing) values.Cpu {
    return .{ .probe = .{ .aes_clmul = aes_clmul, .dit = .not_known }, .timing = timing };
}
/// The first and the last instant the identity is valid at, which chapulin counts inside.
pub const not_before_seconds = testdata.not_before_seconds;
pub const not_after_seconds = testdata.not_after_seconds;
/// Milliseconds in a second, for a ticket's age.
pub const ms_per_second: u64 = 1000;

pub const cookie_key: [constants.server_key_len]u8 = @splat(cookie_key_octet);
pub const ticket_key: [constants.server_key_len]u8 = @splat(ticket_key_octet);
/// The octet each test key repeats, which only has to differ from the other key's.
const cookie_key_octet: u8 = 0x07;
const ticket_key_octet: u8 = 0x09;
pub const chain = [_][]const u8{ leaf, root };
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

/// Octets one direction holds in flight: a server's whole flight and the records after it.
pub const wire_len: usize = 65_536;
/// Calls each side makes before a handshake in memory must have completed.
const handshake_rounds_max = 8;

/// One direction's octets, written at the back and consumed from the front.
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
        std.mem.copyForwards(u8, &wire.octets, wire.octets[consumed..wire.len]);
        wire.len -= consumed;
    }
};

/// Whether the linked object holds AES-GCM beside ChaCha20 (decision 97), and whether it takes the
/// caller's description of its CPU, as chapulin's host object does (its decision 89, decision 97 as
/// amended for chapulin 0.2.0).
pub const aes_gcm = @hasField(chapulin.c.ch_srv_cfg, "cipher_suites");
pub const takes_cpu = @hasField(chapulin.c.ch_cfg, "cpu");

/// Whether a session given the description `described_cpu` holds AES-GCM: an object with AES-GCM,
/// where the probe says `yes` and the mode is stated when the object takes the description.
pub fn holds_aes_gcm(described_cpu: values.Cpu) bool {
    const stated = described_cpu.probe.aes_clmul == .yes and described_cpu.timing == .data_independent;
    return aes_gcm and (!takes_cpu or stated);
}

/// The descriptions a test may run a session under. A probe that says yes needs the instructions,
/// which the build target has or does not, so a target without them runs the others alone. A mode
/// not stated runs none of them, whatever the probe says.
pub const cpus: []const values.Cpu = if (takes_cpu and cpu.probe.aes_clmul == .yes) &.{ cpu_with_aes, cpu_without_aes, cpu_unknown, cpu_not_stated } else &.{ cpu_without_aes, cpu_unknown, cpu_not_stated };

/// The suites a session under the tests' answer holds: the three colibri admits with AES-GCM, and
/// ChaCha20 alone without it.
pub const suites_held: []const u16 = if (holds_aes_gcm(cpu)) &tls_provider.constants.cipher_suites_admitted else &.{chacha};
pub const chacha = tls_provider.constants.cipher_suite_chacha20_poly1305_sha256;

/// A server order naming `suite` alone, or none in an object that holds one suite and no order.
pub fn order_of(suite: *const [1]u16) []const u16 {
    return if (aes_gcm) suite else &.{};
}

/// The suite chapulin's own order runs when neither side names one: AES-256-GCM first when both
/// sessions hold AES-GCM (chapulin's decision 80), and ChaCha20 when either holds it alone.
pub fn default_suite_of(client_cpu: values.Cpu, server_cpu: values.Cpu) u16 {
    if (holds_aes_gcm(client_cpu) and holds_aes_gcm(server_cpu)) return tls_provider.constants.cipher_suite_aes_256_gcm_sha384;
    return chacha;
}

/// The suite chapulin's own order runs under the tests' answer on both sides.
pub const default_suite: u16 = default_suite_of(cpu, cpu);

/// `web_pki` with a client order naming `suite` alone, or none in an object with no order.
pub fn offering(suite: *const [1]u16) values.Client {
    var offered = web_pki;
    offered.cipher_suites = order_of(suite);
    return offered;
}

/// What the tests vary on the server.
pub const ServerChoice = struct {
    tickets: bool = false,
    /// The suites the server selects from, in its order; empty for chapulin's.
    suites: []const u16 = &.{},
    /// The server's probe of its CPU.
    cpu: values.Cpu = cpu,
};

pub fn configure(client_values: values.Client, choice: ServerChoice) !void {
    try client_config.init(client_values);
    try server_config.init(.{
        .ecdsa_p256 = .{ .chain = &chain, .public_key = public_key, .private_key = private_key },
        .cookie_key = &cookie_key,
        .ticket_key = if (choice.tickets) &ticket_key else null,
        .alpn = &protocols,
        .cpu = choice.cpu,
        .cipher_suites = choice.suites,
    });
}

pub const web_pki: values.Client = .{
    .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "localhost" } },
    .alpn = &protocols,
    .cpu = cpu,
};

/// The source each session of the tests draws from: the stream the tests share.
pub fn random() values.Random {
    return random_support.stream.random();
}

/// Starts both sides and runs the handshake until both complete, leaving in `to_client` what the
/// server wrote after it, such as its ticket.
pub fn handshake_both(resumption: ?values.Resumption) !void {
    return handshake_at(now_seconds, resumption);
}

/// As `handshake_both`, with both sides' clocks at `seconds`.
pub fn handshake_at(seconds: u64, resumption: ?values.Resumption) !void {
    to_server = .{};
    to_client = .{};
    try client.start(&client_config, random(), seconds, resumption);
    try server.start(&server_config, random(), seconds);
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
        const opened = try provider.vtable.decrypt_record(provider.context, wire.held(), plaintext[gathered..]);
        if (opened.content == .incomplete) return gathered;
        wire.take(opened.consumed);
        gathered += opened.plaintext_len;
    }
    return error.TestUnexpectedResult;
}
