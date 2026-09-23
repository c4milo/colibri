//! Runs a colibri QUIC client and a colibri QUIC server against each other over chapulin, in one
//! process, until the client's stream has arrived. Part of design §8 step 9e, piece 11.
//!
//! What it proves, which the simulator's check cannot: colibri's connection completes a real
//! TLS 1.3 handshake through `tls.QuicProvider` and protects real packets through
//! `crypto.Suite`, with every key inside chapulin (decision 48). The client verifies the server's
//! certificate chain, both select "hq-interop" by ALPN (RFC 9001 §8.1), and the server reads
//! every octet of the client's stream.
//!
//! What it does not prove is interoperability: both ends are colibri and both are chapulin, so a
//! shared misreading of an RFC passes. `tools/interop.sh` is that check.
//!
//! Datagrams move in memory, in the order each endpoint sends them, and the instant is the
//! check's own, advanced by `quic_round_ns` each round. Nothing is lost or reordered.
const std = @import("std");
const quic = @import("quic");
const constants = @import("../constants.zig");
const check_file = @import("../tls/check_file.zig");
const chapulin_quic_c = @import("chapulin_quic_c.zig");
const chapulin_quic = @import("chapulin_quic.zig");
const loopback_endpoint = @import("loopback_endpoint.zig");

const c = chapulin_quic_c.c;
const Endpoint = loopback_endpoint.Endpoint;
const exit_usage = check_file.exit_usage;
const exit_failed = check_file.exit_failed;

/// The protocol the QUIC Interop Runner's transfer cases speak, which both ends select.
const alpn = "hq-interop";

/// The two endpoints, outside any stack frame: each carries a session, a pool and buffers.
var client: Endpoint = undefined;
var server: Endpoint = undefined;
var client_receive: [constants.tls_receive_len]u8 = undefined;
var server_receive: [constants.tls_receive_len]u8 = undefined;
var keylog: chapulin_quic_c.Keylog = .{};

var leaf_storage: [constants.tls_der_len_max]u8 = undefined;
var issuer_storage: [constants.tls_der_len_max]u8 = undefined;
/// The end-entity certificate and the root that signed it, which is what the Go tool mints.
const go_chain_len: usize = 2;
var chain: [go_chain_len][]const u8 = undefined;
var name_storage: [constants.tls_der_len_max]u8 = undefined;
var spki_storage: [constants.tls_der_len_max]u8 = undefined;
var private_storage: [private_scalar_len]u8 = undefined;
var public_storage: [public_point_len]u8 = undefined;
var cookie_storage: [cookie_key_len]u8 = undefined;

/// What `srv_cfg.h` fixes for the ecdsa_secp256r1_sha256 slot, and RFC 9846 §4.3.2's cookie key.
const private_scalar_len: usize = 32;
const public_point_len: usize = 64;
const cookie_key_len: usize = 32;

const Arguments = struct {
    /// The prefix of the files `tools/h2_interop/tls_identity.go` wrote.
    identity_prefix: []const u8,
    hostname: []const u8,
    now_seconds: u64,
    /// Where the NSS key log goes, or null for nowhere.
    keylog_path: ?[]const u8,
};

fn parse(init: std.process.Init.Minimal) Arguments {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.next();
    const identity_prefix = arguments.next() orelse usage();
    const hostname = arguments.next() orelse usage();
    const now_text = arguments.next() orelse usage();
    return .{
        .identity_prefix = identity_prefix,
        .hostname = hostname,
        .now_seconds = std.fmt.parseUnsigned(u64, now_text, decimal) catch usage(),
        .keylog_path = arguments.next(),
    };
}

/// Seeds chapulin's DRBG and draws the cookie key. The check may read the operating system's
/// entropy; the library may not, and does not.
fn seed_chapulin() !void {
    var seed: [chapulin_quic_c.seed_len]u8 = undefined;
    const drawn = try check_file.read_file("/dev/urandom", &seed);
    const cookie = try check_file.read_file("/dev/urandom", &cookie_storage);
    if (drawn.len != seed.len or cookie.len != cookie_storage.len) fail("could not draw entropy", .{});
    c.ch_drbg_seed(&seed);
}

pub fn main(init: std.process.Init.Minimal) !void {
    if (!chapulin_quic_c.available) {
        std.debug.print("quic-loopback: built without chapulin; pass -Dchapulin-quic=<checkout>\n", .{});
        std.process.exit(exit_usage);
    }
    const asked = parse(init);
    try seed_chapulin();
    const prefix = asked.identity_prefix;
    // A chapulin anchor is the root's Subject Name and its SubjectPublicKeyInfo, each the whole
    // DER TLV. The client pins this one root, or in a raw-pin build the server's own key.
    const anchor_name = try check_file.read_part(prefix, ".name", &name_storage);
    const spki = try check_file.read_part(prefix, ".spki", &spki_storage);
    const anchors = [_]chapulin_quic.Anchor{if (chapulin_quic.webpki) .{
        .name = anchor_name.ptr,
        .name_len = anchor_name.len,
        .spki = spki.ptr,
        .spki_len = spki.len,
    } else {}};
    chain[0] = try check_file.read_part(prefix, ".leaf.der", &leaf_storage);
    chain[1] = try check_file.read_part(prefix, ".ca.der", &issuer_storage);
    const identity: chapulin_quic.Identity = .{
        .chain = &chain,
        .private_scalar = try check_file.read_part(prefix, ".priv", &private_storage),
        .public_point = try check_file.read_part(prefix, ".pub", &public_storage),
        .cookie_key = &cookie_storage,
    };
    server.init(.{
        .role = .server,
        .alpn = alpn,
        .receive = &server_receive,
        .identity = identity,
        .keylog = &keylog,
    }, 0) catch |failure| fail("the server did not start: {t}", .{failure});
    if (!server.session.check_identity()) fail("chapulin refused the server's identity", .{});
    client.init(.{
        .role = .client,
        .alpn = alpn,
        .receive = &client_receive,
        .trust = trust_of(&anchors, asked),
        .keylog = &keylog,
    }, 0) catch |failure| fail("the client did not start: {t}", .{failure});
    const run = exchange();
    report(run);
    check_keylog();
    if (asked.keylog_path) |path| write_keylog(path);
}

/// Each endpoint derives four traffic secrets, and `keylog.h` names one line for each: both
/// handshake secrets and both first application secrets (RFC 9846 §7.1).
const keylog_lines_per_endpoint: usize = 4;
const endpoints: usize = 2;

/// The key log is what makes a capture of a run readable, so a hook that wrote nothing fails.
fn check_keylog() void {
    if (keylog.overflowed) fail("the key log did not fit", .{});
    const lines = std.mem.count(u8, keylog.written(), "\n");
    if (lines != keylog_lines_per_endpoint * endpoints) fail("the key log holds {d} lines", .{lines});
}

/// What the client judges the server by: the root in a Web PKI build, the server's own key in a
/// raw-pin build.
fn trust_of(anchors: []const chapulin_quic.Anchor, asked: Arguments) chapulin_quic.Trust {
    if (chapulin_quic.webpki) return .{ .webpki = .{ .anchors = anchors, .hostname = asked.hostname, .now_seconds = asked.now_seconds } };
    return .{ .pinned = .{ .public_point = &public_storage } };
}

/// What a run counted.
const Run = struct {
    rounds: u32 = 0,
    /// The round each milestone was reached in, or null when it was not.
    handshake_round: ?u32 = null,
    confirmed_round: ?u32 = null,
    client: Sent = .{},
    server: Sent = .{},
};

/// What one endpoint sent.
const Sent = struct {
    datagrams: u64 = 0,
    octets: u64 = 0,
};

/// Moves datagrams until the server has read the whole stream and the client has had it
/// acknowledged, or the rounds run out.
fn exchange() Run {
    var run: Run = .{};
    // Bounded by `quic_rounds_max`.
    for (0..constants.quic_rounds_max) |round| {
        const now_ns = @as(u64, @intCast(round)) * constants.quic_round_ns;
        run.rounds = @intCast(round);
        fire(&client, now_ns, "client");
        fire(&server, now_ns, "server");
        deliver(&client, &server, now_ns, &run.client, "client");
        deliver(&server, &client, now_ns, &run.server, "server");
        note(&run);
        if (client.transfer_done and server.transfer_read) return run;
    }
    fail("stuck after {d} rounds: handshake {?d}, read {d} of {d}", .{
        constants.quic_rounds_max,
        run.handshake_round,
        server.transfer_read_len,
        loopback_endpoint.transfer_len,
    });
}

fn note(run: *Run) void {
    if (run.handshake_round == null and client.connection.handshake_complete and server.connection.handshake_complete)
        run.handshake_round = run.rounds;
    if (run.confirmed_round == null and client.connection.handshake_confirmed)
        run.confirmed_round = run.rounds;
}

fn fire(endpoint: *Endpoint, now_ns: u64, name: []const u8) void {
    endpoint.on_instant(now_ns) catch |failure| fail("{s}: a timer failed: {t}", .{ name, failure });
}

/// Sends every datagram `from` owes now and hands each to `to`, counting them in `sent`.
fn deliver(from: *Endpoint, to: *Endpoint, now_ns: u64, sent: *Sent, name: []const u8) void {
    // Bounded: a round sends at most what the congestion window allows.
    for (0..constants.quic_rounds_max) |_| {
        const datagram = from.send(now_ns) catch |failure| fail("{s}: send failed: {t}", .{ name, failure }) orelse
            return;
        to.receive(datagram, now_ns) catch |failure| fail("{s}'s datagram was refused: {t}", .{ name, failure });
        sent.datagrams += 1;
        sent.octets += datagram.len;
    }
}

fn report(run: Run) void {
    const provider = client.session.provider();
    const selected = provider.negotiated_alpn() orelse fail("the client selected no protocol", .{});
    if (!std.mem.eql(u8, selected, alpn)) fail("the client selected {s}", .{selected});
    std.debug.print(
        "quic-loopback: complete alpn={s} handshake_round={?d} confirmed_round={?d} rounds={d} " ++
            "round_ns={d} client_datagrams={d} client_octets={d} server_datagrams={d} server_octets={d} " ++
            "stream_octets={d}\n",
        .{
            selected,
            run.handshake_round,
            run.confirmed_round,
            run.rounds,
            constants.quic_round_ns,
            run.client.datagrams,
            run.client.octets,
            run.server.datagrams,
            run.server.octets,
            server.transfer_read_len,
        },
    );
}

/// Writes the key log, appending as the format's readers expect of SSLKEYLOGFILE.
fn write_keylog(path: []const u8) void {
    if (!keylog.append_to_file(path)) fail("cannot write the key log to {s}", .{path});
}

fn fail(comptime format: []const u8, arguments: anytype) noreturn {
    std.debug.print("quic-loopback: " ++ format ++ "\n", arguments);
    std.process.exit(exit_failed);
}

fn usage() noreturn {
    std.debug.print("usage: quic-loopback <identity-prefix> <hostname> <unix-seconds> [keylog-path]\n", .{});
    std.process.exit(exit_usage);
}

/// The radix every number on the command line is written in.
const decimal: u8 = 10;
