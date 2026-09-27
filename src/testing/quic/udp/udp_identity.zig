//! What each UDP QUIC endpoint holds besides its connection (design §8 step 9e, piece 11): the
//! keys the endpoint draws, the connection IDs it chooses, the configuration its sessions borrow,
//! converted once from the certificate files (design §8 step 16b), and the key log. The endpoint
//! may read the operating system's entropy; the library may not, and does not (invariant 5).
const std = @import("std");
const tls = @import("tls");
const constants = @import("../../constants.zig");
const check_file = @import("../../tls/check_file.zig");
const entropy = @import("../../entropy.zig");
const keylog_module = @import("../keylog.zig");
const quic_session = @import("../quic_session.zig");
const quic = @import("quic");
const udp_peer = @import("udp_peer.zig");
const udp_arguments = @import("udp_arguments.zig");
const hq = @import("../hq/hq.zig");
const h2 = @import("h2");

/// The length of every connection ID this endpoint chooses. RFC 9000 §7.2: a client's first
/// Destination Connection ID "MUST be at least 8 bytes in length".
pub const id_len: usize = 8;

var log: keylog_module.Keylog align(@alignOf(keylog_module.Keylog)) = .{};
var local_id: [id_len]u8 = undefined;
var original_id: [id_len]u8 = undefined;
var retry_source_id: [id_len]u8 = undefined;
/// The deployment's Retry token key and its lifetime (decision 55).
var retry_key: [tls.quic.token_key_len]u8 = undefined;
var retry: tls.quic.Retry align(@alignOf(tls.quic.Retry)) = undefined;
var cookie_storage: [tls.constants.server_key_len]u8 = undefined;
/// The key the server seals its session tickets under (chapulin's decision 51).
var ticket_key_storage: [tls.constants.server_key_len]u8 = undefined;
var chain_storage: [constants.quic_chain_len_max][constants.tls_der_len_max]u8 = undefined;
var chain: [constants.quic_chain_len_max][]const u8 = undefined;
var private_storage: [tls.constants.p256_private_key_len]u8 = undefined;
var public_storage: [tls.constants.p256_public_key_len]u8 = undefined;
var name_storage: [constants.tls_der_len_max]u8 = undefined;
var spki_storage: [constants.tls_der_len_max]u8 = undefined;
var pin_storage: [1]tls.Pin align(@alignOf(tls.Pin)) = undefined;
/// The configuration every session of the run borrows, in the run's one role.
var server_config: tls.quic.ServerConfig align(@alignOf(tls.quic.ServerConfig)) = undefined;
var client_config: tls.quic.ClientConfig align(@alignOf(tls.quic.ClientConfig)) = undefined;

/// Draws the keys and converts the run's configuration, before any session starts. Each session
/// draws the rest from the source `entropy.zig` hands its `start`.
pub fn seed(asked: udp_arguments.Arguments) !void {
    // RFC 9846 §4.3.2: one key per deployment, and a run is one deployment.
    entropy.fill(&cookie_storage);
    // Decision 55: so is the Retry token's key, which only this process ever holds.
    entropy.fill(&retry_key);
    retry = .{ .key = &retry_key, .lifetime_seconds = constants.quic_retry_token_lifetime_seconds };
    // chapulin's `srv_cfg.h`: one ticket key per deployment, and a ticket resumes only on a server
    // that holds it, which here is this process.
    entropy.fill(&ticket_key_storage);
    switch (asked) {
        .server => |server| try configure_server(server),
        .client => |client| try configure_client(client),
    }
}

/// The suite a server writes a Retry and reads a returned token with (RFC 9000 §8.1.2).
pub fn retry_suite() quic.crypto.Suite {
    return retry.suite();
}

/// Where every session of the run logs its secrets.
pub fn keylog() *keylog_module.Keylog {
    return &log;
}

/// The PATH_CHALLENGE data a move owes (decision 72), drawn at random: RFC 9000 §8.2.1 wants it
/// unpredictable.
pub fn challenge_data() quic.connection_migration.ChallengeData {
    var data: quic.connection_migration.ChallengeData = undefined;
    entropy.fill(std.mem.asBytes(&data));
    return data;
}

/// The value an h3 connection's reserved setting and error codes are drawn from (RFC 9114
/// §7.2.4.1, §8.1), drawn at random, so each connection greases with its own.
pub fn grease() u64 {
    var value: u64 = undefined;
    entropy.fill(std.mem.asBytes(&value));
    return value;
}

/// The ALPN protocols a server offers: h3 first, then hq-interop, and it serves whichever its
/// client asks for (RFC 9001 §8.1).
const server_alpn = [_][]const u8{ &h2.tls_provider.constants.alpn_h3, hq.alpn };
const client_alpn_h3 = [_][]const u8{&h2.tls_provider.constants.alpn_h3};
const client_alpn_hq = [_][]const u8{hq.alpn};

/// A spare connection ID and its stateless reset token (RFC 9000 §5.1.1, §10.3), drawn at random:
/// §5.1 wants a connection ID unlinkable to the others, and §10.3 a token no one else can guess.
pub fn spare_id(id: *[id_len]u8, token: *[quic.constants.stateless_reset_token_len]u8) void {
    entropy.fill(id);
    entropy.fill(token);
}

/// A Retry's Source Connection ID, drawn at random, which the client addresses next (RFC 9000
/// §17.2.5.1). §5.1 wants it unpredictable, as every connection ID this endpoint chooses.
pub fn retry_id() []const u8 {
    entropy.fill(&retry_source_id);
    return &retry_source_id;
}

/// A server's connection ID, drawn at random, for an Initial that returned a Retry token. The token
/// carried the client's first Destination Connection ID and the Retry's Source Connection ID
/// (decision 55), which RFC 9000 §7.3 has the server send back.
pub fn server_ids_after_retry(ids: *const quic.crypto.suite.RetryConnectionIds, source: []const u8) udp_peer.Identity {
    entropy.fill(&local_id);
    return .{
        .local_source = &local_id,
        .original_destination = ids.original_destination_slice(),
        .peer_source = source,
        .retry_source = ids.retry_source_slice(),
    };
}

/// A client's two connection IDs, drawn at random (RFC 9000 §7.2).
pub fn client_ids() udp_peer.Identity {
    entropy.fill(&local_id);
    entropy.fill(&original_id);
    return .{ .local_source = &local_id, .original_destination = &original_id };
}

/// A server's connection ID, drawn at random, beside the two the client's first Initial carried.
pub fn server_ids(destination: []const u8, source: []const u8) udp_peer.Identity {
    entropy.fill(&local_id);
    return .{ .local_source = &local_id, .original_destination = destination, .peer_source = source };
}

/// A client session's start: the run's configuration, the clock the command line gave, and the
/// ticket to present, if any.
pub fn client_start(asked: udp_arguments.Client, resumption: ?tls.Resumption) quic_session.Start {
    return .{ .client = .{ .config = &client_config, .now_seconds = asked.now_seconds, .resumption = resumption } };
}

/// A server session's start: `now_seconds` is the Unix seconds its ticket carries, or 0 to issue
/// none.
pub fn server_start(now_seconds: u64) quic_session.Start {
    return .{ .server = .{ .config = &server_config, .now_seconds = now_seconds } };
}

/// The client offers h3 or hq-interop, as asked. By default it trusts the root the prefix names,
/// and checks the chain and the host name; with `pin` it trusts the server's key alone, whose
/// SHA-256 `<prefix>.pin` holds.
fn configure_client(asked: udp_arguments.Client) !void {
    const prefix = asked.anchor_prefix;
    const alpn: []const []const u8 = if (asked.h3) &client_alpn_h3 else &client_alpn_hq;
    if (asked.pin) {
        try read_key(prefix, ".pin", &pin_storage[0]);
        return client_config.init(.{ .trust = .{ .pins = .{ .pins = &pin_storage, .server_name = asked.hostname } }, .alpn = alpn });
    }
    const anchors = [_]tls.Anchor{.{
        .subject = try check_file.read_part(prefix, ".name", &name_storage),
        .spki = try check_file.read_part(prefix, ".spki", &spki_storage),
    }};
    return client_config.init(.{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = asked.hostname } }, .alpn = alpn });
}

fn configure_server(asked: udp_arguments.Server) !void {
    const prefix = asked.identity_prefix;
    try read_key(prefix, ".priv", &private_storage);
    try read_key(prefix, ".pub", &public_storage);
    try server_config.init(.{
        .ecdsa_p256 = .{ .chain = try read_chain(prefix), .public_key = &public_storage, .private_key = &private_storage },
        .cookie_key = &cookie_storage,
        .ticket_key = &ticket_key_storage,
        .alpn = &server_alpn,
    });
    try server_config.check(entropy.random());
}

/// Reads a key file, which must fill `into` exactly: one octet more is read to tell a longer file.
fn read_key(prefix: []const u8, suffix: []const u8, into: []u8) !void {
    var read_storage: [tls.constants.p256_public_key_len + 1]u8 = undefined;
    const read = try check_file.read_part(prefix, suffix, &read_storage);
    if (read.len != into.len) return error.KeyLengthWrong;
    @memcpy(into, read);
}

/// The certificates the server presents. `tools/quic_interop/qns_identity.py` writes the QUIC
/// Interop Runner's chain as `<prefix>.chain.<i>.der`, the end-entity first. Without those files
/// it is the Go tool's pair: the end-entity certificate and the root that signed it.
fn read_chain(prefix: []const u8) ![]const []const u8 {
    var count: usize = 0;
    // Bounded by `quic_chain_len_max`.
    for (&chain_storage, 0..) |*storage, index| {
        var suffix_storage: [chain_suffix_len_max]u8 = undefined;
        const suffix = std.fmt.bufPrint(&suffix_storage, ".chain.{d}.der", .{index}) catch unreachable;
        chain[index] = check_file.read_part_if_present(prefix, suffix, storage) orelse break;
        count += 1;
    }
    if (count > 0) return chain[0..count];
    chain[0] = try check_file.read_part(prefix, ".leaf.der", &chain_storage[0]);
    chain[1] = try check_file.read_part(prefix, ".ca.der", &chain_storage[1]);
    return chain[0..go_chain_len];
}

/// The Go tool's pair: the end-entity certificate and the root that signed it.
const go_chain_len: usize = 2;

/// Room for `.chain.<i>.der` with a two-digit index.
const chain_suffix_len_max: usize = 16;

/// Appends the traffic secrets gathered since the last call to the file SSLKEYLOGFILE names,
/// when it names one, and empties the log so no line is written twice. With none gathered it
/// opens no file, so a caller may call it after every step.
pub fn write_keylog() void {
    if (log.len == 0 and !log.overflowed) return;
    defer log.clear();
    const path = std.c.getenv("SSLKEYLOGFILE") orelse return;
    if (!log.append_to_file(std.mem.span(path))) std.debug.print("quic-udp: cannot write the key log\n", .{});
}
