//! What each UDP QUIC endpoint holds besides its connection (design §8 step 9e, piece 11): the
//! entropy chapulin draws on, the connection IDs the endpoint chooses, the certificate files, and
//! the key log. The endpoint may read the operating system's entropy; the library may not, and
//! does not (invariant 5).
const std = @import("std");
const constants = @import("../../constants.zig");
const check_file = @import("../../tls/check_file.zig");
const chapulin_quic_c = @import("../chapulin_quic_c.zig");
const chapulin_quic = @import("../chapulin_quic.zig");
const quic = @import("quic");
const chapulin_quic_suite = @import("../chapulin_quic_suite.zig");
const udp_peer = @import("udp_peer.zig");
const udp_arguments = @import("udp_arguments.zig");
const hq = @import("../hq/hq.zig");

const c = chapulin_quic_c.c;

/// The length of every connection ID this endpoint chooses. RFC 9000 §7.2: a client's first
/// Destination Connection ID "MUST be at least 8 bytes in length".
pub const id_len: usize = 8;

/// What `srv_cfg.h` fixes for the ecdsa_secp256r1_sha256 slot, and RFC 9846 §4.3.2's cookie key.
const private_scalar_len: usize = 32;
const public_point_len: usize = 64;
const cookie_key_len: usize = 32;

var keylog: chapulin_quic_c.Keylog = .{};
var local_id: [id_len]u8 = undefined;
var original_id: [id_len]u8 = undefined;
var retry_source_id: [id_len]u8 = undefined;
/// The deployment's Retry token key and its lifetime (decision 55).
var retry: chapulin_quic_suite.Retry = undefined;
var cookie_storage: [cookie_key_len]u8 = undefined;
var chain_storage: [constants.quic_chain_len_max][constants.tls_der_len_max]u8 = undefined;
var chain: [constants.quic_chain_len_max][]const u8 = undefined;
var private_storage: [private_scalar_len]u8 = undefined;
var public_storage: [public_point_len]u8 = undefined;
var name_storage: [constants.tls_der_len_max]u8 = undefined;
var spki_storage: [constants.tls_der_len_max]u8 = undefined;
/// chapulin keeps a pointer to the anchors, so they live as long as the session.
var anchors: [1]chapulin_quic.Anchor = undefined;

/// Fills `into` from the operating system's entropy.
fn draw(into: []u8) !void {
    const drawn = try check_file.read_file("/dev/urandom", into);
    if (drawn.len != into.len) return error.EntropyShort;
}

/// Seeds chapulin's generator and draws the cookie key, before any session starts.
pub fn seed() !void {
    var seed_octets: [chapulin_quic_c.seed_len]u8 = undefined;
    try draw(&seed_octets);
    c.ch_drbg_seed(&seed_octets);
    // RFC 9846 §4.3.2: one key per deployment, and a run is one deployment.
    try draw(&cookie_storage);
    // Decision 55: so is the Retry token's key, which only this process ever holds.
    try draw(&retry.key);
    retry.lifetime_seconds = constants.quic_retry_token_lifetime_seconds;
}

/// The suite a server writes a Retry and reads a returned token with (RFC 9000 §8.1.2).
pub fn retry_suite() quic.crypto.Suite {
    return retry.suite();
}

/// The PATH_CHALLENGE data a move owes (decision 72), drawn at random: RFC 9000 §8.2.1 wants it
/// unpredictable.
pub fn challenge_data() quic.connection_migration.ChallengeData {
    var data: quic.connection_migration.ChallengeData = undefined;
    draw(std.mem.asBytes(&data)) catch unreachable;
    return data;
}

/// A spare connection ID and its stateless reset token (RFC 9000 §5.1.1, §10.3), drawn at random:
/// §5.1 wants a connection ID unlinkable to the others, and §10.3 a token no one else can guess.
pub fn spare_id(id: *[id_len]u8, token: *[quic.constants.stateless_reset_token_len]u8) void {
    draw(id) catch unreachable;
    draw(token) catch unreachable;
}

/// A Retry's Source Connection ID, drawn at random, which the client addresses next (RFC 9000
/// §17.2.5.1). §5.1 wants it unpredictable, as every connection ID this endpoint chooses.
pub fn retry_id() []const u8 {
    draw(&retry_source_id) catch unreachable;
    return &retry_source_id;
}

/// A server's connection ID, drawn at random, for an Initial that returned a Retry token. The token
/// carried the client's first Destination Connection ID and the Retry's Source Connection ID
/// (decision 55), which RFC 9000 §7.3 has the server send back.
pub fn server_ids_after_retry(ids: *const quic.crypto.suite.RetryConnectionIds, source: []const u8) udp_peer.Identity {
    draw(&local_id) catch unreachable;
    return .{
        .local_source = &local_id,
        .original_destination = ids.original_destination_slice(),
        .peer_source = source,
        .retry_source = ids.retry_source_slice(),
    };
}

/// A client's two connection IDs, drawn at random (RFC 9000 §7.2).
pub fn client_ids() udp_peer.Identity {
    draw(&local_id) catch unreachable;
    draw(&original_id) catch unreachable;
    return .{ .local_source = &local_id, .original_destination = &original_id };
}

/// A server's connection ID, drawn at random, beside the two the client's first Initial carried.
pub fn server_ids(destination: []const u8, source: []const u8) udp_peer.Identity {
    draw(&local_id) catch unreachable;
    return .{ .local_source = &local_id, .original_destination = destination, .peer_source = source };
}

/// A client's session options. `receive` is chapulin's buffer for this connection alone.
pub fn client_options(asked: udp_arguments.Client, receive: []u8) !chapulin_quic.Options {
    return .{
        .role = .client,
        .alpn = hq.alpn,
        .receive = receive,
        .trust = try client_trust(asked),
        .keylog = &keylog,
    };
}

/// A Web PKI build pins the root's Subject Name and SubjectPublicKeyInfo, and checks the chain
/// and the host name. A raw-pin build pins the server's own P-256 point, from `<prefix>.pub`.
fn client_trust(asked: udp_arguments.Client) !chapulin_quic.Trust {
    const prefix = asked.anchor_prefix;
    if (!chapulin_quic.webpki) {
        return .{ .pinned = .{ .public_point = try check_file.read_part(prefix, ".pub", &public_storage) } };
    }
    const name = try check_file.read_part(prefix, ".name", &name_storage);
    const spki = try check_file.read_part(prefix, ".spki", &spki_storage);
    anchors[0] = .{ .name = name.ptr, .name_len = name.len, .spki = spki.ptr, .spki_len = spki.len };
    return .{ .webpki = .{ .anchors = &anchors, .hostname = asked.hostname, .now_seconds = asked.now_seconds } };
}

/// A server's session options. `receive` is chapulin's buffer for this connection alone.
pub fn server_options(asked: udp_arguments.Server, receive: []u8) !chapulin_quic.Options {
    const prefix = asked.identity_prefix;
    return .{
        .role = .server,
        .alpn = hq.alpn,
        .receive = receive,
        .identity = .{
            .chain = try read_chain(prefix),
            .private_scalar = try check_file.read_part(prefix, ".priv", &private_storage),
            .public_point = try check_file.read_part(prefix, ".pub", &public_storage),
            .cookie_key = &cookie_storage,
        },
        .keylog = &keylog,
    };
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
    if (keylog.len == 0 and !keylog.overflowed) return;
    defer keylog.clear();
    const path = std.c.getenv("SSLKEYLOGFILE") orelse return;
    if (!keylog.append_to_file(std.mem.span(path))) std.debug.print("quic-udp: cannot write the key log\n", .{});
}
