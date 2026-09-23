//! What each UDP QUIC endpoint holds besides its connection (design §8 step 9e, piece 11): the
//! entropy chapulin draws on, the connection IDs the endpoint chooses, the certificate files, and
//! the key log. The endpoint may read the operating system's entropy; the library may not, and
//! does not (invariant 5).
const std = @import("std");
const constants = @import("../../constants.zig");
const check_file = @import("../../tls/check_file.zig");
const chapulin_quic_c = @import("../chapulin_quic_c.zig");
const chapulin_quic = @import("../chapulin_quic.zig");
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
var receive_storage: [constants.tls_receive_len]u8 = undefined;
var local_id: [id_len]u8 = undefined;
var original_id: [id_len]u8 = undefined;
var cookie_storage: [cookie_key_len]u8 = undefined;
var leaf_storage: [constants.tls_der_len_max]u8 = undefined;
var issuer_storage: [constants.tls_der_len_max]u8 = undefined;
var private_storage: [private_scalar_len]u8 = undefined;
var public_storage: [public_point_len]u8 = undefined;
var name_storage: [constants.tls_der_len_max]u8 = undefined;
var spki_storage: [constants.tls_der_len_max]u8 = undefined;
/// chapulin keeps a pointer to the anchors, so they live as long as the session.
var anchors: [1]c.ch_trust_anchor = undefined;

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

pub fn client_options(asked: udp_arguments.Client) !chapulin_quic.Options {
    const name = try check_file.read_part(asked.anchor_prefix, ".name", &name_storage);
    const spki = try check_file.read_part(asked.anchor_prefix, ".spki", &spki_storage);
    anchors[0] = .{ .name = name.ptr, .name_len = name.len, .spki = spki.ptr, .spki_len = spki.len };
    return .{
        .role = .client,
        .alpn = hq.alpn,
        .receive = &receive_storage,
        .trust = .{ .anchors = &anchors, .hostname = asked.hostname, .now_seconds = asked.now_seconds },
        .keylog = &keylog,
    };
}

pub fn server_options(asked: udp_arguments.Server) !chapulin_quic.Options {
    const prefix = asked.identity_prefix;
    return .{
        .role = .server,
        .alpn = hq.alpn,
        .receive = &receive_storage,
        .identity = .{
            .leaf = try check_file.read_part(prefix, ".leaf.der", &leaf_storage),
            .issuer = try check_file.read_part(prefix, ".ca.der", &issuer_storage),
            .private_scalar = try check_file.read_part(prefix, ".priv", &private_storage),
            .public_point = try check_file.read_part(prefix, ".pub", &public_storage),
            .cookie_key = &cookie_storage,
        },
        .keylog = &keylog,
    };
}

/// Appends the run's traffic secrets to the file SSLKEYLOGFILE names, when it names one.
pub fn write_keylog() void {
    const path = std.c.getenv("SSLKEYLOGFILE") orelse return;
    if (!keylog.append_to_file(std.mem.span(path))) std.debug.print("quic-udp: cannot write the key log\n", .{});
}
