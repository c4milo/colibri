//! What a chapulin server loads once at start, which `accept_check.zig` and the h2 server's TLS
//! mode share: the generator's seed, RFC 9846 §4.3.2's cookie key, and the identity
//! `tools/h2_interop/tls_identity.go` wrote. Part of design §8 step 5's TLS work.
//!
//! This endpoint code may read the operating system's entropy; the library may not, and does not.
const std = @import("std");
const chapulin = @import("chapulin.zig");
const chapulin_server = @import("chapulin_server.zig");
const constants = @import("../constants.zig");
const check_file = @import("check_file.zig");

const c = chapulin.c;

/// The storage the loaded identity and cookie key point into. It outlives every session, which
/// is chapulin's rule for its configuration (decision 35).
pub const Storage = struct {
    leaf: [constants.tls_der_len_max]u8,
    issuer: [constants.tls_der_len_max]u8,
    private_scalar: [chapulin_server.private_scalar_len]u8,
    public_point: [chapulin_server.public_point_len]u8,
    cookie_key: [chapulin_server.cookie_key_len]u8,
};

pub const Error = error{
    /// The operating system gave fewer random octets than asked for.
    EntropyShort,
};

/// Where the random octets come from.
const entropy_path = "/dev/urandom";

/// Seeds chapulin's generator and draws the cookie key. A `RAND=drbg` build requires the seed
/// before any handshake, and `ch_srv_check` draws entropy of its own to salt a signature. RFC 9846
/// §4.3.2 asks for one cookie key per deployment, and a run is one deployment.
pub fn seed(storage: *Storage) !void {
    var drawn: [chapulin.seed_len]u8 = undefined;
    const octets = try check_file.read_file(entropy_path, &drawn);
    if (octets.len != drawn.len) return Error.EntropyShort;
    c.ch_drbg_seed(&drawn);
    const cookie = try check_file.read_file(entropy_path, &storage.cookie_key);
    if (cookie.len != storage.cookie_key.len) return Error.EntropyShort;
}

/// Reads the four parts of the identity `tls_identity.go` minted, each raw DER or raw octets.
pub fn load(prefix: []const u8, storage: *Storage) !chapulin_server.Identity {
    return .{
        .leaf = try check_file.read_part(prefix, ".leaf.der", &storage.leaf),
        .issuer = try check_file.read_part(prefix, ".ca.der", &storage.issuer),
        .private_scalar = try check_file.read_part(prefix, ".priv", &storage.private_scalar),
        .public_point = try check_file.read_part(prefix, ".pub", &storage.public_point),
    };
}
