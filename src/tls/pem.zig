//! The PEM files an operator holds (RFC 7468), read into the values `tls` takes
//! (https://github.com/c4milo/colibri/issues/97, decision 141): a server's certificate chain and
//! its P-256 key, and a client's CA bundle. chapulin decodes each file (its decision 131), and
//! this file shapes the result. None of the calls reads a file: the program reads it into a slice
//! and passes the slice, with rooms it places and sizes. Decoding authenticates nothing; the files
//! are trusted because the operator placed them.
const std = @import("std");
const assert = std.debug.assert;
const chapulin = @import("chapulin_tcp");
const constants = @import("constants.zig");
const values = @import("values.zig");
const config = @import("config.zig");

/// A file chapulin refuses: a block of a label other than the call's, an encrypted key, a key that
/// is not P-256 or that the leaf does not carry, or more than fits the rooms. The text lines
/// around the blocks are skipped (RFC 7468 §2 and §5.2).
pub const Error = error{Invalid};

/// A P-256 key pair read from a PEM file: the scalar and its point, which
/// `EcdsaP256Identity.private_key` and `public_key` point at. The scalar is a secret: `wipe` zeroes
/// it once no session uses it.
pub const P256Key = extern struct {
    /// The private scalar, big-endian.
    private_key: [constants.protocol.p256_private_key_len]u8 = @splat(0),
    /// The point, X||Y.
    public_key: [constants.protocol.p256_public_key_len]u8 = @splat(0),

    /// Writes zero over the scalar, through a write the compiler keeps.
    pub fn wipe(key: *P256Key) void {
        std.crypto.secureZero(u8, &key.private_key);
    }
};

/// Reads the CERTIFICATE blocks of `file`, the end-entity first (RFC 9846 §4.5.1), into the DER
/// room `der` and the slices of `room`, and returns the chain `EcdsaP256Identity.chain` takes. A
/// DER room of `file.len / 4 * 3` octets holds any file. Both rooms stay in place while a session
/// uses the chain.
pub fn chain(file: []const u8, der: []u8, room: [][]const u8) Error![]const []const u8 {
    const fits = room[0..@min(room.len, constants.limits.certificate_chain_len_max)];
    // RFC 7468 §2, §5.1 and §5.2, and RFC 9846 §4.5.1: chapulin skips the text around the blocks,
    // and refuses a block of another label.
    const read = chapulin.Chain.fromPem(file, der, fits) catch return error.Invalid;
    assert(read.certs.len > 0 and read.certs.len <= fits.len);
    return read.certs;
}

/// Reads one PRIVATE KEY block (PKCS #8, RFC 7468 §10) or one EC PRIVATE KEY block (SEC 1, RFC 5915 §4)
/// of `file` into `key`. The key must be P-256, and `leaf`, the end-entity certificate's DER, must
/// carry its point (RFC 9846 §4.5.2). `cpu` is the server's `Cpu`, which chapulin computes the
/// point under. The program wipes `file` itself once the call returns.
pub fn p256_key(cpu: values.Cpu, file: []const u8, leaf: []const u8, key: *P256Key) Error!void {
    // chapulin decodes into the caller's key, so no copy of the scalar is left to wipe. A refused
    // file leaves both fields zero.
    const read: *chapulin.EcdsaP256Key = @ptrCast(key);
    // RFC 7468 §2 and §10, RFC 5958 §2, RFC 5915 §3 and §4, and RFC 9846 §4.5.2: chapulin skips the
    // text around the block, and refuses another label, a key that is not P-256, and one the leaf
    // does not carry.
    read.fromPem(config.cpu_value(chapulin, cpu), file, leaf) catch return error.Invalid;
}

comptime {
    // `p256_key` hands the caller's key to chapulin as chapulin's own type.
    assert(@sizeOf(P256Key) == @sizeOf(chapulin.EcdsaP256Key));
    assert(@alignOf(P256Key) == @alignOf(chapulin.EcdsaP256Key));
    assert(@offsetOf(P256Key, "private_key") == @offsetOf(chapulin.EcdsaP256Key, "private_key"));
    assert(@offsetOf(P256Key, "public_key") == @offsetOf(chapulin.EcdsaP256Key, "public_key"));
}

/// Reads the CERTIFICATE blocks of a CA bundle into the DER room `der` and the anchors of `room`,
/// each the certificate's subject Name and SubjectPublicKeyInfo (RFC 9846 §4.5.1.3), and returns
/// the anchors `Trust.web_pki.anchors` takes. The text lines around the blocks are skipped, as a
/// curl-style bundle carries them. Both rooms stay in place while a session uses the anchors.
pub fn anchors(file: []const u8, der: []u8, room: []values.Anchor) Error![]const values.Anchor {
    // chapulin's anchors are a type of the object, copied into colibri's after the call.
    var read_room: [constants.limits.anchors_max]chapulin.TrustAnchor = undefined;
    const fits = read_room[0..@min(room.len, read_room.len)];
    // RFC 7468 §5.1 and §5.2, and RFC 9846 §4.5.1.3: chapulin skips the text around the blocks,
    // and refuses a bundle with a block of another label.
    const read = chapulin.Anchors.fromPem(config.limits_of(chapulin), file, der, fits) catch return error.Invalid;
    assert(read.anchors.len > 0 and read.anchors.len <= fits.len);
    for (read.anchors, room[0..read.anchors.len]) |anchor, *kept| kept.* = .{ .subject = anchor.name, .spki = anchor.spki };
    return room[0..read.anchors.len];
}

test {
    _ = @import("pem_test.zig");
}
