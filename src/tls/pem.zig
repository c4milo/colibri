//! The PEM files an operator holds (RFC 7468), read into the values `tls` takes
//! (https://github.com/c4milo/colibri/issues/97, decision 141): a server's certificate chain and
//! its key, P-256, RSA or ML-DSA-87 (decision 147), and a client's CA bundle. chapulin decodes each file (its decision 131), and
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

/// Reads the CERTIFICATE blocks of `file`, the end-entity first (RFC 9846 §4.5.1), into the DER
/// room `der` and the slices of `room`, and returns the chain `Identity.chain` takes. A
/// DER room of `file.len / 4 * 3` octets holds any file. Both rooms stay in place while a session
/// uses the chain.
pub fn chain(file: []const u8, der: []u8, room: [][]const u8) Error![]const []const u8 {
    const fits = room[0..@min(room.len, constants.limits.certificate_chain_len_max)];
    // RFC 7468 §2, §5.1 and §5.2, and RFC 9846 §4.5.1: chapulin skips the text around the blocks,
    // and refuses a block of another label.
    const read = chapulin.Chain.from_pem(file, der, fits) catch return error.Invalid;
    assert(read.certs.len > 0 and read.certs.len <= fits.len);
    return read.certs;
}

/// Reads one key block of `file` into `key`, and sets `key.scheme` from the key's algorithm:
/// - ecdsa_secp256r1_sha256 for a PRIVATE KEY block (PKCS #8, RFC 7468 §10) or an EC PRIVATE KEY
///   block (SEC 1, RFC 5915 §4) that holds a P-256 key;
/// - rsa_pss_rsae_sha256 for a PRIVATE KEY block that holds an rsaEncryption key of two primes and
///   the public exponent 65537 (RFC 8017 §3.2). chapulin signs once with it at load and verifies
///   the signature under the leaf's key, so a private key that does not match the leaf is refused;
/// - mldsa87 for a PRIVATE KEY block that holds an ML-DSA-87 key (RFC 9881 §6), in an object that
///   holds chapulin's ML-DSA-87 slot.
/// `leaf`, the end-entity certificate's DER, must carry the key's public key (RFC 9846 §4.5.2).
/// `cpu` is the server's `Cpu`, which chapulin computes the public key under. A refused file
/// leaves `key` with no scheme and zero keys. The program wipes `file` itself once the call
/// returns.
pub fn key(cpu: values.Cpu, file: []const u8, leaf: []const u8, into: *values.Key) Error!void {
    into.* = .{};
    // RFC 7468 §2 and §10, RFC 5958 §2, RFC 5915 §3 and §4, and RFC 9846 §4.5.2: chapulin skips
    // the text around the block, and refuses another label, another algorithm, and a key the leaf
    // does not carry. Each call is tried in turn, so the one that holds the key's algorithm reads it.
    if (read_p256(cpu, file, leaf, into)) return;
    if (read_rsa(cpu, file, leaf, into)) return;
    if (comptime has_mldsa87) {
        if (read_mldsa87(cpu, file, leaf, into)) return;
    }
    // RFC 7468 §10 and RFC 9881 §6: no call read the block as a key of its algorithm.
    return error.Invalid;
}

/// Whether the object reads an ML-DSA-87 key, which a host object does and a device object does not.
const has_mldsa87 = @hasDecl(chapulin.c, "ch_mldsa_key_from_pem");

/// Reads a P-256 key into `into`. chapulin decodes into its own key, which this copies and wipes.
fn read_p256(cpu: values.Cpu, file: []const u8, leaf: []const u8, into: *values.Key) bool {
    var read: chapulin.EcdsaP256Key = .{};
    defer read.wipe();
    read.init_from_pem(config.cpu_value(chapulin, cpu), file, leaf) catch return false;
    @memcpy(into.private_key[0..read.private_key.len], &read.private_key);
    @memcpy(into.public_key[0..read.public_key.len], &read.public_key);
    into.scheme = .ecdsa_secp256r1_sha256;
    return true;
}

/// Reads an RSA key into `into`: chapulin's `RsaKey` into the private room, whose alignment
/// holds it, and the modulus into the public room.
fn read_rsa(cpu: values.Cpu, file: []const u8, leaf: []const u8, into: *values.Key) bool {
    var read: chapulin.RsaKey = .{};
    defer read.wipe();
    read.init_from_pem(config.cpu_value(chapulin, cpu), file, leaf) catch return false;
    const modulus = read.public_key();
    @memcpy(into.private_key[0..@sizeOf(chapulin.RsaKey)], std.mem.asBytes(&read));
    @memcpy(into.public_key[0..modulus.len], modulus);
    into.scheme = .rsa_pss_rsae_sha256;
    return true;
}

/// Reads an ML-DSA-87 key into `into`, as `read_p256` reads a P-256 one.
fn read_mldsa87(cpu: values.Cpu, file: []const u8, leaf: []const u8, into: *values.Key) bool {
    var read: chapulin.MlDsa87Key = .{};
    defer read.wipe();
    read.init_from_pem(config.cpu_value(chapulin, cpu), file, leaf) catch return false;
    @memcpy(&into.private_key, &read.private_key);
    @memcpy(&into.public_key, &read.public_key);
    into.scheme = .mldsa87;
    return true;
}

comptime {
    // `read_p256`, `read_rsa` and `read_mldsa87` copy chapulin's keys into the rooms of a `Key`.
    assert(@sizeOf(@FieldType(chapulin.EcdsaP256Key, "private_key")) == constants.protocol.p256_private_key_len);
    assert(@sizeOf(@FieldType(chapulin.EcdsaP256Key, "public_key")) == constants.protocol.p256_public_key_len);
    assert(@sizeOf(chapulin.RsaKey) <= constants.protocol.mldsa87_private_key_len);
    assert(@alignOf(chapulin.RsaKey) <= @alignOf(values.Key) and
        @offsetOf(values.Key, "private_key") % @alignOf(chapulin.RsaKey) == 0);
    assert(@sizeOf(@FieldType(chapulin.c.ch_rsa_priv, "n")) <= constants.protocol.mldsa87_public_key_len);
    if (has_mldsa87) {
        assert(@sizeOf(@FieldType(chapulin.MlDsa87Key, "private_key")) == constants.protocol.mldsa87_private_key_len);
        assert(@sizeOf(@FieldType(chapulin.MlDsa87Key, "public_key")) == constants.protocol.mldsa87_public_key_len);
    }
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
    const read = chapulin.Anchors.from_pem(config.limits_of(chapulin), file, der, fits) catch return error.Invalid;
    assert(read.anchors.len > 0 and read.anchors.len <= fits.len);
    for (read.anchors, room[0..read.anchors.len]) |anchor, *kept| kept.* = .{ .subject = anchor.name, .spki = anchor.spki };
    return room[0..read.anchors.len];
}

test {
    _ = @import("pem_test.zig");
}
