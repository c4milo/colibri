//! The checks of `dnssec` against the examples the RFCs print: RFC 5702 §6 for RSA/SHA-256 and
//! RSA/SHA-512, RFC 6605 §6 for the two ECDSA curves, and RFC 8080 §6.1 for Ed25519. Each RRSIG's
//! signed data is built here as RFC 4034 §3.1.8.1 defines it, each signature must verify, and the
//! same signature over data one octet off must not. The DS records of RFC 6605 §6 and RFC 8080
//! §6.1 check the digests.
const std = @import("std");
const dnssec = @import("dnssec.zig");
const protocol = @import("constants.zig").protocol;
const algorithm_file = @import("algorithm.zig");

const testing = std.testing;
const Algorithm = dnssec.Algorithm;

/// The type numbers of the records the examples sign, in IANA's Resource Record TYPEs registry,
/// and class IN.
const type_a: u16 = 1;
const type_mx: u16 = 15;
const class_in: u16 = 1;
/// A DNSKEY's Protocol field is always 3 (RFC 4034 §2.1.2), and the flags of a zone key alone and
/// of a key that also signs keys (RFC 4034 §2.1.1).
const dnskey_protocol: u8 = 3;
const flags_zone_key: u16 = 256;
const flags_key_signing: u16 = 257;
/// The TTL every example's records carry.
const ttl: u32 = 3600;
/// Room for one example's signed data, or a DS digest's input. Test-only.
const data_len_max: usize = 512;

/// The comptime branches decoding one octet of Base64 takes, at most. Test-only.
const quota_per_octet: u32 = 100;
/// The hexadecimal digits of one octet, and the pieces `check` feeds the data in. Test-only.
const digits_per_octet: usize = 2;
const pieces: usize = 2;

/// The octets of a Base64 text, as the RFCs print keys and signatures, decoded when the test
/// compiles.
fn base64(comptime text: []const u8) [std.base64.standard.Decoder.calcSizeForSlice(text) catch unreachable]u8 {
    @setEvalBranchQuota(text.len * quota_per_octet);
    var octets: [std.base64.standard.Decoder.calcSizeForSlice(text) catch unreachable]u8 = undefined;
    std.base64.standard.Decoder.decode(&octets, text) catch unreachable;
    return octets;
}

/// The octets of a hexadecimal text, decoded when the test compiles.
fn hex(comptime text: []const u8) [text.len / digits_per_octet]u8 {
    var octets: [text.len / digits_per_octet]u8 = undefined;
    _ = std.fmt.hexToBytes(&octets, text) catch unreachable;
    return octets;
}

/// Writes `name`, a domain name without its final dot, in the wire form and lower case RFC 4034
/// §6.2 makes canonical: each label after its length, then the root's empty label.
fn put_name(writer: *std.Io.Writer, name: []const u8) !void {
    var labels = std.mem.splitScalar(u8, name, '.');
    while (labels.next()) |label| {
        try writer.writeByte(@intCast(label.len));
        for (label) |octet| try writer.writeByte(std.ascii.toLower(octet));
    }
    try writer.writeByte(0);
}

/// One RRSIG's fields before its Signature, and the one record of the RRset it covers.
const Signed = struct {
    covered: u16,
    algorithm: Algorithm,
    labels: u8,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer: []const u8,
    owner: []const u8,
    rdata: []const u8,
};

/// RFC 4034 §3.1.8.1: the signed data is the RRSIG's RDATA before its Signature, then each record
/// of the RRset in canonical form, with the RRSIG's Original TTL.
fn signed_data(signed: Signed, out: []u8) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    try writer.writeInt(u16, signed.covered, .big);
    try writer.writeByte(@intFromEnum(signed.algorithm));
    try writer.writeByte(signed.labels);
    try writer.writeInt(u32, ttl, .big);
    try writer.writeInt(u32, signed.expiration, .big);
    try writer.writeInt(u32, signed.inception, .big);
    try writer.writeInt(u16, signed.key_tag, .big);
    try put_name(&writer, signed.signer);
    try put_name(&writer, signed.owner);
    try writer.writeInt(u16, signed.covered, .big);
    try writer.writeInt(u16, class_in, .big);
    try writer.writeInt(u32, ttl, .big);
    try writer.writeInt(u16, @intCast(signed.rdata.len), .big);
    try writer.writeAll(signed.rdata);
    return writer.buffered();
}

/// One example: the signed record, the DNSKEY's Public Key field and the RRSIG's Signature.
const Example = struct {
    signed: Signed,
    key: []const u8,
    signature: []const u8,
};

/// Whether the example's signature verifies over `data`.
fn check(example: Example, data: []const u8) dnssec.Error!void {
    var hash = try dnssec.Hash.init(example.signed.algorithm, example.key, example.signature);
    // The data in two pieces, as a caller that builds it streams it.
    hash.update(data[0 .. data.len / pieces]);
    hash.update(data[data.len / pieces ..]);
    var digest: [protocol.digest_len_max]u8 = undefined;
    return dnssec.verify(example.signed.algorithm, example.key, hash.final(&digest), example.signature);
}

/// The example's signature verifies over its signed data, and not over the data one octet off.
fn expect_verifies(example: Example) !void {
    var room: [data_len_max]u8 = undefined;
    const data = try signed_data(example.signed, &room);
    try check(example, data);
    room[data.len - 1] ^= 1;
    try testing.expectError(error.Auth, check(example, data));
}

test "RFC 5702 §6.1: the RSA/SHA-256 example verifies, and data one octet off does not" {
    if (comptime !algorithm_file.available) return error.SkipZigTest;
    try expect_verifies(.{
        .signed = .{ .covered = type_a, .algorithm = .rsasha256, .labels = 3, .expiration = 1893456000, .inception = 946684800, .key_tag = 9033, .signer = "example.net", .owner = "www.example.net", .rdata = &.{ 192, 0, 2, 91 } },
        .key = &base64("AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk="),
        .signature = &base64("kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg=="),
    });
}

test "RFC 5702 §6.2: the RSA/SHA-512 example verifies, and data one octet off does not" {
    if (comptime !algorithm_file.available) return error.SkipZigTest;
    try expect_verifies(.{
        .signed = .{ .covered = type_a, .algorithm = .rsasha512, .labels = 3, .expiration = 1893456000, .inception = 946684800, .key_tag = 3740, .signer = "example.net", .owner = "www.example.net", .rdata = &.{ 192, 0, 2, 91 } },
        .key = &base64("AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL"),
        .signature = &base64("tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw="),
    });
}

/// The P-256 and P-384 examples' keys (RFC 6605 §6), which their DS records digest too.
const p256_key = base64("GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==");
const p384_key = base64("xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40");

test "RFC 6605 §6.1: the P-256 example verifies, and data one octet off does not" {
    if (comptime !algorithm_file.available) return error.SkipZigTest;
    try expect_verifies(.{
        .signed = .{ .covered = type_a, .algorithm = .ecdsap256sha256, .labels = 3, .expiration = 1284026679, .inception = 1281607479, .key_tag = 55648, .signer = "example.net", .owner = "www.example.net", .rdata = &.{ 192, 0, 2, 1 } },
        .key = &p256_key,
        .signature = &base64("qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw=="),
    });
}

test "RFC 6605 §6.2: the P-384 example verifies, and data one octet off does not" {
    if (comptime !algorithm_file.available) return error.SkipZigTest;
    try expect_verifies(.{
        .signed = .{ .covered = type_a, .algorithm = .ecdsap384sha384, .labels = 3, .expiration = 1284027625, .inception = 1281608425, .key_tag = 10771, .signer = "example.net", .owner = "www.example.net", .rdata = &.{ 192, 0, 2, 1 } },
        .key = &p384_key,
        .signature = &base64("/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm"),
    });
}

/// RFC 8080 §6.1's first Ed25519 key.
const ed25519_key = base64("l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=");

test "RFC 8080 §6.1: the Ed25519 example verifies, and data one octet off does not" {
    if (comptime !algorithm_file.available) return error.SkipZigTest;
    // The MX record RFC 8080 §6.1 signs: preference 10, then mail.example.com in canonical form.
    const mx_rdata = [_]u8{ 0, 10, 4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    // RFC 8080 §6.1 prints the RRSIG without its Algorithm field, which is 15. Its Labels field
    // says 3, though example.com has 2 labels (RFC 4034 §3.1.3), and the signature is over the 3
    // it prints.
    try expect_verifies(.{
        .signed = .{ .covered = type_mx, .algorithm = .ed25519, .labels = 3, .expiration = 1440021600, .inception = 1438207200, .key_tag = 3613, .signer = "example.com", .owner = "example.com", .rdata = &mx_rdata },
        .key = &ed25519_key,
        .signature = &base64("Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkjH5GaMWeG96GUVZu6ECKOQmemHDg=="),
    });
}

/// RFC 4034 §5.1.4: a DS digest is of the DNSKEY owner's canonical name, then the DNSKEY's RDATA.
fn expect_ds(digest_type: dnssec.DigestType, owner: []const u8, flags: u16, algorithm: Algorithm, key: []const u8, expected: []const u8) !void {
    var room: [data_len_max]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&room);
    try put_name(&writer, owner);
    try writer.writeInt(u16, flags, .big);
    try writer.writeByte(dnskey_protocol);
    try writer.writeByte(@intFromEnum(algorithm));
    try writer.writeAll(key);
    var hash = dnssec.Hash.digest(digest_type);
    hash.update(writer.buffered());
    var digest: [protocol.digest_len_max]u8 = undefined;
    try testing.expectEqualSlices(u8, expected, hash.final(&digest));
}

test "RFC 6605 §6 and RFC 8080 §6.1: each DS digest is the one the RFC prints" {
    if (comptime !algorithm_file.available) return error.SkipZigTest;
    try expect_ds(.sha256, "example.net", flags_key_signing, .ecdsap256sha256, &p256_key, &hex("b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17"));
    try expect_ds(.sha384, "example.net", flags_key_signing, .ecdsap384sha384, &p384_key, &hex("72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6"));
    try expect_ds(.sha256, "example.com", flags_key_signing, .ed25519, &ed25519_key, &hex("3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b"));
}

test "decision 142: an algorithm or a digest type colibri cannot check is null" {
    if (comptime !algorithm_file.available) {
        try testing.expectEqual(null, dnssec.algorithm(protocol.algorithm_rsasha256));
        return;
    }
    try testing.expectEqual(Algorithm.rsasha256, dnssec.algorithm(protocol.algorithm_rsasha256).?);
    try testing.expectEqual(Algorithm.ed25519, dnssec.algorithm(protocol.algorithm_ed25519).?);
    // RSA/SHA-1 (5), NSEC3RSASHA1 (7) and Ed448 (16) are not checked.
    for ([_]u8{ 5, 7, 16, 0, 255 }) |number| try testing.expectEqual(null, dnssec.algorithm(number));
    try testing.expectEqual(dnssec.DigestType.sha384, dnssec.digest_type(protocol.digest_sha384).?);
    for ([_]u8{ 0, 3, 5 }) |number| try testing.expectEqual(null, dnssec.digest_type(number));
}

test "RFC 8080 §3 and §4: an Ed25519 key or signature of the wrong length is refused" {
    if (comptime !algorithm_file.available) return error.SkipZigTest;
    const signature: [64]u8 = @splat(0);
    try testing.expectError(error.Invalid, dnssec.Hash.init(.ed25519, ed25519_key[0 .. ed25519_key.len - 1], &signature));
    try testing.expectError(error.Invalid, dnssec.Hash.init(.ed25519, &ed25519_key, signature[0 .. signature.len - 1]));
}
