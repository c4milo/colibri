//! Example: a DNS resolver checks an RRSIG and a DS record with `dnssec` (decision 142).
//!
//! The records are RFC 6605 §6.1's: a P-256 DNSKEY for example.net, the DS record that names it,
//! and the RRSIG over www.example.net's A record. The program builds the RRSIG's signed data
//! itself, as RFC 4034 §3.1.8.1 defines it, and streams it into a `dnssec.Hash`, so no copy of the
//! RRset is made. It checks the DS digest the same way (RFC 4034 §5.1.4). Nothing allocates or
//! does I/O.
//!
//! The program checks that the signature verifies, that one changed octet of the data makes it
//! fail, and that the DS digest is the one the RFC prints. Anything else exits with an error,
//! which is how `zig build examples` and CI know the example still works.
//!
//! Run it with `zig build example-dnssec_check`, or every example with `zig build examples`.
const std = @import("std");
const dnssec = @import("dnssec");

/// chapulin's one hook, which every program that links colibri's chapulin object defines.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}

/// RFC 6605 §6.1: the DNSKEY's flags and key, its key tag, and the RRSIG over the A record.
const key_flags: u16 = 257;
const key_tag: u16 = 55648;
const dnskey_protocol: u8 = 3;
const ttl: u32 = 3600;
const type_a: u16 = 1;
const class_in: u16 = 1;
const labels: u8 = 3;
const expiration: u32 = 1284026679;
const inception: u32 = 1281607479;
const address = [_]u8{ 192, 0, 2, 1 };
const key_text = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";
const signature_text = "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==";
const ds_digest_text = "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17";

/// Room for the signed data and for the DS digest's input.
const data_len_max = 256;

pub fn main() !void {
    var key: [64]u8 = undefined;
    var signature: [64]u8 = undefined;
    try std.base64.standard.Decoder.decode(&key, key_text);
    try std.base64.standard.Decoder.decode(&signature, signature_text);

    // A record names its algorithm and its digest type by number; colibri says whether it can
    // check them.
    const algorithm = dnssec.algorithm(13) orelse return error.AlgorithmUnchecked;
    const digest_type = dnssec.digest_type(2) orelse return error.DigestUnchecked;

    var data: [data_len_max]u8 = undefined;
    const signed = try signed_data(&data, algorithm);
    try check(algorithm, &key, &signature, signed);
    std.debug.print("dnssec_check: the RRSIG over www.example.net/A verifies\n", .{});
    data[signed.len - 1] ^= 1;
    if (check(algorithm, &key, &signature, signed)) |_| return error.ChangedDataVerified else |failure| {
        if (failure != error.SignatureVerificationFailed) return failure;
    }

    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, ds_digest_text);
    var input: [data_len_max]u8 = undefined;
    var ds = dnssec.Hash.digest(digest_type);
    ds.update(try dnskey_of(&input, algorithm, &key));
    var digest: [dnssec.constants.protocol.digest_len_max]u8 = undefined;
    if (!std.mem.eql(u8, &expected, ds.final(&digest))) return error.DigestWrong;
    std.debug.print("dnssec_check: the DS digest of example.net's DNSKEY is the one RFC 6605 prints\n", .{});
}

/// Hashes the signed data under the DNSKEY's key and checks the RRSIG's signature over it.
fn check(algorithm: dnssec.Algorithm, key: []const u8, signature: []const u8, data: []const u8) dnssec.Error!void {
    var hash = try dnssec.Hash.init(algorithm, key, signature);
    hash.update(data);
    var digest: [dnssec.constants.protocol.digest_len_max]u8 = undefined;
    try dnssec.verify(algorithm, key, hash.final(&digest), signature);
}

/// RFC 4034 §3.1.8.1: the RRSIG's RDATA before its Signature, then the A record in canonical form.
fn signed_data(out: []u8, algorithm: dnssec.Algorithm) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    try writer.writeInt(u16, type_a, .big);
    try writer.writeByte(@intFromEnum(algorithm));
    try writer.writeByte(labels);
    try writer.writeInt(u32, ttl, .big);
    try writer.writeInt(u32, expiration, .big);
    try writer.writeInt(u32, inception, .big);
    try writer.writeInt(u16, key_tag, .big);
    try writer.writeAll("\x07example\x03net\x00");
    try writer.writeAll("\x03www\x07example\x03net\x00");
    try writer.writeInt(u16, type_a, .big);
    try writer.writeInt(u16, class_in, .big);
    try writer.writeInt(u32, ttl, .big);
    try writer.writeInt(u16, address.len, .big);
    try writer.writeAll(&address);
    return writer.buffered();
}

/// RFC 4034 §5.1.4: the DNSKEY owner's canonical name, then the DNSKEY's RDATA.
fn dnskey_of(out: []u8, algorithm: dnssec.Algorithm, key: []const u8) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    try writer.writeAll("\x07example\x03net\x00");
    try writer.writeInt(u16, key_flags, .big);
    try writer.writeByte(dnskey_protocol);
    try writer.writeByte(@intFromEnum(algorithm));
    try writer.writeAll(key);
    return writer.buffered();
}
