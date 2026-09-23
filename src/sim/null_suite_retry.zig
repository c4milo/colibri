//! The null suite's Retry answers: RFC 9001 §5.8's Integrity Tag and RFC 9000 §8.1.1's address
//! validation token. Split off `null_suite.zig` for length; it is the same suite, and no more
//! cryptography than the rest of it.
const std = @import("std");
const crypto = @import("crypto");
const constants = @import("constants.zig");
const null_suite = @import("null_suite.zig");
const null_suite_keys = @import("null_suite_keys.zig");

const Crc32 = std.hash.Crc32;
const tag_len = null_suite_keys.tag_len;
const write_tag = null_suite_keys.write_tag;

pub fn tag_valid(context: *const anyopaque, pseudo_packet: []const u8, tag: *const [tag_len]u8) bool {
    _ = context;
    var expected: [tag_len]u8 = undefined;
    write_tag(&expected, constants.null_suite_retry_name, 0, pseudo_packet, pseudo_packet.len);
    return std.mem.eql(u8, &expected, tag);
}

pub fn tag_write(context: *const anyopaque, pseudo_packet: []const u8, tag: *[tag_len]u8) crypto.suite.RetryTagError!void {
    if (!null_suite.from_const(context).writes_retry_tag) return error.Unsupported;
    write_tag(tag, constants.null_suite_retry_name, 0, pseudo_packet, pseudo_packet.len);
}

/// RFC 9000 §8.1.4: the token is "covered by integrity protection against modification or
/// falsification by clients" and bound to the client's address. This one is neither protected nor
/// secret — it is a checksum of the address and the instant it expires at, written in network
/// byte order so one host's octets are every host's (invariant 5). It proves the shape and
/// nothing else, like every other answer this suite gives.
pub fn token_write(context: *anyopaque, address: []const u8, now_ns: u64, output: []u8) crypto.suite.TokenError!usize {
    if (!null_suite.from(context).mints_retry_token) return error.Unsupported;
    const len = constants.null_suite_retry_token_len;
    if (output.len < len) return error.NoSpaceLeft;
    const name = std.mem.nativeToBig(u32, Crc32.hash(address));
    @memcpy(output[0..@sizeOf(u32)], std.mem.asBytes(&name));
    // §8.1.4: "Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a
    // short time", which is an instant written into the token rather than a clock read later.
    const expires = std.mem.nativeToBig(u64, now_ns +| constants.null_suite_retry_token_lifetime_ns);
    @memcpy(output[@sizeOf(u32)..len], std.mem.asBytes(&expires));
    return len;
}

pub fn token_valid(context: *const anyopaque, address: []const u8, token: []const u8, now_ns: u64) bool {
    _ = context;
    if (token.len != constants.null_suite_retry_token_len) return false;
    const name = std.mem.nativeToBig(u32, Crc32.hash(address));
    // §8.1.4: a token is accepted for the address it was written for and no other.
    if (!std.mem.eql(u8, token[0..@sizeOf(u32)], std.mem.asBytes(&name))) return false;
    const expires = std.mem.readInt(u64, token[@sizeOf(u32)..][0..@sizeOf(u64)], .big);
    return now_ns < expires;
}

const testing = std.testing;
const NullSuite = null_suite.NullSuite;
/// RFC 9001 Appendix A's Destination Connection ID, which the pseudo-packet carries. Test-only.
const sample_dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";

/// The tag the test below produced on the host that wrote it, macOS on arm64, and must produce on
/// every other. It pins that the null suite's octets do not vary by host; it says nothing about
/// whether they are good ones. Test-only.
const retry_tag_expected = "\x50\x0d\xea\xf3\x9f\x93\xfd\x3b\x14\x40\xc3\x22\xdb\xde\xd4\xea".*;

test "§5.8: the Retry tag is a function of the pseudo-packet, and a suite may decline to write it" {
    var suite_under_test: NullSuite = .{};
    const vtable = suite_under_test.suite().vtable;
    var tag: [tag_len]u8 = undefined;
    try vtable.retry_tag_write(&suite_under_test, "\x08" ++ sample_dcid ++ "retry", &tag);
    try testing.expect(vtable.retry_tag_valid(&suite_under_test, "\x08" ++ sample_dcid ++ "retry", &tag));
    try testing.expect(!vtable.retry_tag_valid(&suite_under_test, "\x08" ++ sample_dcid ++ "retrz", &tag));
    // One host's tag is every host's: the checksums are taken over octets in network order.
    try testing.expectEqualSlices(u8, &retry_tag_expected, &tag);
    suite_under_test.writes_retry_tag = false;
    try testing.expectError(error.Unsupported, vtable.retry_tag_write(&suite_under_test, "retry", &tag));
}
