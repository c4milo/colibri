//! The null suite's Retry answers: RFC 9001 §5.8's Integrity Tag and RFC 9000 §8.1.1's address
//! validation token. Split off `null_suite.zig` for length; it is the same suite, and no more
//! cryptography than the rest of it.
const std = @import("std");
const core = @import("core");
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
/// secret. It holds a type octet, a checksum of the address, the instant it expires at, and the two
/// connection IDs decision 55 has a Retry token carry, every integer in network byte order so one
/// host's octets are every host's (invariant 5). It proves the shape and nothing else, like every
/// other answer this suite gives.
pub fn token_write(
    context: *anyopaque,
    address: []const u8,
    ids: *const crypto.suite.RetryConnectionIds,
    now_ns: u64,
    output: []u8,
) crypto.suite.TokenError!usize {
    if (!null_suite.from(context).mints_retry_token) return error.Unsupported;
    var writer = core.Writer.init(output);
    write_token(&writer, address, ids, now_ns) catch return error.NoSpaceLeft;
    return writer.written().len;
}

fn write_token(writer: *core.Writer, address: []const u8, ids: *const crypto.suite.RetryConnectionIds, now_ns: u64) core.writer.Error!void {
    // §8.1.1: a server tells a Retry's token from a NEW_TOKEN frame's, so every token says which.
    try writer.write_byte(constants.null_suite_retry_token_type);
    try writer.write_int(u32, Crc32.hash(address));
    // §8.1.4: "Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a
    // short time", which is an instant written into the token rather than a clock read later.
    try writer.write_int(u64, now_ns +| constants.null_suite_retry_token_lifetime_ns);
    try writer.write_byte(ids.original_destination_len);
    try writer.write_bytes(ids.original_destination_slice());
    try writer.write_byte(ids.retry_source_len);
    try writer.write_bytes(ids.retry_source_slice());
}

pub fn token_check(context: *const anyopaque, address: []const u8, token: []const u8, now_ns: u64) crypto.suite.TokenCheck {
    _ = context;
    var reader = core.Reader.init(token);
    const kind = reader.read_byte() catch return .not_retry;
    // §8.1.3: a token that is not a Retry token leaves the server as if it had none.
    if (kind != constants.null_suite_retry_token_type) return .not_retry;
    return read_retry_token(&reader, address, now_ns) catch .invalid;
}

/// The rest of a Retry token, once its type octet has said it is one. Anything that does not read
/// back whole is a token the client changed, which §8.1.2 answers with INVALID_TOKEN.
fn read_retry_token(reader: *core.Reader, address: []const u8, now_ns: u64) !crypto.suite.TokenCheck {
    const name = try reader.read_int(u32);
    const expires_ns = try reader.read_int(u64);
    const original_destination = try read_connection_id(reader);
    const retry_source = try read_connection_id(reader);
    if (reader.remaining_len() != 0) return .invalid;
    // §8.1.4: a token is accepted for the address it was written for and no other.
    if (name != Crc32.hash(address)) return .invalid;
    // §8.1.4: and only for a short time.
    if (now_ns >= expires_ns) return .invalid;
    return .{ .retry = crypto.suite.RetryConnectionIds.of(original_destination, retry_source) };
}

fn read_connection_id(reader: *core.Reader) ![]const u8 {
    const len = try reader.read_byte();
    // RFC 9000 §17.2: a connection ID is at most 20 octets.
    if (len > crypto.constants.connection_id_len_max) return error.ConnectionIdTooLong;
    return reader.take(len);
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

test "RFC 9000 §8.1.4: a token checks for its address, within its lifetime, and gives its IDs back" {
    var suite_under_test: NullSuite = .{};
    const vtable = suite_under_test.suite().vtable;
    const ids = crypto.suite.RetryConnectionIds.of("original", "retry");
    var token: [crypto.constants.connection_id_len_max * 2 + 16]u8 = undefined;
    const now_ns: u64 = 5_000;
    const len = try vtable.retry_token_write(&suite_under_test, "address", &ids, now_ns, &token);
    const written = token[0..len];
    const checked = vtable.retry_token_check(&suite_under_test, "address", written, now_ns).retry;
    try testing.expectEqualStrings("original", checked.original_destination_slice());
    try testing.expectEqualStrings("retry", checked.retry_source_slice());
    // Another address, an expired lifetime, a changed octet and a cut-short token all fail.
    try testing.expectEqual(.invalid, vtable.retry_token_check(&suite_under_test, "other", written, now_ns));
    const expired_ns = now_ns + constants.null_suite_retry_token_lifetime_ns;
    try testing.expectEqual(.invalid, vtable.retry_token_check(&suite_under_test, "address", written, expired_ns));
    try testing.expectEqual(.invalid, vtable.retry_token_check(&suite_under_test, "address", written[0 .. len - 1], now_ns));
    token[len] = 0;
    try testing.expectEqual(.invalid, vtable.retry_token_check(&suite_under_test, "address", token[0 .. len + 1], now_ns));
    written[1] ^= 1;
    try testing.expectEqual(.invalid, vtable.retry_token_check(&suite_under_test, "address", written, now_ns));
    // §8.1.3: a token of another type, or none, is no Retry token.
    written[0] +%= 1;
    try testing.expectEqual(.not_retry, vtable.retry_token_check(&suite_under_test, "address", written, now_ns));
    try testing.expectEqual(.not_retry, vtable.retry_token_check(&suite_under_test, "address", "", now_ns));
    // A suite that offers no Retry mints nothing, and a buffer too short holds nothing.
    try testing.expectError(error.NoSpaceLeft, vtable.retry_token_write(&suite_under_test, "address", &ids, now_ns, token[0..3]));
    suite_under_test.mints_retry_token = false;
    try testing.expectError(error.Unsupported, vtable.retry_token_write(&suite_under_test, "address", &ids, now_ns, &token));
}
