//! RFC 9001 Appendix A's sample packet protection, through colibri's `crypto.Suite` as chapulin's
//! QUIC object fills it (design §8 step 7, https://github.com/c4milo/colibri/issues/9). Decision
//! 48 has the suite hold every key, so the vectors check the provider through the vtable, from
//! `src/testing/`, where chapulin is linked.
//!
//! One client session covers A.1 to A.4. A session's role is fixed when it starts, and a
//! client's Initial keys are the server's in the other direction (RFC 9001 §5.2), so:
//!   - A.2: the client seals its Initial, and the octets must be the published packet;
//!   - A.3: the client opens the server's published Initial, and must find its header and payload;
//!   - A.4: the Retry Integrity Tag checks, and chapulin writes the published one over the
//!     pseudo-packet colibri builds.
//! A.1's keys are what makes A.2 and A.3 come out octet for octet.
//!
//! A.5 is chapulin's to check, in its own `test/quic_packet_tests.h`: it starts from a 1-RTT
//! secret, and under decision 48 no secret crosses the vtable, so colibri has no way to give one.
//!
//! The hex is copied from `docs/rfcs/rfc9001.txt` line for line, and each constant names the lines.
const std = @import("std");
const quic = @import("quic");
const constants = @import("../constants.zig");
const chapulin_quic_c = @import("chapulin_quic_c.zig");
const chapulin_quic = @import("chapulin_quic.zig");

const c = chapulin_quic_c.c;
const crypto = quic.crypto;
const testing = std.testing;

/// The octets a string of hex digits spells, at compile time.
fn hex(comptime digits: []const u8) [digits.len / hex_digits_per_octet]u8 {
    @setEvalBranchQuota(hex_branches_per_digit * digits.len);
    var octets: [digits.len / hex_digits_per_octet]u8 = undefined;
    _ = std.fmt.hexToBytes(&octets, digits) catch unreachable;
    return octets;
}
const hex_digits_per_octet = 2;
const hex_branches_per_digit = 64;

/// A.1: the Destination Connection ID of the client's first Initial, which the Initial keys
/// derive from (RFC 9001 §5.2).
const client_dcid = hex("8394c8f03e515708");

/// A.2: the CRYPTO frame the client's Initial carries (RFC 9001 lines 2388 to 2395).
const client_crypto_frame = hex("060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" ++
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" ++
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" ++
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" ++
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" ++
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100" ++
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" ++
    "75300901100f088394c8f03e51570806048000ffff");

/// A.2: the client Initial's unprotected header, packet number 2 (RFC 9001 lines 2401 to 2401).
const client_header = hex("c300000001088394c8f03e5157080000449e00000002");

/// A.2: the protected client Initial (RFC 9001 lines 2421 to 2458).
const client_protected = hex("c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" ++
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" ++
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" ++
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" ++
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" ++
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" ++
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" ++
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" ++
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" ++
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" ++
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" ++
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" ++
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" ++
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" ++
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" ++
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" ++
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" ++
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" ++
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" ++
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" ++
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" ++
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" ++
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" ++
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" ++
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" ++
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" ++
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" ++
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" ++
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" ++
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" ++
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" ++
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" ++
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" ++
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" ++
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" ++
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" ++
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" ++
    "e221af44860018ab0856972e194cd934");

/// A.3: the server Initial's payload, an ACK frame and a CRYPTO frame (RFC 9001 lines 2465 to 2468).
const server_payload = hex("02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" ++
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" ++
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" ++
    "020304");

/// A.3: the server Initial's unprotected header, packet number 1 (RFC 9001 lines 2473 to 2473).
const server_header = hex("c1000000010008f067a5502a4262b50040750001");

/// A.3: the protected server Initial (RFC 9001 lines 2484 to 2488).
const server_protected = hex("cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" ++
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" ++
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" ++
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" ++
    "2158407dd074ee");

/// A.4: the Retry packet, its Retry Integrity Tag last (RFC 9001 lines 2497 to 2498).
const retry_packet = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f" ++
    "0f2496ba");

/// A.2: the client's Initial payload is the CRYPTO frame and PADDING frames, 1162 octets in all.
const client_payload_len = 1162;
const client_packet_number = 2;
const client_packet_number_len = 4;
const server_packet_number = 1;

/// A client session with the A.1 connection ID's Initial keys installed, as colibri's client has
/// them before its first packet. Its trust is placeholder octets, which chapulin reads only to
/// judge a server's chain, and these tests receive none. Test-only.
var test_session: chapulin_quic.Session = undefined;
var test_receive: [constants.tls_receive_len]u8 = undefined;
const placeholder_octet: u8 = 0x30;
const placeholder_len = 8;
const placeholder: [placeholder_len]u8 = @splat(placeholder_octet);
/// A P-256 point's length, X||Y, which a raw-pin build takes.
const point_len = 64;
const placeholder_point: [point_len]u8 = @splat(placeholder_octet);
const test_now_seconds: u64 = 1;

fn start_client() !crypto.Suite {
    const seed: [chapulin_quic_c.seed_len]u8 = @splat(0);
    c.ch_drbg_seed(&seed);
    const anchors = [_]chapulin_quic.Anchor{if (chapulin_quic.webpki) .{
        .name = &placeholder,
        .name_len = placeholder.len,
        .spki = &placeholder,
        .spki_len = placeholder.len,
    } else {}};
    const trust: chapulin_quic.Trust = if (chapulin_quic.webpki)
        .{ .webpki = .{ .anchors = &anchors, .hostname = "example.com", .now_seconds = test_now_seconds } }
    else
        .{ .pinned = .{ .public_point = &placeholder_point } };
    test_session.init(.{ .role = .client, .alpn = &.{"hq-interop"}, .receive = &test_receive, .trust = trust });
    try test_session.provider().set_transport_params(&placeholder);
    const suite = test_session.suite();
    try suite.vtable.install_initial_keys(suite.context, .client, &client_dcid);
    return suite;
}

test "RFC 9001 Appendix A.2: the client's Initial is sealed octet for octet" {
    if (!chapulin_quic_c.available) return error.SkipZigTest;
    const suite = try start_client();
    var payload: [client_payload_len]u8 = @splat(0);
    @memcpy(payload[0..client_crypto_frame.len], &client_crypto_frame);
    var output: [client_protected.len]u8 = undefined;
    const written = try suite.seal(.{
        .level = .initial,
        .packet_number = client_packet_number,
        .header = &client_header,
        .packet_number_len = client_packet_number_len,
        .payload = &payload,
    }, &output);
    try testing.expectEqualSlices(u8, &client_protected, output[0..written]);
}

test "RFC 9001 Appendix A.3: the server's Initial opens to its header and payload" {
    if (!chapulin_quic_c.available) return error.SkipZigTest;
    const suite = try start_client();
    var packet = server_protected;
    // The Packet Number field follows the header's Length field, which ends the unprotected part.
    const packet_number_offset = server_header.len - server_packet_number_len;
    const opened = try suite.open(.{
        .level = .initial,
        .packet = &packet,
        .packet_number_offset = packet_number_offset,
        .largest_packet_number = null,
    });
    try testing.expectEqual(server_packet_number, opened.packet_number);
    try testing.expectEqual(server_packet_number_len, opened.packet_number_len);
    try testing.expectEqualSlices(u8, &server_header, packet[0..server_header.len]);
    try testing.expectEqualSlices(u8, &server_payload, packet[server_header.len..][0..opened.payload_len]);
}
const server_packet_number_len = 2;

test "RFC 9001 Appendix A.4: the Retry Integrity Tag over colibri's pseudo-packet" {
    if (!chapulin_quic_c.available) return error.SkipZigTest;
    const suite = try start_client();
    const tag_len = crypto.constants.retry_integrity_tag_len;
    const without_tag = retry_packet[0 .. retry_packet.len - tag_len];
    const tag = retry_packet[retry_packet.len - tag_len ..];
    var pseudo_buffer: [quic.constants.retry_pseudo_packet_len_max]u8 = undefined;
    var pseudo = quic.core.Writer.init(&pseudo_buffer);
    try quic.packet.header_write.write_retry_pseudo_packet(&pseudo, &client_dcid, without_tag);
    try testing.expect(suite.vtable.retry_tag_valid(suite.context, pseudo.written(), tag));
    var written: [tag_len]u8 = undefined;
    try suite.vtable.retry_tag_write(suite.context, pseudo.written(), &written);
    try testing.expectEqualSlices(u8, tag, &written);
    // Another original connection ID is another pseudo-packet, whose tag this is not.
    var other = quic.core.Writer.init(&pseudo_buffer);
    try quic.packet.header_write.write_retry_pseudo_packet(&other, "other-id", without_tag);
    try testing.expect(!suite.vtable.retry_tag_valid(suite.context, other.written(), tag));
}
