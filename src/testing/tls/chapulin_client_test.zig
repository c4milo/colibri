//! The tests of `chapulin_client.zig`, split out because a hand-written source file stays at or
//! under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const tls = @import("tls");
const constants = @import("../constants.zig");
const chapulin = @import("chapulin.zig");
const chapulin_client = @import("chapulin_client.zig");

const c = chapulin.c;
const testing = std.testing;
const Client = chapulin_client.Client;
const Io = chapulin_client.Io;
const send = chapulin_client.send;
const recv = chapulin_client.recv;
const tls_1_3 = chapulin_client.tls_1_3;
const alpn_h2 = chapulin_client.alpn_h2;

/// The client the tests drive, placed outside any stack frame: it carries chapulin's session,
/// which is larger than a stack frame should hold.
var test_client: Client = undefined;
const test_hostname = "localhost";
/// An instant inside any certificate a test would use. A constant because no file under `src/`
/// may read a clock.
const test_now_seconds: u64 = 1_780_000_000;
/// The receive buffer the tests lend the client.
var test_receive: [constants.tls_receive_len]u8 = undefined;

test "the configuration colibri builds is the one chapulin is given" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{
        .anchors = &anchors,
        .hostname = test_hostname,
        .socket = 0,
        .now_seconds = test_now_seconds,
        .receive = &test_receive,
    });
    // RFC 9113 §3.1: one protocol is offered, and it is "h2".
    try testing.expectEqual(1, test_client.config.alpn_count);
    try testing.expectEqual(alpn_h2.len, test_client.config.alpn_protocols[0].name_len);
    try testing.expectEqualSlices(u8, "h2", test_client.config.alpn_protocols[0].name[0..2]);
    // The receive buffer is colibri's storage, and chapulin advertises its size to the peer.
    try testing.expectEqual(constants.tls_receive_len, test_client.config.buf_len);
    try testing.expectEqual(@intFromPtr(&test_receive), @intFromPtr(test_client.config.buf));
    // The hostname is the one the certificate must carry.
    try testing.expectEqual(test_hostname.len, test_client.config.hostname_len);
    // The callbacks point at this file, and their state at the phase.
    try testing.expect(test_client.config.send != null);
    try testing.expect(test_client.config.recv != null);
    try testing.expectEqual(Io.socket, std.meta.activeTag(test_client.io));
}

test "the record phase serves colibri's buffers and never the socket" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{
        .anchors = &anchors,
        .hostname = test_hostname,
        .socket = 0,
        .now_seconds = test_now_seconds,
        .receive = &test_receive,
    });
    // Moving to phase 2 is what `handshake` does on success; the descriptor is never used again.
    var input = [_]u8{ 1, 2, 3, 4 };
    var output: [8]u8 = @splat(0);
    test_client.io = .{ .records = .{ .input = &input, .output = &output } };
    // `recv` hands chapulin the octets colibri passed, in order, and stops at the end of them.
    var taken: [4]u8 = @splat(0);
    try testing.expectEqual(2, recv(@ptrCast(&test_client.io), &taken, 2));
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, taken[0..2]);
    try testing.expectEqual(2, recv(@ptrCast(&test_client.io), &taken, 4));
    try testing.expectEqualSlices(u8, &.{ 3, 4 }, taken[0..2]);
    // Past the end it fails rather than blocking, because no callback of chapulin's can say
    // "nothing yet" and colibri only ever passes a whole record.
    try testing.expectEqual(-1, recv(@ptrCast(&test_client.io), &taken, 1));
    // `send` fills colibri's output and refuses to write part of a record into a short one.
    // `send` answers 0 for success, never a count: chapulin reads a positive value as failure.
    const sealed = [_]u8{ 9, 9, 9 };
    try testing.expectEqual(0, send(@ptrCast(&test_client.io), &sealed, 3));
    try testing.expectEqualSlices(u8, &.{ 9, 9, 9 }, output[0..3]);
    try testing.expectEqual(3, test_client.io.records.written);
    try testing.expectEqual(-1, send(@ptrCast(&test_client.io), &sealed, 6));
    try testing.expectEqual(3, test_client.io.records.written);
    try testing.expectEqual(3, test_client.io.records.written);
}

test "the vtable colibri gets answers every member" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{
        .anchors = &anchors,
        .hostname = test_hostname,
        .socket = 0,
        .now_seconds = test_now_seconds,
        .receive = &test_receive,
    });
    const held = test_client.provider();
    var room: [64]u8 = @splat(0);

    // Before the handshake nothing is negotiated. RFC 7301 §3.1's selection arrives in
    // EncryptedExtensions, and chapulin's CH_ALPN_NONE is 255, so a zeroed session must not
    // read as having chosen the protocol at index 0.
    try testing.expect(!held.vtable.handshake_complete(held.context));
    try testing.expectEqual(null, held.vtable.negotiated_alpn(held.context));
    try testing.expectEqual(null, held.vtable.negotiated_parameters(held.context));

    // RFC 8446 §4.6.3 and §4.6.1: chapulin answers a peer's KeyUpdate and NewSessionTicket
    // inside `ch_read`, so colibri owes no handshake octets and consumes none.
    try testing.expectEqual(0, try held.vtable.handshake_write(held.context, &room, 0));
    try testing.expectEqual(0, try held.vtable.handshake_read(held.context, &room, 0));

    // A session that has not failed has no alert to report.
    try testing.expectEqual(null, held.vtable.take_alert(held.context));

    // Every member is mandatory (decision 8), so the two chapulin does not offer refuse rather
    // than being absent.
    const update = held.vtable.initiate_key_update(held.context, .update_not_requested, &room);
    try testing.expectError(error.Unsupported, update);
    const exported = held.vtable.export_keying_material(held.context, "colibri", null, &room);
    try testing.expectError(error.Unsupported, exported);
}

test "once the handshake is done the session reports what it chose" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{
        .anchors = &anchors,
        .hostname = test_hostname,
        .socket = 0,
        .now_seconds = test_now_seconds,
        .receive = &test_receive,
    });
    // What `handshake` does on success. The live handshake is a separate check; this pins what
    // colibri reads afterwards.
    test_client.io = .{ .records = .{} };
    test_client.session.alpn_selected = 0;
    const held = test_client.provider();
    try testing.expect(held.vtable.handshake_complete(held.context));
    try testing.expectEqualStrings("h2", held.vtable.negotiated_alpn(held.context).?);
    // RFC 9113 §9.2: colibri needs both codepoints, and admits this suite (decision 45).
    const negotiated = held.vtable.negotiated_parameters(held.context).?;
    try testing.expectEqual(tls_1_3, negotiated.version);
    try testing.expectEqual(tls.constants.cipher_suite_chacha20_poly1305_sha256, negotiated.cipher_suite);
    // A server that selected nothing leaves colibri with no protocol, which `attach_tls` refuses.
    test_client.session.alpn_selected = c.CH_ALPN_NONE;
    try testing.expectEqual(null, held.vtable.negotiated_alpn(held.context));
}
