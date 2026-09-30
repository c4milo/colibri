//! The tests of the record-mode sessions (`record.zig`), split out for length: a client and a server
//! of the library's TCP object run against each other in memory (`record_test_support.zig`).
const std = @import("std");
const tls_provider = @import("tls_provider");
const chapulin = @import("chapulin_tcp");
const record = @import("record.zig");
const values = @import("../values.zig");
const support = @import("record_test_support.zig");
const random_support = @import("../random_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;
const to_server = &support.to_server;
const to_client = &support.to_client;
const scratch = &support.scratch;

test "a client and a server complete the handshake and report what they chose" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    for ([_]tls_provider.Provider{ client.provider(), server.provider() }) |provider| {
        try testing.expect(provider.vtable.handshake_complete(provider.context));
        // RFC 7301 §3.2: the server selects the first protocol it offers that the client does.
        try testing.expectEqualStrings("h2", provider.vtable.negotiated_alpn(provider.context).?);
        const chosen = provider.vtable.negotiated_parameters(provider.context).?;
        try testing.expectEqual(tls_provider.constants.version_tls_1_3, chosen.version);
        try testing.expect(tls_provider.provider.cipher_suite_admitted(chosen.cipher_suite));
    }
    try testing.expectEqualStrings("localhost", server.sni().?);
    try testing.expect(!client.resumed() and !server.resumed());
}

test "RFC 9846 §9.1: each suite the object holds, named alone in a server's order, carries records" {
    for (support.suites_held) |suite| {
        const order = [_]u16{suite};
        try support.configure(support.web_pki, .{ .suites = support.order_of(&order) });
        try support.handshake_both(null);
        for ([_]tls_provider.Provider{ client.provider(), server.provider() }) |provider| {
            try testing.expectEqual(suite, provider.vtable.negotiated_parameters(provider.context).?.cipher_suite);
        }
        const sender = client.provider();
        const sealed = try sender.vtable.encrypt_record(sender.context, "suite", to_server.free());
        to_server.len += sealed.written;
        try testing.expectEqualStrings("suite", scratch[0..try support.open_all(server.provider(), to_server, scratch)]);
    }
}

test "RFC 9846 §4.2.2: each suite the object holds, offered alone in a client's order, runs" {
    for (support.suites_held) |suite| {
        const order = [_]u16{suite};
        try support.configure(support.offering(&order), .{});
        try support.handshake_both(null);
        for ([_]tls_provider.Provider{ client.provider(), server.provider() }) |provider| {
            try testing.expectEqual(suite, provider.vtable.negotiated_parameters(provider.context).?.cipher_suite);
        }
    }
}

test "chapulin's own order runs AES-256-GCM in an object with AES-GCM, and ChaCha20 in one without" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    for ([_]tls_provider.Provider{ client.provider(), server.provider() }) |provider| {
        try testing.expectEqual(support.default_suite, provider.vtable.negotiated_parameters(provider.context).?.cipher_suite);
    }
}

test "RFC 9846 §5.2: records carry data each way, and a seal takes only what fits" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    const sender = client.provider();
    const receiver = server.provider();
    const sealed = try sender.vtable.encrypt_record(sender.context, "hello", to_server.free());
    try testing.expectEqual(5, sealed.consumed);
    to_server.len += sealed.written;
    try testing.expectEqualStrings("hello", scratch[0..try support.open_all(receiver, to_server, scratch)]);
    // Three records' worth goes out whole into an output that holds them.
    const long: [40_000]u8 = @splat('x');
    const whole = try receiver.vtable.encrypt_record(receiver.context, &long, to_client.free());
    try testing.expectEqual(long.len, whole.consumed);
    to_client.len += whole.written;
    try testing.expectEqual(long.len, try support.open_all(sender, to_client, scratch));
    // An output short of the whole takes what fits, and one that holds no sealed octet takes none.
    var small: [64]u8 = undefined;
    const part = try sender.vtable.encrypt_record(sender.context, &long, &small);
    try testing.expect(part.consumed > 0 and part.consumed < long.len and part.written <= small.len);
    try testing.expectError(error.NoSpaceLeft, sender.vtable.encrypt_record(sender.context, &long, small[0..20]));
    // No plaintext seals nothing, whatever room there is.
    const nothing = try sender.vtable.encrypt_record(sender.context, "", &small);
    try testing.expectEqual(0, nothing.consumed + nothing.written);
}

test "a session reports nothing it chose before its handshake completes" {
    try support.configure(support.web_pki, .{});
    to_server.* = .{};
    to_client.* = .{};
    try client.start(&support.client_config, support.random(), support.now_seconds, null);
    try server.start(&support.server_config, support.random(), support.now_seconds);
    to_server.len += (try client.handshake(&.{}, to_server.free())).written;
    // The server has read the ClientHello and chosen, and waits for the client's Finished.
    const flight = try server.handshake(to_server.held(), to_client.free());
    try testing.expect(!flight.complete);
    const provider = server.provider();
    try testing.expect(!provider.vtable.handshake_complete(provider.context));
    try testing.expectEqual(null, provider.vtable.negotiated_alpn(provider.context));
    try testing.expectEqual(null, provider.vtable.negotiated_parameters(provider.context));
    var exported: [32]u8 = undefined;
    try testing.expectError(error.HandshakeIncomplete, provider.vtable.export_keying_material(provider.context, "EXPORTER-test", null, &exported));
}

test "RFC 9846 §5.1: a record not yet whole is incomplete, and a short plaintext buffer is refused" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    const sender = client.provider();
    const receiver = server.provider();
    const sealed = try sender.vtable.encrypt_record(sender.context, "abcdef", to_server.free());
    const opened = try receiver.vtable.decrypt_record(receiver.context, to_server.octets[0 .. sealed.written - 1], scratch);
    try testing.expectEqual(tls_provider.Content.incomplete, opened.content);
    try testing.expectEqual(0, opened.consumed);
    try testing.expectError(error.NoSpaceLeft, receiver.vtable.decrypt_record(receiver.context, to_server.octets[0..sealed.written], scratch[0..2]));
}

test "RFC 9846 §6: a record that does not authenticate fails, and its alert is owed to the peer" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    const sender = client.provider();
    const receiver = server.provider();
    // A live session has raised nothing, and asking does not use up what a failure leaves.
    try testing.expectEqual(null, receiver.vtable.take_alert(receiver.context));
    const sealed = try sender.vtable.encrypt_record(sender.context, "tampered", to_server.free());
    to_server.octets[sealed.written - 1] ^= 1;
    try testing.expectError(error.TlsFailed, receiver.vtable.decrypt_record(receiver.context, to_server.octets[0..sealed.written], scratch));
    const local = receiver.vtable.take_alert(receiver.context).?;
    try testing.expectEqual(tls_provider.Alert.bad_record_mac, local.description);
    try testing.expectEqual(tls_provider.AlertReport.Origin.local, local.origin);
    try testing.expectEqual(null, receiver.vtable.take_alert(receiver.context));
    // The alert chapulin sent from inside the read goes out through `handshake_write`, whole and
    // once, and the peer's read fails on it.
    var short: [1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, receiver.vtable.handshake_write(receiver.context, &short, 0));
    const written = try receiver.vtable.handshake_write(receiver.context, to_client.free(), 0);
    try testing.expectEqual(chapulin.record.alert_record_len, written);
    to_client.len += written;
    try testing.expectEqual(0, try receiver.vtable.handshake_write(receiver.context, to_client.free(), 0));
    try testing.expectError(error.TlsFailed, sender.vtable.decrypt_record(sender.context, to_client.held(), scratch));
    // RFC 9846 §6.2: the peer names the alert it received, and sends none in answer.
    const received = sender.vtable.take_alert(sender.context).?;
    try testing.expectEqual(tls_provider.Alert.bad_record_mac, received.description);
    try testing.expectEqual(tls_provider.AlertReport.Origin.peer, received.origin);
    try testing.expectEqual(null, sender.vtable.take_alert(sender.context));
}

test "RFC 9846 §6.1: close_notify goes out once, reaches the peer, and the peer still writes" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    const closing = client.provider();
    const peer = server.provider();
    var short: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, closing.vtable.send_close_notify(closing.context, &short));
    const written = try closing.vtable.send_close_notify(closing.context, to_server.free());
    try testing.expect(written > 0);
    to_server.len += written;
    try testing.expectEqual(0, try closing.vtable.send_close_notify(closing.context, to_server.free()));
    // Once sent, there is nothing more to send, whatever the room.
    try testing.expectEqual(0, try closing.vtable.send_close_notify(closing.context, &short));
    const opened = try peer.vtable.decrypt_record(peer.context, to_server.held(), scratch);
    try testing.expectEqual(tls_provider.Content.alert, opened.content);
    const report = peer.vtable.take_alert(peer.context).?;
    try testing.expectEqual(tls_provider.Alert.close_notify, report.description);
    try testing.expectEqual(tls_provider.AlertReport.Origin.peer, report.origin);
    try testing.expectEqual(null, peer.vtable.take_alert(peer.context));
    const sealed = try peer.vtable.encrypt_record(peer.context, "after", to_client.free());
    try testing.expectEqual(5, sealed.consumed);
}

test "RFC 9846 §4.7.1: the server's ticket resumes a later connection, and a stale one is refused" {
    try support.configure(support.web_pki, .{ .tickets = true });
    try support.handshake_both(null);
    // The ticket rides a record after the handshake, which the client opens.
    const receiver = client.provider();
    const opened = try receiver.vtable.decrypt_record(receiver.context, to_client.held(), scratch);
    try testing.expectEqual(tls_provider.Content.new_session_ticket, opened.content);
    var ticket = client.take_ticket().?;
    defer ticket.wipe();
    try testing.expectEqual(null, client.take_ticket());
    try testing.expect(ticket.lifetime_s > 0 and ticket.psk_len > 0);
    client.close();
    server.close();
    try support.handshake_both(.{ .ticket = &ticket, .age_ms = support.ms_per_second });
    try testing.expect(client.resumed() and server.resumed());
    // Closing wipes the copy of the ticket the connection offered.
    client.close();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&client.offered), 0));
    const stale_ms = (@as(u64, ticket.lifetime_s) + 1) * support.ms_per_second;
    try testing.expectError(error.Refused, client.start(&support.client_config, support.random(), support.now_seconds, .{ .ticket = &ticket, .age_ms = stale_ms }));
    // A TCP connection's ticket names no QUIC version, and chapulin's decision 79 keeps a QUIC
    // connection's ticket off TCP.
    try testing.expectEqual(0, ticket.quic_version);
    var from_quic = ticket;
    from_quic.quic_version = 1;
    try testing.expectError(error.Refused, client.start(&support.client_config, support.random(), support.now_seconds, .{ .ticket = &from_quic, .age_ms = 0 }));
}

test "RFC 9846 §7.5: both sides export the same keying material" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    var from_client: [32]u8 = undefined;
    var from_server: [32]u8 = undefined;
    const sides = [_]tls_provider.Provider{ client.provider(), server.provider() };
    try sides[0].vtable.export_keying_material(sides[0].context, "EXPORTER-test", null, &from_client);
    try sides[1].vtable.export_keying_material(sides[1].context, "EXPORTER-test", null, &from_server);
    try testing.expectEqualSlices(u8, &from_client, &from_server);
    var too_long: [256]u8 = undefined;
    try testing.expectError(error.OutputTooLong, sides[0].vtable.export_keying_material(sides[0].context, "EXPORTER-test", null, &too_long));
    // chapulin takes a label as a C string of at most `CH_EXPORT_LABEL_MAX` octets, and refuses an
    // empty one itself.
    try testing.expectError(error.Unsupported, sides[0].vtable.export_keying_material(sides[0].context, "", null, &from_client));
    try testing.expectError(error.Unsupported, sides[0].vtable.export_keying_material(sides[0].context, "EXPORTER\x00", null, &from_client));
    const long_label: [chapulin.c.CH_EXPORT_LABEL_MAX + 1]u8 = @splat('x');
    try testing.expectError(error.Unsupported, sides[0].vtable.export_keying_material(sides[0].context, &long_label, null, &from_client));
    // An empty output asks for nothing, which it gets.
    try sides[0].vtable.export_keying_material(sides[0].context, "EXPORTER-test", null, from_client[0..0]);
}

test "RFC 9846 §6: a chain no anchor signed, or one outside its validity, fails with an alert" {
    // The leaf's own key is no anchor of the chain.
    const impostor = [_]values.Anchor{.{ .subject = support.root_name, .spki = support.public_key }};
    try support.configure(.{ .trust = .{ .web_pki = .{ .anchors = &impostor, .server_name = "localhost" } }, .alpn = &support.protocols, .aes_instructions = support.aes_instructions }, .{});
    try testing.expectError(error.HandshakeFailed, support.handshake_both(null));
    try testing.expect(client.alert() != null);
    // A second before the identity's notBefore and a second after its notAfter, the leaf "has
    // expired or is not currently valid", which is certificate_expired (RFC 9846 §6.2).
    for ([_]u64{ support.not_before_seconds - 1, support.not_after_seconds + 1 }) |seconds| {
        try support.configure(support.web_pki, .{});
        try testing.expectError(error.HandshakeFailed, support.handshake_at(seconds, null));
        try testing.expectEqual(@intFromEnum(tls_provider.Alert.certificate_expired), client.alert().?);
    }
    // A clock of 0 with anchors is no clock at all.
    try testing.expectError(error.Refused, client.start(&support.client_config, support.random(), 0, null));
}

test "the identity is valid at its notBefore and at its notAfter, so any instant between works" {
    for ([_]u64{ support.not_before_seconds, support.now_seconds, support.not_after_seconds }) |seconds| {
        try support.configure(support.web_pki, .{});
        try support.handshake_at(seconds, null);
    }
}

test "a pin of the server's key authenticates it with no anchor, clock or name" {
    // The DER SubjectPublicKeyInfo of a P-256 key is this prefix, then the point X||Y.
    const spki_prefix = [_]u8{
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    };
    var pin: values.Pin = undefined;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(&spki_prefix);
    hash.update(support.public_key);
    hash.final(&pin);
    try support.configure(.{ .trust = .{ .pins = .{ .pins = &.{pin} } }, .alpn = &support.protocols, .aes_instructions = support.aes_instructions }, .{});
    try support.handshake_both(null);
    // No server_name was sent.
    try testing.expectEqual(null, server.sni());
    // Pins alone read the leaf alone, however long the chain after it (chapulin `e802399`).
    const long_chain = [_][]const u8{support.leaf} ++ [_][]const u8{support.root} ** 15;
    try support.server_config.init(.{
        .ecdsa_p256 = .{ .chain = &long_chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .alpn = &support.protocols,
        .aes_instructions = support.aes_instructions,
    });
    try support.handshake_both(null);
    // Another key's pin fails the handshake.
    pin[0] ^= 1;
    try support.configure(.{ .trust = .{ .pins = .{ .pins = &.{pin} } }, .alpn = &support.protocols, .aes_instructions = support.aes_instructions }, .{});
    try testing.expectError(error.HandshakeFailed, support.handshake_both(null));
}

test "a ClientHello longer than the output goes out over several calls, and nothing is read before it" {
    try support.configure(support.web_pki, .{});
    to_server.* = .{};
    to_client.* = .{};
    try client.start(&support.client_config, support.random(), support.now_seconds, null);
    var piece: [100]u8 = undefined;
    var progress = try client.handshake(&.{}, &piece);
    try testing.expectEqual(piece.len, progress.written);
    // A record offered while the ClientHello is still owed is left for a later call.
    var early = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x00 };
    progress = try client.handshake(&early, piece[0..0]);
    try testing.expectEqual(0, progress.consumed + progress.written);
    // The rest arrives in pieces, and ends when a call writes less than it could.
    @memcpy(to_server.free()[0..piece.len], &piece);
    to_server.len += piece.len;
    for (0..support.wire_len / piece.len) |_| {
        progress = try client.handshake(&.{}, &piece);
        @memcpy(to_server.free()[0..progress.written], piece[0..progress.written]);
        to_server.len += progress.written;
        if (progress.written < piece.len) break;
    }
    // The server reads the ClientHello whole, which it would refuse had any octet changed.
    try server.start(&support.server_config, support.random(), support.now_seconds);
    const flight = try server.handshake(to_server.held(), to_client.free());
    try testing.expectEqual(to_server.len, flight.consumed);
    try testing.expect(flight.written > 0);
}

test "a ClientHello that offers a ticket goes out whole into `handshake_output_len_min` octets" {
    try support.configure(support.web_pki, .{ .tickets = true });
    try support.handshake_both(null);
    const receiver = client.provider();
    _ = try receiver.vtable.decrypt_record(receiver.context, to_client.held(), scratch);
    var ticket = client.take_ticket().?;
    defer ticket.wipe();
    client.close();
    server.close();
    try client.start(&support.client_config, support.random(), support.now_seconds, .{ .ticket = &ticket, .age_ms = support.ms_per_second });
    var output: [record.Client.handshake_output_len_min]u8 = undefined;
    const hello = try client.handshake(&.{}, &output);
    // A call that writes less than its output holds has taken all the client staged.
    try testing.expect(hello.written > 0 and hello.written < output.len);
    try testing.expect(!client.owed);
}

test "a server whose output cannot hold its flight fails the handshake" {
    try support.configure(support.web_pki, .{});
    to_server.* = .{};
    try client.start(&support.client_config, support.random(), support.now_seconds, null);
    to_server.len += (try client.handshake(&.{}, to_server.free())).written;
    try server.start(&support.server_config, support.random(), support.now_seconds);
    var short: [64]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, server.handshake(to_server.held(), &short));
}

/// `count` ALPN protocol names, each different: "p0", "p1", and on.
fn distinct_protocols(comptime count: usize) [count][]const u8 {
    var names: [count][]const u8 = undefined;
    for (&names, 0..) |*name, index| name.* = std.fmt.comptimePrint("p{d}", .{index});
    return names;
}

test "a list longer than the one it is copied into is refused when it is converted" {
    const config = &support.client_config;
    // The limits a caller bounds its lists by: at the limit a list converts, and past it it does not.
    const anchors_max = record.ClientConfig.anchors_max;
    const most_anchors = [_]values.Anchor{support.anchors[0]} ** anchors_max;
    try config.init(.{ .trust = .{ .web_pki = .{ .anchors = &most_anchors, .server_name = "a" } }, .alpn = &support.protocols, .aes_instructions = support.aes_instructions });
    // A session starts from it, so chapulin takes that many too.
    try client.start(config, support.random(), support.now_seconds, null);
    client.close();
    const many_anchors = [_]values.Anchor{support.anchors[0]} ** (anchors_max + 1);
    try testing.expectError(error.TooManyAnchors, config.init(.{ .trust = .{ .web_pki = .{ .anchors = &many_anchors, .server_name = "a" } }, .alpn = &support.protocols, .aes_instructions = support.aes_instructions }));
    // chapulin refuses a protocol named twice, so each name differs.
    const most_protocols = comptime distinct_protocols(record.ClientConfig.protocols_max);
    try config.init(.{ .trust = support.web_pki.trust, .alpn = &most_protocols, .aes_instructions = support.aes_instructions });
    try client.start(config, support.random(), support.now_seconds, null);
    client.close();
    const many_protocols = [_][]const u8{"h2"} ** (record.ClientConfig.protocols_max + 1);
    try testing.expectError(error.TooManyProtocols, config.init(.{ .trust = support.web_pki.trust, .alpn = &many_protocols, .aes_instructions = support.aes_instructions }));
    const server_config = &support.server_config;
    const server_most = comptime distinct_protocols(record.ServerConfig.protocols_max);
    try server_config.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .alpn = &server_most,
        .aes_instructions = support.aes_instructions,
    });
    try server.start(server_config, support.random(), support.now_seconds);
    server.close();
    const server_protocols = [_][]const u8{"h2"} ** (record.ServerConfig.protocols_max + 1);
    try testing.expectError(error.TooManyProtocols, server_config.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .alpn = &server_protocols,
        .aes_instructions = support.aes_instructions,
    }));
    const long_chain = [_][]const u8{support.leaf} ** 17;
    try testing.expectError(error.TooManyCertificates, server_config.init(.{
        .ecdsa_p256 = .{ .chain = &long_chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .alpn = &support.protocols,
        .aes_instructions = support.aes_instructions,
    }));
    const many_suites = [_]u16{support.chacha} ** 4;
    // An object without AES-GCM has no order to set at all (decision 97).
    const refused = if (support.aes_gcm) error.TooManySuites else error.SuitesUnavailable;
    try testing.expectError(refused, server_config.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .alpn = &support.protocols,
        .aes_instructions = support.aes_instructions,
        .cipher_suites = &many_suites,
    }));
    var many_offered = support.web_pki;
    many_offered.cipher_suites = &many_suites;
    try testing.expectError(refused, support.client_config.init(many_offered));
}

test "a rule of chapulin's is chapulin's to report, when a session starts or a server is checked" {
    // chapulin's `webpki_cfg.h` takes at most `CH_SPKI_PIN_MAX` pins.
    const many_pins = [_]values.Pin{@splat(1)} ** 5;
    try support.client_config.init(.{ .trust = .{ .pins = .{ .pins = &many_pins } }, .alpn = &support.protocols, .aes_instructions = support.aes_instructions });
    try testing.expectError(error.Refused, client.start(&support.client_config, support.random(), support.now_seconds, null));
    // chapulin's `webpki_cfg.h` refuses a client order that names a suite twice.
    if (support.aes_gcm) {
        const repeated = [_]u16{ support.chacha, support.chacha };
        var twice = support.web_pki;
        twice.cipher_suites = &repeated;
        try support.client_config.init(twice);
        try testing.expectError(error.Refused, client.start(&support.client_config, support.random(), support.now_seconds, null));
    }
    // A server with no identity has no key to check, and none to serve from.
    try support.server_config.init(.{ .cookie_key = &support.cookie_key, .alpn = &support.protocols, .aes_instructions = support.aes_instructions });
    try testing.expectError(error.IdentityRefused, support.server_config.check(support.random()));
    try testing.expectError(error.Refused, server.start(&support.server_config, support.random(), support.now_seconds));
    // No protocol offered is no ALPN extension, which a client that speaks h11 alone may send.
    try support.client_config.init(.{ .trust = support.web_pki.trust, .alpn = &.{}, .aes_instructions = support.aes_instructions });
    try support.server_config.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .alpn = &support.protocols,
        .aes_instructions = support.aes_instructions,
    });
    try support.handshake_both(null);
    try testing.expectEqual(null, client.provider().vtable.negotiated_alpn(client.provider().context));
}

test "a server's identity passes chapulin's check, and a key that does not match fails it" {
    try support.configure(support.web_pki, .{});
    try support.server_config.check(support.random());
    const wrong_key: [32]u8 = @splat(0x42);
    try support.server_config.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = &wrong_key },
        .cookie_key = &support.cookie_key,
        .alpn = &support.protocols,
        .aes_instructions = support.aes_instructions,
    });
    try testing.expectError(error.IdentityRefused, support.server_config.check(support.random()));
}

/// What a client and a server whose sources start at one seed write first: the ClientHello, and
/// the server's flight that answers it.
const FirstFlights = struct {
    hello: [record.Client.handshake_output_len_min]u8 = undefined,
    hello_len: usize = 0,
    flight: [support.wire_len]u8 = undefined,
    flight_len: usize = 0,
};

fn first_flights(client_seed: u64, server_seed: u64, flights: *FirstFlights) !void {
    var client_stream: random_support.Stream = .{ .state = client_seed };
    var server_stream: random_support.Stream = .{ .state = server_seed };
    try client.start(&support.client_config, client_stream.random(), support.now_seconds, null);
    defer client.close();
    try server.start(&support.server_config, server_stream.random(), support.now_seconds);
    defer server.close();
    flights.hello_len = (try client.handshake(&.{}, &flights.hello)).written;
    to_server.* = .{};
    @memcpy(to_server.free()[0..flights.hello_len], flights.hello[0..flights.hello_len]);
    to_server.len = flights.hello_len;
    flights.flight_len = (try server.handshake(to_server.held(), &flights.flight)).written;
}

test "decision 94: each session draws from its caller's source alone, so one seed replays it" {
    try support.configure(support.web_pki, .{});
    const seed = random_support.seed;
    var first: FirstFlights = .{};
    var again: FirstFlights = .{};
    var client_other: FirstFlights = .{};
    var server_other: FirstFlights = .{};
    try first_flights(seed, seed, &first);
    try first_flights(seed, seed, &again);
    try first_flights(seed +% 1, seed, &client_other);
    try first_flights(seed, seed +% 1, &server_other);
    try testing.expectEqualSlices(u8, first.hello[0..first.hello_len], again.hello[0..again.hello_len]);
    try testing.expectEqualSlices(u8, first.flight[0..first.flight_len], again.flight[0..again.flight_len]);
    // Another seed for one side changes what that side writes, and the same hello for the other.
    try testing.expect(!std.mem.eql(u8, first.hello[0..first.hello_len], client_other.hello[0..client_other.hello_len]));
    try testing.expectEqualSlices(u8, first.hello[0..first.hello_len], server_other.hello[0..server_other.hello_len]);
    try testing.expect(!std.mem.eql(u8, first.flight[0..first.flight_len], server_other.flight[0..server_other.flight_len]));
}
