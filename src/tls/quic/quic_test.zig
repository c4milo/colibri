//! The tests of the QUIC sessions (`quic.zig`), split out for length: a client and a server of the
//! library's QUIC object run against each other in memory (`quic_test_support.zig`).
const std = @import("std");
const tls_provider = @import("tls_provider");
const crypto = @import("crypto");
const quic = @import("quic.zig");
const values = @import("../values.zig");
const constants = @import("../constants.zig");
const identity = @import("../record/record_test_support.zig");
const support = @import("quic_test_support.zig");
const random_support = @import("../random_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;

/// A payload long enough for RFC 9001 §5.4.2's header protection sample.
const payload = "a payload colibri frames, 32 oct";

test "RFC 9001 §4.1: a client and a server complete the handshake and read each other's parameters" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    for ([_]tls_provider.QuicProvider{ client.provider(), server.provider() }) |provider| {
        try testing.expectEqualStrings("h3", provider.vtable.negotiated_alpn(provider.context).?);
        try testing.expectEqual(null, provider.vtable.take_alert(provider.context));
    }
    // RFC 9001 §8.2: each side's parameters reach the other.
    try testing.expectEqualStrings(support.server_parameters, client.provider().vtable.peer_transport_params(client.provider().context).?);
    try testing.expectEqualStrings(support.client_parameters, server.provider().vtable.peer_transport_params(server.provider().context).?);
    try testing.expectEqualStrings("localhost", server.sni().?);
    try testing.expect(!client.resumed() and !server.resumed());
    // chapulin has no QUIC exporter.
    var exported: [32]u8 = undefined;
    const provider = client.provider();
    try testing.expectError(error.Unsupported, provider.vtable.export_keying_material(provider.context, "EXPORTER-test", null, &exported));
    client.close();
    server.close();
}

test "RFC 9001 §5.2: Initial packets open at the peer, and the wrong role or no start installs nothing" {
    try support.configure(support.web_pki, .{});
    try client.start(&support.client_config, identity.random(), identity.now_seconds, null);
    server.start(&support.server_config, identity.random(), identity.now_seconds);
    const client_suite = client.suite();
    const server_suite = server.suite();
    // Nothing is installed before chapulin's session starts.
    try testing.expect(!client_suite.vtable.keys_available(client_suite.context, .initial, .write));
    try testing.expectError(error.Unsupported, client_suite.vtable.install_initial_keys(client_suite.context, .client, &support.destination_id));
    try client.provider().set_transport_params(support.client_parameters);
    try server.provider().set_transport_params(support.server_parameters);
    try testing.expectError(error.Unsupported, client_suite.vtable.install_initial_keys(client_suite.context, .server, &support.destination_id));
    try client_suite.vtable.install_initial_keys(client_suite.context, .client, &support.destination_id);
    try server_suite.vtable.install_initial_keys(server_suite.context, .server, &support.destination_id);
    try testing.expect(client_suite.vtable.keys_available(client_suite.context, .initial, .write));
    try testing.expect(!client_suite.vtable.keys_available(client_suite.context, .handshake, .write));
    var header_storage: [64]u8 = undefined;
    const header = try support.initial_header(7, payload.len, &header_storage);
    // RFC 9001 §5.7: a level whose keys are not installed opens nothing.
    try testing.expectError(error.KeysUnavailable, server_suite.vtable.open(server_suite.context, .{
        .level = .handshake,
        .packet = support.packet[0 .. header.len + payload.len + crypto.constants.aead_tag_len],
        .packet_number_offset = header.len - support.packet_number_len,
        .largest_packet_number = null,
    }));
    const opened = try support.seal_and_open(client_suite, server_suite, .initial, header, 7, payload, .{});
    try testing.expectEqual(7, opened.packet_number);
    try testing.expectEqual(support.packet_number_len, opened.packet_number_len);
    try testing.expectEqualStrings(payload, support.opened_payload(header.len, opened));
    // RFC 9001 §5.5: a packet that fails to open is dropped.
    const written = try client_suite.vtable.seal(client_suite.context, .{ .level = .initial, .packet_number = 8, .header = header, .packet_number_len = support.packet_number_len, .payload = payload }, &support.packet);
    support.packet[written - 1] ^= 1;
    try testing.expectError(error.Discarded, server_suite.vtable.open(server_suite.context, .{
        .level = .initial,
        .packet = support.packet[0..written],
        .packet_number_offset = header.len - support.packet_number_len,
        .largest_packet_number = 7,
    }));
    // RFC 9001 §4.9: a discarded level's keys are gone in both directions.
    client_suite.vtable.discard_keys(client_suite.context, .initial);
    try testing.expect(!client_suite.vtable.keys_available(client_suite.context, .initial, .write));
    try testing.expect(!client_suite.vtable.keys_available(client_suite.context, .initial, .read));
    try testing.expectError(error.KeysUnavailable, client_suite.vtable.seal(client_suite.context, .{ .level = .initial, .packet_number = 9, .header = header, .packet_number_len = support.packet_number_len, .payload = payload }, &support.packet));
    client.close();
    server.close();
}

test "RFC 9001 §6: 1-RTT packets carry each admitted suite, and a key update is the peer's next keys" {
    for (identity.suites_held) |suite| {
        const order = [_]u16{suite};
        try support.configure(support.web_pki, .{ .suites = identity.order_of(&order) });
        try support.handshake_both(null);
        const client_suite = client.suite();
        const server_suite = server.suite();
        var header_storage: [64]u8 = undefined;
        var header = try support.short_header(0, false, &header_storage);
        var opened = try support.seal_and_open(client_suite, server_suite, .application, header, 0, payload, .{});
        try testing.expectEqualStrings(payload, support.opened_payload(header.len, opened));
        try testing.expectEqual(crypto.suite.KeySet.current, opened.key_set);
        // RFC 9001 §6.1: the client updates, flips its Key Phase bit, and the server opens with
        // its next keys.
        try testing.expect(!client_suite.vtable.key_phase(client_suite.context));
        try client_suite.vtable.update_keys(client_suite.context);
        try testing.expect(client_suite.vtable.key_phase(client_suite.context));
        header = try support.short_header(1, true, &header_storage);
        // The server processed packet 0 in its current phase (RFC 9001 §6.5).
        opened = try support.seal_and_open(client_suite, server_suite, .application, header, 1, payload, .{ .largest = 0, .current_phase_lowest = 0 });
        try testing.expectEqual(crypto.suite.KeySet.next, opened.key_set);
        try testing.expectEqualStrings(payload, support.opened_payload(header.len, opened));
        client_suite.vtable.discard_previous_keys(client_suite.context);
        client.close();
        server.close();
    }
}

test "RFC 9846 §4.2.2: a client's order naming one suite runs it, and chapulin's own runs its first" {
    for (identity.suites_held) |suite| {
        const order = [_]u16{suite};
        var offered = support.web_pki;
        offered.cipher_suites = identity.order_of(&order);
        try support.configure(offered, .{});
        try support.handshake_both(null);
        try testing.expectEqual(suite, try suite_ran(&client.session));
        try testing.expectEqual(suite, try suite_ran(&server.session));
        client.close();
        server.close();
    }
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    try testing.expectEqual(identity.default_suite, try suite_ran(&client.session));
    try testing.expectEqual(identity.default_suite, try suite_ran(&server.session));
    client.close();
    server.close();
}

/// The suite a session ran. A client of an object without AES-GCM offers ChaCha20 alone and
/// records no suite (chapulin's `suite`), so null means ChaCha20 there and nowhere else.
fn suite_ran(session: anytype) !u16 {
    if (session.suite()) |recorded| return @intFromEnum(recorded);
    // RFC 9846 §4.2.3: a client that offered more than one suite takes the one the ServerHello
    // names, so only an object that holds ChaCha20 alone records none.
    try testing.expect(!identity.aes_gcm);
    return identity.chacha;
}

test "RFC 9001 §4.8: a flight chapulin refuses fails the handshake, and the alert is reported once" {
    try support.configure(support.web_pki, .{});
    try support.start_both(null);
    const provider = client.provider();
    const suite = client.suite();
    try suite.vtable.install_initial_keys(suite.context, .client, &support.destination_id);
    var header_storage: [64]u8 = undefined;
    const header = try support.initial_header(0, payload.len, &header_storage);
    const sealing: crypto.suite.Sealing = .{ .level = .initial, .packet_number = 0, .header = header, .packet_number_len = support.packet_number_len, .payload = payload };
    // An output that cannot hold the packet takes none of it.
    try testing.expectError(error.NoSpaceLeft, suite.vtable.seal(suite.context, sealing, support.packet[0..header.len]));
    // RFC 9001 §4.1.3: nothing at the Handshake level is read before the Initial level's.
    try testing.expectError(error.WrongLevel, provider.vtable.provide_handshake(provider.context, .handshake, "\x08\x00\x00\x00"));
    // RFC 9846 §4.2.3: a ServerHello whose body is empty.
    try testing.expectError(error.TlsFailed, provider.vtable.provide_handshake(provider.context, .initial, "\x02\x00\x00\x00"));
    try testing.expect(provider.vtable.take_alert(provider.context) != null);
    try testing.expectEqual(null, provider.vtable.take_alert(provider.context));
    try testing.expect(!provider.vtable.handshake_complete(provider.context));
    // RFC 9001 §4.1.3: parameters come before the handshake, once.
    try testing.expectError(error.HandshakeStarted, provider.vtable.set_transport_params(provider.context, support.client_parameters));
    // RFC 9001 §4.8: the failed session still seals one CONNECTION_CLOSE at the level, and then
    // holds no key there.
    const written = try suite.vtable.seal(suite.context, sealing, &support.packet);
    // RFC 9001 §5.2: the close opens at the server's Initial keys, which derive from the same
    // Destination Connection ID in the same version.
    const server_suite = server.suite();
    try server_suite.vtable.install_initial_keys(server_suite.context, .server, &support.destination_id);
    const opened = try server_suite.vtable.open(server_suite.context, .{
        .level = .initial,
        .packet = support.packet[0..written],
        .packet_number_offset = header.len - support.packet_number_len,
        .largest_packet_number = null,
        .current_phase_lowest = null,
    });
    try testing.expectEqualStrings(payload, support.opened_payload(header.len, opened));
    try testing.expectError(error.KeysUnavailable, suite.vtable.seal(suite.context, sealing, &support.packet));
    client.close();
    server.close();
}

test "a level's octets that do not fit its buffer fail the handshake, and nothing is handed over" {
    try support.configure(support.web_pki, .{});
    try support.start_both(null);
    // Nearly full with octets colibri has not taken, the server's Initial level cannot hold its
    // ServerHello.
    const initial = @intFromEnum(tls_provider.Level.initial);
    server.state.outgoing_len[initial] = constants.crypto_out_len - 1;
    try testing.expectError(error.NoSpaceLeft, support.move(client.provider(), server.provider()));
    const provider = server.provider();
    try testing.expectError(error.NoSpaceLeft, provider.vtable.write_handshake(provider.context, .initial, &support.scratch));
    client.close();
    server.close();
    // A client whose level is as full cannot stage its ClientHello there.
    try client.start(&support.client_config, identity.random(), identity.now_seconds, null);
    client.state.outgoing_len[initial] = constants.crypto_out_len - 1;
    try client.provider().set_transport_params(support.client_parameters);
    try testing.expectError(error.NoSpaceLeft, client.provider().vtable.write_handshake(client.provider().context, .initial, &support.scratch));
    client.close();
}

test "a level colibri has taken every octet of starts empty again" {
    try support.configure(support.web_pki, .{});
    try support.start_both(null);
    const provider = client.provider();
    const initial = @intFromEnum(tls_provider.Level.initial);
    try testing.expect(client.state.outgoing_len[initial] > 0);
    _ = try provider.vtable.write_handshake(provider.context, .initial, &support.scratch);
    try testing.expectEqual(0, client.state.outgoing_len[initial]);
    try testing.expectEqual(0, client.state.outgoing_taken[initial]);
    client.close();
    server.close();
}

test "a session reports nothing before chapulin's starts, and owes nothing it has not written" {
    try support.configure(support.web_pki, .{ .tickets = true });
    // A connection that resumed and was not closed leaves its session in the struct, which the
    // next `start` reuses: nothing of it may be reported before chapulin's new session starts.
    try support.handshake_both(null);
    try support.move(server.provider(), client.provider());
    var ticket = client.take_ticket().?;
    defer ticket.wipe();
    try support.handshake_both(.{ .ticket = &ticket, .age_ms = 0 });
    try testing.expect(client.resumed() and server.resumed());
    try client.start(&support.client_config, identity.random(), identity.now_seconds, null);
    const provider = client.provider();
    try testing.expectError(error.WrongLevel, provider.vtable.provide_handshake(provider.context, .initial, "\x02"));
    try testing.expectEqual(null, provider.vtable.peer_transport_params(provider.context));
    try testing.expectEqual(null, provider.vtable.negotiated_alpn(provider.context));
    try testing.expect(!provider.vtable.handshake_complete(provider.context));
    try testing.expectEqual(null, provider.vtable.take_alert(provider.context));
    try testing.expectEqual(0, try provider.vtable.write_handshake(provider.context, .initial, &support.scratch));
    try testing.expectEqual(null, client.take_ticket());
    try testing.expect(!client.resumed());
    const suite = client.suite();
    try testing.expect(!suite.vtable.keys_available(suite.context, .initial, .read));
    try testing.expect(!suite.vtable.key_phase(suite.context));
    try testing.expectError(error.KeysUnavailable, suite.vtable.update_keys(suite.context));
    suite.vtable.discard_keys(suite.context, .initial);
    suite.vtable.discard_previous_keys(suite.context);
    var tag: [crypto.constants.retry_integrity_tag_len]u8 = @splat(0);
    try testing.expect(!suite.vtable.retry_tag_valid(suite.context, "a pseudo-packet", &tag));
    var header_storage: [64]u8 = undefined;
    const header = try support.short_header(0, false, &header_storage);
    try testing.expectError(error.KeysUnavailable, suite.vtable.seal(suite.context, .{ .level = .application, .packet_number = 0, .header = header, .packet_number_len = support.packet_number_len, .payload = payload }, &support.packet));
    try testing.expectError(error.KeysUnavailable, suite.vtable.open(suite.context, .{ .level = .application, .packet = support.packet[0..header.len], .packet_number_offset = header.len - support.packet_number_len, .largest_packet_number = null }));
    server.start(&support.server_config, identity.random(), identity.now_seconds);
    try testing.expectEqual(null, server.sni());
    try testing.expect(!server.resumed());
    const server_suite = server.suite();
    try testing.expectError(error.Unsupported, server_suite.vtable.install_initial_keys(server_suite.context, .server, &support.destination_id));
    // chapulin's session holds at most `CH_TRANSPORT_PARAMS_MAX` octets of parameters.
    const long_parameters: [client.state.local_parameters.len + 1]u8 = @splat(0);
    try testing.expectError(error.TlsFailed, provider.vtable.set_transport_params(provider.context, &long_parameters));
    client.close();
}

test "RFC 9001 §4.1.3: the ClientHello is written whole or in pieces, never twice" {
    try support.configure(support.web_pki, .{});
    try support.start_both(null);
    const provider = client.provider();
    var piece: [100]u8 = undefined;
    var total: usize = 0;
    for (0..support.scratch.len / piece.len) |_| {
        const written = try provider.vtable.write_handshake(provider.context, .initial, &piece);
        total += written;
        if (written < piece.len) break;
    }
    try testing.expect(total > piece.len);
    try testing.expectEqual(0, try provider.vtable.write_handshake(provider.context, .initial, &piece));
    client.close();
    server.close();
}

test "RFC 9846 §4.7.1: the server's ticket resumes a later connection, and a malformed one is refused" {
    try support.configure(support.web_pki, .{ .tickets = true });
    try support.handshake_both(null);
    // The ticket rides the application level after the handshake.
    try support.move(server.provider(), client.provider());
    var ticket = client.take_ticket().?;
    defer ticket.wipe();
    try testing.expectEqual(null, client.take_ticket());
    client.close();
    server.close();
    try support.handshake_both(.{ .ticket = &ticket, .age_ms = identity.ms_per_second });
    try testing.expect(client.resumed() and server.resumed());
    client.close();
    // Closing wipes the copy of the ticket the connection offered.
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&client.offered), 0));
    server.close();
    var malformed = ticket;
    malformed.psk_len = 5;
    try testing.expectError(error.Refused, client.start(&support.client_config, identity.random(), identity.now_seconds, .{ .ticket = &malformed, .age_ms = 0 }));
    // RFC 9846 §4.7.1: a ticket past its lifetime is refused when chapulin's session starts.
    const stale_ms = (@as(u64, ticket.lifetime_s) + 1) * identity.ms_per_second;
    try client.start(&support.client_config, identity.random(), identity.now_seconds, .{ .ticket = &ticket, .age_ms = stale_ms });
    try testing.expectError(error.TlsFailed, client.provider().set_transport_params(support.client_parameters));
    client.close();
}

test "the keylog context a program sets is the one chapulin's hook carries" {
    try support.configure(support.web_pki, .{});
    var marker: u8 = 0;
    try client.start(&support.client_config, identity.random(), identity.now_seconds, null);
    client.set_keylog_context(&marker);
    try client.provider().set_transport_params(support.client_parameters);
    try testing.expectEqual(@as(?*anyopaque, &marker), client.session.hook.context);
    client.close();
}

/// A token key and lifetime for the Retry test, the key an octet repeated.
const token_key_octet: u8 = 0x4b;
const token_key: [quic.token_key_len]u8 = @splat(token_key_octet);
const token_lifetime_seconds: u64 = 10;
const now_seconds: u64 = 1;

test "decision 55: a Retry token gives both connection IDs back, and the Retry tag verifies" {
    const retry: quic.Retry = .{ .key = &token_key, .lifetime_seconds = token_lifetime_seconds };
    const suite = retry.suite();
    const ids = crypto.suite.RetryConnectionIds.of(&support.destination_id, "retry-id");
    var token: [256]u8 = undefined;
    const now_ns = now_seconds * constants.nanoseconds_per_second;
    const len = try suite.vtable.retry_token_write(suite.context, "address", &ids, now_ns, &token);
    const minted = token[0..len];
    const checked = suite.vtable.retry_token_check(suite.context, "address", minted, now_ns).retry;
    try testing.expectEqualSlices(u8, &support.destination_id, checked.original_destination_slice());
    try testing.expectEqualStrings("retry-id", checked.retry_source_slice());
    // RFC 9000 §8.1.4: bound to the address, and accepted for a short time only, which is seconds.
    const soon_ns = now_ns + constants.nanoseconds_per_second;
    try testing.expectEqualStrings("retry-id", suite.vtable.retry_token_check(suite.context, "address", minted, soon_ns).retry.retry_source_slice());
    try testing.expectEqual(.invalid, suite.vtable.retry_token_check(suite.context, "elsewhere", minted, now_ns));
    const late_ns = (now_seconds + token_lifetime_seconds + 1) * constants.nanoseconds_per_second;
    try testing.expectEqual(.invalid, suite.vtable.retry_token_check(suite.context, "address", minted, late_ns));
    // RFC 9000 §8.1.3: a token of another type is no Retry token.
    minted[0] +%= 1;
    try testing.expectEqual(.not_retry, suite.vtable.retry_token_check(suite.context, "address", minted, now_ns));
    try testing.expectError(error.NoSpaceLeft, suite.vtable.retry_token_write(suite.context, "address", &ids, now_ns, token[0..1]));
    // An address longer than chapulin binds has no token.
    const long_address: [256]u8 = @splat('a');
    try testing.expectError(error.Unsupported, suite.vtable.retry_token_write(suite.context, &long_address, &ids, now_ns, &token));
    try testing.expectEqual(.invalid, suite.vtable.retry_token_check(suite.context, &long_address, token[0..len], now_ns));
    // RFC 9001 §5.8: a client's session verifies the tag any suite writes, and no other.
    try support.configure(support.web_pki, .{});
    try support.start_both(null);
    var tag: [crypto.constants.retry_integrity_tag_len]u8 = undefined;
    try suite.vtable.retry_tag_write(suite.context, "a pseudo-packet", &tag);
    const client_suite = client.suite();
    try testing.expect(client_suite.vtable.retry_tag_valid(client_suite.context, "a pseudo-packet", &tag));
    tag[0] ^= 1;
    try testing.expect(!client_suite.vtable.retry_tag_valid(client_suite.context, "a pseudo-packet", &tag));
    // A session mints no token of its own.
    try testing.expectError(error.Unsupported, client_suite.vtable.retry_token_write(client_suite.context, "address", &ids, now_ns, &token));
    try testing.expectEqual(.not_retry, client_suite.vtable.retry_token_check(client_suite.context, "address", minted, now_ns));
    client.close();
    server.close();
}

test {
    _ = values;
}

/// What a QUIC client and server whose sources start at one seed write first at the Initial level:
/// the ClientHello, and the ServerHello that answers it.
const InitialFlights = struct {
    hello: [constants.crypto_out_len]u8 = undefined,
    hello_len: usize = 0,
    answer: [constants.crypto_out_len]u8 = undefined,
    answer_len: usize = 0,
};

fn initial_flights(client_seed: u64, server_seed: u64, flights: *InitialFlights) !void {
    var client_stream: random_support.Stream = .{ .state = client_seed };
    var server_stream: random_support.Stream = .{ .state = server_seed };
    try client.start(&support.client_config, client_stream.random(), identity.now_seconds, null);
    defer client.close();
    server.start(&support.server_config, server_stream.random(), identity.now_seconds);
    defer server.close();
    try client.provider().set_transport_params(support.client_parameters);
    try server.provider().set_transport_params(support.server_parameters);
    const from = client.provider();
    flights.hello_len = try from.vtable.write_handshake(from.context, .initial, &flights.hello);
    const to = server.provider();
    try to.vtable.provide_handshake(to.context, .initial, flights.hello[0..flights.hello_len]);
    flights.answer_len = try to.vtable.write_handshake(to.context, .initial, &flights.answer);
}

test "decision 94: each QUIC session draws from its caller's source alone, so one seed replays it" {
    try support.configure(support.web_pki, .{});
    const seed = random_support.seed;
    var first: InitialFlights = .{};
    var again: InitialFlights = .{};
    var client_other: InitialFlights = .{};
    var server_other: InitialFlights = .{};
    try initial_flights(seed, seed, &first);
    try initial_flights(seed, seed, &again);
    try initial_flights(seed +% 1, seed, &client_other);
    try initial_flights(seed, seed +% 1, &server_other);
    try testing.expect(first.hello_len > 0 and first.answer_len > 0);
    try testing.expectEqualSlices(u8, first.hello[0..first.hello_len], again.hello[0..again.hello_len]);
    try testing.expectEqualSlices(u8, first.answer[0..first.answer_len], again.answer[0..again.answer_len]);
    // Another seed for one side changes what that side writes, and the same hello for the other.
    try testing.expect(!std.mem.eql(u8, first.hello[0..first.hello_len], client_other.hello[0..client_other.hello_len]));
    try testing.expectEqualSlices(u8, first.hello[0..first.hello_len], server_other.hello[0..server_other.hello_len]);
    try testing.expect(!std.mem.eql(u8, first.answer[0..first.answer_len], server_other.answer[0..server_other.answer_len]));
}
