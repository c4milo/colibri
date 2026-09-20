//! The tests of `null_quic_provider.zig`, split out because a hand-written source file stays at or
//! under 500 lines with its tests included (CLAUDE.md).
//!
//! They drive a client and a server against each other the way `quic.connection_crypto` drives one
//! provider: `write_handshake` at a level, then `provide_handshake` of what it wrote at the same
//! level. `src/sim/` cannot import `quic` (design §3), so the moving is done here.
const std = @import("std");
const core = @import("core");
const tls = @import("tls");
const constants = @import("constants.zig");
const null_quic_provider = @import("null_quic_provider.zig");

const testing = std.testing;
const Alert = tls.Alert;
const Level = tls.Level;
const NullQuicProvider = null_quic_provider.NullQuicProvider;
const MessageType = null_quic_provider.MessageType;
const Role = null_quic_provider.Role;

/// The two endpoints, placed at file level: each holds a buffer per encryption level and a test
/// places the struct rather than a stack frame (CLAUDE.md non-negotiable 4).
var test_client: NullQuicProvider = undefined;
var test_server: NullQuicProvider = undefined;

/// Octets one flight is written into before it is handed to the peer, which is the part a CRYPTO
/// frame would carry. Larger than any flight below.
const test_flight_len_max: usize = 1024;
var test_flight: [test_flight_len_max]u8 = undefined;

/// Made-up `quic_transport_parameters` bodies (RFC 9001 §8.2). What the null provider does with
/// the body is carry it, so its octets are a label a test can recognise.
const client_params = "client transport parameters";
const server_params = "server transport parameters";

/// Octets of exported keying material one test asks for (RFC 9846 §7.5).
const test_export_len: usize = 32;

/// The header RFC 9846 §4 puts before a message's body.
const header_len: usize = constants.null_quic_message_header_len;

/// Puts both endpoints back to the start of their scripts.
fn pair() void {
    test_client = .{ .role = .client };
    test_server = .{ .role = .server };
}

/// Moves every octet `from` owes at `level` to `to`, and answers how many moved. It is what
/// `connection_crypto.write_crypto` and `connection_crypto.provide_handshake` do together, with
/// the CRYPTO frame left out.
fn flight(from: *NullQuicProvider, to: *NullQuicProvider, level: Level) !usize {
    var filled: usize = 0;
    for (0..constants.null_quic_steps_max) |_| {
        const written = try from.provider().write_handshake(level, test_flight[filled..]);
        if (written == 0) break;
        filled += written;
    }
    if (filled > 0) try to.provider().provide_handshake(level, test_flight[0..filled]);
    return filled;
}

/// Drives a pair until neither owes anything, at every level of RFC 9001 §4.1.4.
fn run_handshake(client: *NullQuicProvider, server: *NullQuicProvider) !void {
    for (0..constants.null_quic_steps_max) |_| {
        var moved: usize = 0;
        for (0..core.levels_count) |index| {
            const level: Level = @enumFromInt(index);
            moved += try flight(client, server, level);
            moved += try flight(server, client, level);
        }
        if (moved == 0) return;
    }
}

test "RFC 9001 §4.1.5: a pair completes the handshake and each learns the other's parameters" {
    pair();
    try test_client.provider().set_transport_params(client_params);
    try test_server.provider().set_transport_params(server_params);
    try testing.expect(!test_client.provider().handshake_complete());
    try testing.expect(!test_server.provider().handshake_complete());
    try run_handshake(&test_client, &test_server);
    // RFC 9001 §4.1.1: both reach completion, though §4.1.1 says not at the same moment.
    try testing.expect(test_client.provider().handshake_complete());
    try testing.expect(test_server.provider().handshake_complete());
    // RFC 9001 §8.1: "endpoints MUST use ALPN", and h3 is what this pair selects.
    try testing.expect(test_client.provider().speaks(&tls.constants.alpn_h3));
    try testing.expect(test_server.provider().speaks(&tls.constants.alpn_h3));
    // RFC 9001 §8.2: the extension crosses in the ClientHello and in EncryptedExtensions.
    try testing.expectEqualStrings(server_params, test_client.provider().peer_transport_params().?);
    try testing.expectEqualStrings(client_params, test_server.provider().peer_transport_params().?);
}

test "RFC 9001 §4.1.4: the ClientHello moves at Initial and every message after it at Handshake" {
    pair();
    try test_client.provider().set_transport_params(client_params);
    try test_server.provider().set_transport_params(server_params);
    // Nothing is owed at Handshake before the ClientHello, which is Initial.
    try testing.expectEqual(0, try flight(&test_client, &test_server, .handshake));
    try testing.expect(try flight(&test_client, &test_server, .initial) > 0);
    try testing.expectEqual(@intFromEnum(MessageType.client_hello), test_flight[0]);
    // The server answers the ServerHello at Initial and owes nothing more there.
    try testing.expect(try flight(&test_server, &test_client, .initial) > 0);
    try testing.expectEqual(@intFromEnum(MessageType.server_hello), test_flight[0]);
    try testing.expectEqual(0, try flight(&test_server, &test_client, .initial));
    // The rest of the server's flight is Handshake: EncryptedExtensions, then Finished.
    try testing.expect(try flight(&test_server, &test_client, .handshake) > 0);
    try testing.expectEqual(@intFromEnum(MessageType.encrypted_extensions), test_flight[0]);
    // So is the client's Finished, and the client owes nothing at Initial again.
    try testing.expectEqual(0, try flight(&test_client, &test_server, .initial));
    try testing.expect(try flight(&test_client, &test_server, .handshake) > 0);
    try testing.expectEqual(@intFromEnum(MessageType.finished), test_flight[0]);
}

test "RFC 9001 §4.1.1: completion is a state the pair reaches, not one it starts in" {
    pair();
    try test_client.provider().set_transport_params(client_params);
    try test_server.provider().set_transport_params(server_params);
    _ = try flight(&test_client, &test_server, .initial);
    // The server read the ClientHello and has sent no Finished, so it is not complete.
    try testing.expect(!test_server.provider().handshake_complete());
    _ = try flight(&test_server, &test_client, .initial);
    _ = try flight(&test_server, &test_client, .handshake);
    // The client verified the server's Finished but has not sent its own, which RFC 9001 §4.1.1
    // requires too. The server has sent its own and not verified the client's.
    try testing.expect(!test_client.provider().handshake_complete());
    try testing.expect(!test_server.provider().handshake_complete());
    _ = try flight(&test_client, &test_server, .handshake);
    try testing.expect(test_client.provider().handshake_complete());
    try testing.expect(test_server.provider().handshake_complete());
}

test "RFC 9001 §8.1: no protocol is selected until a message that carries ALPN is read" {
    pair();
    try test_client.provider().set_transport_params(client_params);
    try test_server.provider().set_transport_params(server_params);
    // RFC 9846 §4.3's table carries ALPN in the ClientHello and in EncryptedExtensions.
    try testing.expectEqual(null, test_client.provider().negotiated_alpn());
    try testing.expectEqual(null, test_server.provider().negotiated_alpn());
    _ = try flight(&test_client, &test_server, .initial);
    // The server has read the ClientHello and selected; the client has read nothing.
    try testing.expect(test_server.provider().speaks(&tls.constants.alpn_h3));
    try testing.expectEqual(null, test_client.provider().negotiated_alpn());
    _ = try flight(&test_server, &test_client, .initial);
    try testing.expectEqual(null, test_client.provider().negotiated_alpn());
    _ = try flight(&test_server, &test_client, .handshake);
    try testing.expect(test_client.provider().speaks(&tls.constants.alpn_h3));
}

test "RFC 9001 §4.1.3: octets at a level the provider does not read are the wrong level" {
    pair();
    try test_client.provider().set_transport_params(client_params);
    try test_server.provider().set_transport_params(server_params);
    // No message of this handshake moves at the application level, so it is refused from the
    // start: RFC 9000 §12.5 makes octets at the wrong level a protocol violation.
    try testing.expectError(
        error.WrongLevel,
        test_server.provider().provide_handshake(.application, "x"),
    );
    _ = try flight(&test_client, &test_server, .initial);
    _ = try flight(&test_server, &test_client, .initial);
    // The client read the ServerHello, so no step of its script reads at Initial again.
    try testing.expectError(
        error.WrongLevel,
        test_client.provider().provide_handshake(.initial, "x"),
    );
    // The level it does read at still takes them: one octet of a message is not a whole one yet.
    try test_client.provider().provide_handshake(.handshake, "\x08");
    try testing.expect(!test_client.provider().handshake_complete());
}

test "RFC 9001 §4.1.3: the parameters are set before the handshake starts and refused after" {
    pair();
    try test_client.provider().set_transport_params(client_params);
    // "A QUIC client starts TLS by requesting TLS handshake bytes from TLS", so the client's first
    // write starts it, and "A QUIC server starts the process by providing TLS with the client's
    // handshake bytes", which the same flight does.
    _ = try flight(&test_client, &test_server, .initial);
    try testing.expectError(
        error.HandshakeStarted,
        test_client.provider().set_transport_params(client_params),
    );
    try testing.expectError(
        error.HandshakeStarted,
        test_server.provider().set_transport_params(server_params),
    );
}

test "RFC 9001 §4.1.3: each role starts the handshake at its own call and not at the other's" {
    pair();
    // colibri asks every level for what a provider owes before the peer's first flight arrives.
    // "A QUIC server starts the process by providing TLS with the client's handshake bytes", so
    // being asked is not the server's start and its parameters can still be set.
    try testing.expectEqual(0, try test_server.provider().write_handshake(.initial, &test_flight));
    try testing.expectEqual(0, try test_server.provider().write_handshake(.handshake, &test_flight));
    try test_server.provider().set_transport_params(server_params);
    // "A QUIC client starts TLS by requesting TLS handshake bytes from TLS", so a client handed
    // octets before it asked for any has not started either.
    try test_client.provider().provide_handshake(.initial, "\x02");
    try test_client.provider().set_transport_params(client_params);
    // Its own first request is the start, and after it the parameters are refused.
    try testing.expect(try test_client.provider().write_handshake(.initial, &test_flight) > 0);
    try testing.expectError(
        error.HandshakeStarted,
        test_client.provider().set_transport_params(client_params),
    );
}

test "RFC 9001 §8.2: a peer that carried no parameters leaves them null" {
    pair();
    // Neither endpoint was given a body, so the ClientHello and the EncryptedExtensions carry
    // none and `connection_crypto.require_peer_parameters` is what makes that fatal.
    try testing.expectEqual(null, test_server.provider().peer_transport_params());
    try run_handshake(&test_client, &test_server);
    try testing.expect(test_server.provider().handshake_complete());
    try testing.expectEqual(null, test_server.provider().peer_transport_params());
    try testing.expectEqual(null, test_client.provider().peer_transport_params());
}

test "RFC 9001 §4.1.3: a message cut across calls waits until the rest of it arrives" {
    pair();
    try test_client.provider().set_transport_params(client_params);
    const written = try test_client.provider().write_handshake(.initial, &test_flight);
    try testing.expectEqual(header_len + client_params.len, written);
    // One octet per call, as a run of small CRYPTO frames would deliver it.
    for (0..written - 1) |index| {
        try test_server.provider().provide_handshake(.initial, test_flight[index..][0..1]);
        try testing.expectEqual(null, test_server.provider().peer_transport_params());
    }
    try test_server.provider().provide_handshake(.initial, test_flight[written - 1 ..][0..1]);
    try testing.expectEqualStrings(client_params, test_server.provider().peer_transport_params().?);
}

test "RFC 9846 §4: a message of the wrong type aborts the handshake with unexpected_message" {
    pair();
    // A ServerHello where the server's script expects a ClientHello, framed as §4 frames one: the
    // HandshakeType, then a uint24 length of zero.
    const wrong = "\x02\x00\x00\x00";
    try testing.expectError(
        error.TlsFailed,
        test_server.provider().provide_handshake(.initial, wrong),
    );
    try testing.expectEqual(Alert.unexpected_message, test_server.provider().take_alert().?);
    // RFC 9001 §4.8: the call clears the description, so the next one reports none.
    try testing.expectEqual(null, test_server.provider().take_alert());
}

test "RFC 9001 §4.8: a provider a test fails reports its description once" {
    pair();
    test_client.fails_with = .handshake_failure;
    try testing.expectError(
        error.TlsFailed,
        test_client.provider().write_handshake(.initial, &test_flight),
    );
    try testing.expectEqual(Alert.handshake_failure, test_client.provider().take_alert().?);
    try testing.expectEqual(null, test_client.provider().take_alert());
    // The failure fires once, so the handshake runs after it.
    try testing.expect(try test_client.provider().write_handshake(.initial, &test_flight) > 0);
    // The read side fails the same way.
    test_server.fails_with = .internal_error;
    try testing.expectError(
        error.TlsFailed,
        test_server.provider().provide_handshake(.initial, "x"),
    );
    try testing.expectEqual(Alert.internal_error, test_server.provider().take_alert().?);
}

test "RFC 9846 §7.5: the exporter answers after completion and is a function of its inputs" {
    pair();
    var secret: [test_export_len]u8 = @splat(0);
    try testing.expectError(
        error.HandshakeIncomplete,
        test_client.provider().export_keying_material("label", null, &secret),
    );
    try run_handshake(&test_client, &test_server);
    try test_client.provider().export_keying_material("label", null, &secret);
    var empty_context: [test_export_len]u8 = @splat(0);
    try test_server.provider().export_keying_material("label", "", &empty_context);
    // §7.5: "providing no context computes the same value as providing an empty context".
    try testing.expectEqualSlices(u8, &secret, &empty_context);
    var other: [test_export_len]u8 = @splat(0);
    // The label's length is folded in, so moving an octet out of the label is another input.
    try test_client.provider().export_keying_material("labe", "l", &other);
    try testing.expect(!std.mem.eql(u8, &secret, &other));
    try test_client.provider().export_keying_material("other", null, &other);
    try testing.expect(!std.mem.eql(u8, &secret, &other));
    // Two words of one answer differ, so it is not one checksum written over and over.
    const word = @sizeOf(u32);
    try testing.expect(!std.mem.eql(u8, secret[0..word], secret[word..][0..word]));
}

test "the role decides the script, and a client and a server never run the same one" {
    pair();
    try testing.expectEqual(Role.client, test_client.role);
    try testing.expectEqual(Role.server, test_server.role);
    // The client writes first and the server reads first, which is RFC 9001 §4.1.3's order.
    try testing.expect(try test_client.provider().write_handshake(.initial, &test_flight) > 0);
    try testing.expectEqual(0, try test_server.provider().write_handshake(.initial, &test_flight));
}
