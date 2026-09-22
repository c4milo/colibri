//! The tests of `connection_identity.zig`, split out so a hand-written file stays under 500 lines.
//!
//! What they pin is RFC 9000 §7.3's Figures 7 and 8, read as the wire sees them: which value each
//! header carries at each point of the handshake, and which parameter each role sends.
const std = @import("std");
const crypto = @import("crypto");
const transport_parameters = @import("../transport_parameters.zig");
const identity_module = @import("connection_identity.zig");

const testing = std.testing;
const Identity = identity_module.Identity;
const Parameters = transport_parameters.Parameters;
const ConnectionId = transport_parameters.ConnectionId;

/// RFC 9000 §7.3's Figure 7 and Figure 8 name five connection IDs. These are those: one octet
/// repeated, distinct per identifier, so a test that reads the wrong one cannot pass by
/// coincidence. The server's and the client's differ in length too, which §5.1 permits and which
/// makes a mix-up fail on the length as well as the octets.
const s1_octet: u8 = 0x51;
const s2_octet: u8 = 0x52;
const s3_octet: u8 = 0x53;
const c1_octet: u8 = 0xc1;
const server_id_len: usize = 8;
const client_id_len: usize = 5;
const s1_storage: [server_id_len]u8 = @splat(s1_octet);
const s2_storage: [server_id_len]u8 = @splat(s2_octet);
const s3_storage: [server_id_len]u8 = @splat(s3_octet);
const c1_storage: [client_id_len]u8 = @splat(c1_octet);
const s1: []const u8 = &s1_storage;
const s2: []const u8 = &s2_storage;
const s3: []const u8 = &s3_storage;
const c1: []const u8 = &c1_storage;

var test_identity: Identity = undefined;

fn client() void {
    test_identity.init(.{ .local_initial_source = c1, .original_destination = s1 });
}

fn server() void {
    test_identity.init(.{
        .local_initial_source = s3,
        .original_destination = s1,
        .peer_initial_source = c1,
    });
}

test "§7.3 Figure 7: a client addresses S1 until the server answers, then S3" {
    client();
    // `Initial: DCID=S1, SCID=C1 ->`
    try testing.expectEqualSlices(u8, s1, test_identity.destination().slice());
    try testing.expectEqualSlices(u8, c1, test_identity.source().slice());
    // `<- Initial: DCID=C1, SCID=S3`, after which `1-RTT: DCID=S3 ->`.
    test_identity.on_peer_initial(s3);
    try testing.expectEqualSlices(u8, s3, test_identity.destination().slice());
    // §7.3 authenticates the first Source Connection ID the peer sent, so a later one is ignored.
    test_identity.on_peer_initial(s2);
    try testing.expectEqualSlices(u8, s3, test_identity.destination().slice());
    // The endpoint's own never moves: it is what its initial_source_connection_id must equal.
    try testing.expectEqualSlices(u8, c1, test_identity.source().slice());
}

test "§7.3 Figure 8: a Retry replaces S1 with S2, and S3 replaces that" {
    client();
    test_identity.on_retry(s2);
    // `Initial: DCID=S2, SCID=C1 ->`
    try testing.expectEqualSlices(u8, s2, test_identity.destination().slice());
    try testing.expectEqualSlices(u8, c1, test_identity.source().slice());
    // The Retry does not change what original_destination_connection_id must be: §7.3 says it
    // "refers to the first Initial packet received before sending the Retry packet".
    try testing.expectEqualSlices(u8, s1, test_identity.original_destination.slice());
    test_identity.on_peer_initial(s3);
    try testing.expectEqualSlices(u8, s3, test_identity.destination().slice());
}

test "§7.3 Figure 7: a server addresses C1 from the first packet it sends" {
    server();
    // `<- Initial: DCID=C1, SCID=S3`, and `<- 1-RTT: DCID=C1` later, which is the same value.
    try testing.expectEqualSlices(u8, c1, test_identity.destination().slice());
    try testing.expectEqualSlices(u8, s3, test_identity.source().slice());
}

test "§7.3: a server sends three connection IDs and a client sends one" {
    var parameters = Parameters.initial();
    server();
    test_identity.on_retry(s2);
    identity_module.describe(&test_identity, &parameters, .server);
    try testing.expectEqualSlices(u8, s3, parameters.initial_source_connection_id.?.slice());
    try testing.expectEqualSlices(u8, s1, parameters.original_destination_connection_id.?.slice());
    try testing.expectEqualSlices(u8, s2, parameters.retry_source_connection_id.?.slice());

    // §18.2 makes the other two server-only, so a client sends its own and nothing else.
    var client_parameters = Parameters.initial();
    client();
    identity_module.describe(&test_identity, &client_parameters, .client);
    try testing.expectEqualSlices(u8, c1, client_parameters.initial_source_connection_id.?.slice());
    try testing.expectEqual(null, client_parameters.original_destination_connection_id);
    try testing.expectEqual(null, client_parameters.retry_source_connection_id);
}

test "§7.3: no Retry means no retry_source_connection_id at all" {
    var parameters = Parameters.initial();
    server();
    identity_module.describe(&test_identity, &parameters, .server);
    // §7.3 makes the "presence of the retry_source_connection_id transport parameter when no
    // Retry packet was received" a connection error, so a server that sent none sends none.
    try testing.expectEqual(null, parameters.retry_source_connection_id);
}

test "§5.1: a short header's Destination Connection ID length is this endpoint's own" {
    client();
    try testing.expectEqual(c1.len, test_identity.local_len());
    server();
    try testing.expectEqual(s3.len, test_identity.local_len());
    // §5.1 admits a zero-length connection ID, and then a short header carries none at all.
    test_identity.init(.{ .local_initial_source = &.{}, .original_destination = s1 });
    try testing.expectEqual(0, test_identity.local_len());
}

test "§7.3 Figure 8: a server keeps addressing C1 across its own Retry" {
    // A server reads the peer's C1 off the Initial that made it answer with a Retry, so unlike
    // the client it already knows what it addresses, and the Retry does not change it.
    server();
    try testing.expectEqualSlices(u8, c1, test_identity.destination().slice());
    test_identity.on_retry(s2);
    try testing.expectEqualSlices(u8, c1, test_identity.destination().slice());
    try testing.expectEqualSlices(u8, s3, test_identity.source().slice());
}

/// The parameters a server sends this client, as RFC 9000 §7.3 requires them: its own first
/// Source Connection ID, and the Destination Connection ID the client's first Initial carried.
fn server_parameters() Parameters {
    var peer = Parameters.initial();
    peer.initial_source_connection_id = ConnectionId.of(s3);
    peer.original_destination_connection_id = ConnectionId.of(s1);
    return peer;
}

test "RFC 9000 §7.3: a client holds the server's parameters to the headers it saw" {
    client();
    test_identity.on_peer_initial(s3);
    const authentic = server_parameters();
    try identity_module.authenticate(&test_identity, &authentic, .client);

    // "An endpoint MUST treat the absence of the initial_source_connection_id transport parameter
    // from either endpoint ... as a connection error of type TRANSPORT_PARAMETER_ERROR."
    var absent = authentic;
    absent.initial_source_connection_id = null;
    try testing.expectError(
        identity_module.Error.ConnectionIdMissing,
        identity_module.authenticate(&test_identity, &absent, .client),
    );
    // "a mismatch between values received from a peer in these transport parameters and the value
    // sent in the corresponding Destination or Source Connection ID fields of Initial packets."
    var wrong = authentic;
    wrong.initial_source_connection_id = ConnectionId.of(s2);
    try testing.expectError(
        identity_module.Error.ConnectionIdMismatch,
        identity_module.authenticate(&test_identity, &wrong, .client),
    );
    // "If a zero-length connection ID is selected, the corresponding transport parameter is
    // included with a zero-length value", so an empty one is a value and not a wildcard.
    var empty = authentic;
    empty.initial_source_connection_id = ConnectionId.of("");
    try testing.expectError(
        identity_module.Error.ConnectionIdMismatch,
        identity_module.authenticate(&test_identity, &empty, .client),
    );
}

test "RFC 9000 §7.3: a client requires the server to echo the connection ID it first addressed" {
    client();
    test_identity.on_peer_initial(s3);
    const authentic = server_parameters();

    // "the absence of the original_destination_connection_id transport parameter from the server".
    var absent = authentic;
    absent.original_destination_connection_id = null;
    try testing.expectError(
        identity_module.Error.ConnectionIdMissing,
        identity_module.authenticate(&test_identity, &absent, .client),
    );
    // S2 is the Retry's Source Connection ID, not the client's first Destination Connection ID.
    var wrong = authentic;
    wrong.original_destination_connection_id = ConnectionId.of(s2);
    try testing.expectError(
        identity_module.Error.ConnectionIdMismatch,
        identity_module.authenticate(&test_identity, &wrong, .client),
    );
}

test "RFC 9000 §7.3: retry_source_connection_id is owed after a Retry and refused before one" {
    client();
    test_identity.on_peer_initial(s3);
    // "presence of the retry_source_connection_id transport parameter when no Retry packet was
    // received".
    var unasked = server_parameters();
    unasked.retry_source_connection_id = ConnectionId.of(s2);
    try testing.expectError(
        identity_module.Error.RetrySourceUnexpected,
        identity_module.authenticate(&test_identity, &unasked, .client),
    );

    // §7.3 Figure 8: the Retry carried S2, so from here the server owes it as a parameter.
    test_identity.on_retry(s2);
    // "absence of the retry_source_connection_id transport parameter from the server after
    // receiving a Retry packet".
    const absent = server_parameters();
    try testing.expectError(
        identity_module.Error.RetrySourceUnexpected,
        identity_module.authenticate(&test_identity, &absent, .client),
    );
    var wrong = server_parameters();
    wrong.retry_source_connection_id = ConnectionId.of(s1);
    try testing.expectError(
        identity_module.Error.ConnectionIdMismatch,
        identity_module.authenticate(&test_identity, &wrong, .client),
    );
    try identity_module.authenticate(&test_identity, &unasked, .client);
}

test "RFC 9000 §7.3: a server checks the one parameter §18.2 lets a client send" {
    server();
    var peer = Parameters.initial();
    peer.initial_source_connection_id = ConnectionId.of(c1);
    try identity_module.authenticate(&test_identity, &peer, .server);

    // A server never receives the other two: §18.2 makes them server-only and
    // `transport_parameters_read` refuses them from a client, so nothing here looks for them.
    peer.initial_source_connection_id = ConnectionId.of(s1);
    try testing.expectError(
        identity_module.Error.ConnectionIdMismatch,
        identity_module.authenticate(&test_identity, &peer, .server),
    );
}

test "RFC 9000 §7.3: parameters that arrive before any packet of the peer's are refused" {
    client();
    // A client has not heard from the server yet, so there is no Source Connection ID to hold the
    // parameter to. The handshake cannot reach here, and the check fails closed rather than
    // taking the peer's word for its own value.
    try testing.expectEqual(null, test_identity.peer_initial_source);
    try testing.expectError(
        identity_module.Error.ConnectionIdMissing,
        identity_module.authenticate(&test_identity, &server_parameters(), .client),
    );
}
