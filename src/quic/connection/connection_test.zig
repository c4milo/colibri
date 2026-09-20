//! The tests of `connection.zig`, split out because a hand-written source file stays at or under
//! 500 lines with its tests included (CLAUDE.md).
//!
//! What they pin is the joining, not the pieces: every module a connection holds was tested on
//! its own in steps 9a to 9d, and what is new is that one connection pairs them correctly and
//! starts in the state RFC 9000 §7.4 leaves an endpoint that has not heard from its peer.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const identity_module = @import("connection_identity.zig");

const testing = std.testing;
const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

/// The connection the tests drive, placed outside any stack frame: it carries three CRYPTO
/// windows and a stream table, which are larger than a stack frame should hold.
var test_connection: Connection = undefined;

/// An instant the tests begin at. A constant, because no file under `src/` reads a clock.
const test_now_ns: u64 = 1_000_000;

/// What the tests grant a peer. Large enough that no test below is bounded by these rather than
/// by the rule it is checking.
const test_max_data: u64 = 1_048_576;
const test_max_streams_bidi: u64 = 8;
const test_max_streams_uni: u64 = 3;
const test_idle_timeout_ms: u64 = 30_000;

/// RFC 9000 §7.3's C1 and S1 as fixed octets: §5.1 wants a connection ID unpredictable and
/// invariant 5 forbids colibri a random number, so a test states them rather than drawing them.
const local_id_octet: u8 = 0xc1;
const original_id_octet: u8 = 0x51;
const test_id_len: usize = 8;
const local_id: [test_id_len]u8 = @splat(local_id_octet);
const original_id: [test_id_len]u8 = @splat(original_id_octet);
const test_identity: identity_module.Options = .{
    .local_initial_source = &local_id,
    .original_destination = &original_id,
};

fn local_parameters() Parameters {
    var parameters = Parameters.initial();
    parameters.initial_max_data = test_max_data;
    parameters.initial_max_streams_bidi = test_max_streams_bidi;
    parameters.initial_max_streams_uni = test_max_streams_uni;
    parameters.max_idle_timeout_ms = test_idle_timeout_ms;
    return parameters;
}

test "a connection begins having heard nothing from its peer" {
    test_connection.init(.{ .role = .client, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    try testing.expectEqual(.client, test_connection.role);
    // RFC 9000 §7.4: the peer's parameters arrive during the handshake, so there are none yet.
    try testing.expectEqual(null, test_connection.peer_parameters);
    // RFC 9001 §4.1.2: confirmed is a later state than complete, and neither has happened.
    try testing.expect(!test_connection.handshake_confirmed);
}

test "RFC 9000 §12.3 and RFC 9001 Table 1: one packet number space per encryption level" {
    test_connection.init(.{ .role = .server, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    const levels = [_]Level{ .initial, .handshake, .application };
    const kinds = [_]@TypeOf(test_connection.space_at(.initial).kind){ .initial, .handshake, .application };
    for (levels, kinds) |level, kind| {
        // The space a level indexes is the space for that level, which is what `space_at` rests on.
        try testing.expectEqual(kind, test_connection.space_at(level).kind);
        // Nothing has been sent, so every space is at its first packet number (§12.3).
        try testing.expectEqual(0, test_connection.space_at(level).next_packet_number);
    }
}

test "RFC 9000 §19.6: each level carries its own CRYPTO stream" {
    test_connection.init(.{ .role = .client, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    try test_connection.crypto_at(.initial).receive(0, "client hello");
    try testing.expectEqualStrings("client hello", test_connection.crypto_at(.initial).readable());
    // The other two are untouched, because §19.6 makes each level a separate flow.
    try testing.expectEqual(0, test_connection.crypto_at(.handshake).readable().len);
    try testing.expectEqual(0, test_connection.crypto_at(.application).readable().len);
}

test "RFC 9000 §18.2: what colibri may spend starts at zero and the peer's parameters raise it" {
    test_connection.init(.{ .role = .client, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    // Before the peer speaks, colibri may send no data and open no stream: §18.2 says a limit
    // that is absent or zero means the peer cannot open streams until a MAX_STREAMS frame.
    try testing.expectEqual(0, test_connection.send_flow.available());
    try testing.expect(test_connection.send_flow.is_blocked());
    // What colibri grants comes from its own parameters and is in force from the start.
    try testing.expectEqual(local_parameters().initial_max_data, test_connection.receive_flow.available());

    var peer = Parameters.initial();
    peer.initial_max_data = 1 << 18;
    peer.initial_max_streams_bidi = 5;
    peer.initial_max_streams_uni = 2;
    test_connection.apply_peer_parameters(peer);
    try testing.expectEqual(peer.initial_max_data, test_connection.send_flow.available());
    try testing.expect(!test_connection.send_flow.is_blocked());
    try testing.expectEqual(peer, test_connection.peer_parameters.?);
}

test "RFC 9000 §10.1: an idle timeout of zero disables it, and any other value arms it" {
    var without = local_parameters();
    without.max_idle_timeout_ms = 0;
    test_connection.init(.{ .role = .server, .local_parameters = without, .now_ns = test_now_ns, .identity = test_identity });
    try testing.expectEqual(null, test_connection.termination.idle_timeout_ns);

    test_connection.init(.{ .role = .server, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    // §18.2 states the parameter in milliseconds and colibri counts in nanoseconds.
    const expected = test_idle_timeout_ms * constants.nanoseconds_per_millisecond;
    try testing.expectEqual(expected, test_connection.termination.idle_timeout_ns.?);
}

test "RFC 9001 §4.1.2: confirmed is a state of its own, reached after complete" {
    test_connection.init(.{ .role = .client, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    try testing.expect(!test_connection.handshake_confirmed);
    test_connection.confirm_handshake();
    try testing.expect(test_connection.handshake_confirmed);
}

test "a connection holds no key and no socket, which is what makes it the caller's to place" {
    // RFC 9001 §4.1.4's secrets are the suite's (decision 48) and the handshake is the provider's
    // (decision 8), so neither appears here. A field of either kind would fail this by name.
    inline for (@typeInfo(Connection).@"struct".fields) |field| {
        try testing.expect(!std.mem.containsAtLeast(u8, field.name, 1, "secret"));
        try testing.expect(!std.mem.containsAtLeast(u8, field.name, 1, "socket"));
        try testing.expect(!std.mem.containsAtLeast(u8, field.name, 1, "provider"));
        try testing.expect(!std.mem.containsAtLeast(u8, field.name, 1, "suite"));
    }
    // And the whole thing is one struct the caller places, whose size colibri states (decision 35).
    try testing.expect(@sizeOf(Connection) > 0);
    try testing.expect(constants.packet_number_spaces == core.levels_count);
}

test "RFC 9000 §8.1, §21.1.1.1: a client may send at once and a server may not" {
    // A client has received nothing and must still be able to send its first Initial, which
    // §14.1 makes 1,200 octets. §21.1.1.1: the limit "does not apply to clients when
    // establishing a new connection".
    test_connection.init(.{ .role = .client, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    try testing.expectEqual(0, test_connection.path.received);
    try testing.expect(!test_connection.path.is_amplification_limited(constants.datagram_len_min));

    // A server has received nothing either, and §8.1 is exactly the rule that stops it answering:
    // three times nothing is nothing.
    test_connection.init(.{ .role = .server, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    try testing.expectEqual(0, test_connection.path.send_allowance());
    try testing.expect(test_connection.path.is_amplification_limited(1));

    // And the server's exemption arrives with the client's octets, not with its role.
    test_connection.path.on_datagram_received(constants.datagram_len_min);
    const allowance = constants.anti_amplification_factor * constants.datagram_len_min;
    try testing.expectEqual(allowance, test_connection.path.send_allowance());
}

test "RFC 9000 §8.2.3: a client's exemption is not a validated path MTU" {
    // §21.1.1.1 lifts §8's limit for a client; it says nothing about the path MTU, which §8.2.3
    // makes a separate question that only an expanded PATH_CHALLENGE settles.
    test_connection.init(.{ .role = .client, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    try testing.expect(!test_connection.path.mtu_validated);
}

test "RFC 9000 §19.16: a zero-length connection ID reaches the set that refuses a retirement" {
    // §5.1 lets an endpoint use a zero-length connection ID, and its own first Source Connection
    // ID is what says so. The connection must carry that answer through to `local_ids`, because
    // §19.16 makes a RETIRE_CONNECTION_ID frame a connection error for such an endpoint and
    // nothing else on the connection knows.
    const none: [0]u8 = @splat(0);
    test_connection.init(.{
        .role = .client,
        .local_parameters = local_parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &none, .original_destination = &original_id },
    });
    try testing.expectEqual(0, test_connection.identity.local_len());
    try testing.expectError(
        error.ZeroLengthConnectionId,
        test_connection.local_ids.retire(0, null),
    );

    // An endpoint whose connection IDs have octets answers the frame on its merits instead.
    test_connection.init(.{ .role = .client, .local_parameters = local_parameters(), .now_ns = test_now_ns, .identity = test_identity });
    try testing.expectError(
        error.RetiredUnissued,
        test_connection.local_ids.retire(0, null),
    );
}
