//! The tests of decision 157 through the engine: an h3 client in the same process connects, and
//! the engine's table of connection IDs routes the datagrams that follow (RFC 9000 §5.2).
const std = @import("std");
const quic = @import("quic");
const support = @import("../quic/quic_test_support.zig");
const internal = @import("../quic/quic_connection_internal.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const engine = &support.engine_support.engine;

/// A short header's first octet, its Destination Connection ID, and the longest packet number
/// after it: as much as the engine reads to route it (RFC 9000 §17.3.1). Test-only.
const short_len = 1 + constants.policy.quic_id_len + @sizeOf(u32);

/// The slot of the one connection the engine holds. Test-only.
fn only_slot() !u32 {
    const connections = &engine.state.connections;
    for (connections.routes.held, 0..) |held, index| {
        if (held.len > 0) return @intCast(connections.slots.tcp_count + index);
    }
    return error.TestExpectedConnection;
}

/// A datagram whose first packet has a short header addressed to `dcid`. Test-only.
fn short_datagram(dcid: []const u8, octets: *[short_len]u8) []u8 {
    octets.* = @splat(0);
    octets[0] = quic.constants.protocol.fixed_bit;
    @memcpy(octets[1..][0..dcid.len], dcid);
    return octets;
}

fn route(octets: []u8) ?u32 {
    return engine.state.connections.receive(octets, .not_ect, support.client_address(), support.now_ns, true);
}

test "decision 157: a short header with the client's first DCID reaches no connection" {
    try support.start_engine(null);
    try support.connect();
    const connection = engine.state.connections.at(try only_slot());
    // RFC 9000 §7.2: the client sends the server's ID once the server's first Initial arrives,
    // and a short header comes only after that, so the table alone routes it.
    var octets: [short_len]u8 = undefined;
    try testing.expectEqual(null, route(short_datagram(connection.transport.identity.original_destination.slice(), &octets)));
}

test "decision 157: a closed connection takes no datagram, though its IDs are in the table" {
    try support.start_engine(null);
    try support.connect();
    const slot = try only_slot();
    const connection = engine.state.connections.at(slot);
    var id: [constants.policy.quic_id_len]u8 = undefined;
    @memcpy(&id, connection.transport.local_ids.active[0].value());
    var octets: [short_len]u8 = undefined;
    internal.transport_closed(connection);
    try testing.expectEqual(null, route(short_datagram(&id, &octets)));
}

test "decision 157: an ID the peer retired frees its entry after its connection's next datagram" {
    try support.start_engine(null);
    try support.connect();
    try support.pump(support.rounds_default);
    const slot = try only_slot();
    const connection = engine.state.connections.at(slot);
    const local = &connection.transport.local_ids;
    // RFC 9000 §5.1.1: the confirmed handshake gave the client spare IDs.
    try testing.expect(local.len > 1);
    const retired = local.active[1];
    var id: [constants.policy.quic_id_len]u8 = undefined;
    @memcpy(&id, retired.value());
    try testing.expectEqual(slot - engine.state.connections.slots.tcp_count, engine.state.connections.routes.find(&id).?);
    // §5.1.2: the peer retired it, as a RETIRE_CONNECTION_ID frame would.
    try local.retire(retired.sequence_number, null);
    _ = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    try testing.expectEqual(null, engine.state.connections.routes.find(&id));
}
