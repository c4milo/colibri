//! The tests of the server's QUIC endpoint (`endpoint.zig`): an h3 client in the same process sends
//! every datagram through the endpoint, which routes it (RFC 9000 §5.2), starts the connection
//! from the client's first Initial (§7.2), answers Retry and Version Negotiation (§8.1.2, §6.1),
//! and hands back a connection once it is over.
const std = @import("std");
const quic = @import("quic");
const tls = @import("tls");
const support = @import("quic_test_support.zig");
const tcp_support = @import("connection_test_support.zig");
const constants = @import("constants.zig");

const testing = std.testing;
const endpoint = &support.endpoint;

const ok: u16 = 200;

test "RFC 9000 §7.2, §5.2: a client's first Initial starts a connection, which takes its datagrams" {
    try support.start_endpoint(null);
    try support.connect();
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    const served = support.served;
    try served.respond(fetch.id, ok, &.{}, false);
    _ = try served.write_body(fetch.id, "through the endpoint", true);
    try support.pump(support.rounds_default);
    try testing.expectEqualStrings("through the endpoint", support.content_of(fetch));
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
    // RFC 9000 §5.1.1: once the handshake is confirmed the client holds spare IDs to move to.
    try testing.expect(support.client.remote_ids.active_len() > 1);
    try testing.expectEqual(null, endpoint.ended());
}

/// The deployment's Retry token key (decision 55). Test-only.
const retry_key: [tls.quic.token_key_len]u8 = @splat(retry_key_octet);
const retry_key_octet: u8 = 0x2e;
const retry_lifetime_seconds: u64 = 10;
threadlocal var retry: tls.quic.Retry align(@alignOf(tls.quic.Retry)) = undefined;

test "RFC 9000 §8.1.2: with Retry set, the Initial that returns the Retry's token starts the connection" {
    retry = .{ .key = &retry_key, .lifetime_seconds = retry_lifetime_seconds };
    try support.start_endpoint(&retry);
    try support.connect();
    // RFC 9000 §7.3: the server sends back the Retry's Source Connection ID.
    try testing.expect(support.served.transport.identity.retry_source != null);
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    try support.served.respond(fetch.id, ok, &.{}, true);
    try support.pump(support.rounds_default);
    try testing.expectEqual(ok, fetch.status);
}

/// A long header under a reserved version, padded to the smallest datagram that may start a
/// connection (RFC 9000 §14.1). Test-only.
threadlocal var probe: [quic.constants.datagram_len_min]u8 = undefined;
/// RFC 9000 §15: a version of the reserved pattern 0x?a?a?a?a, which no endpoint speaks.
const reserved_version: u32 = 0x1a2a_3a4a;
const probe_id_len: u8 = 8;
const long_header_form: u8 = 0xc0;

test "RFC 9000 §6.1: a datagram for another version gets Version Negotiation, and no connection" {
    try support.start_endpoint(null);
    @memset(&probe, 0);
    probe[0] = long_header_form;
    std.mem.writeInt(u32, probe[1..][0..@sizeOf(u32)], reserved_version, .big);
    // The Destination and Source Connection ID lengths and IDs (RFC 8999 §5.1).
    probe[5] = probe_id_len;
    probe[6 + probe_id_len] = probe_id_len;
    const from = support.client_address();
    try testing.expectEqual(null, endpoint.receive(&probe, .not_ect, from, support.now_ns));
    var output: [quic.constants.datagram_len_max]u8 = undefined;
    const reply = endpoint.send(&output, support.now_ns).?;
    try testing.expect((try quic.packet.invariant.read_long(reply.octets)).is_version_negotiation());
    try testing.expect(reply.to.eql(&from));
    try testing.expectEqual(null, endpoint.send(&output, support.now_ns));
    // RFC 9000 §5.2.2: a datagram too small to start a connection gets nothing.
    try testing.expectEqual(null, endpoint.receive(probe[0 .. probe.len - 1], .not_ect, from, support.now_ns));
    try testing.expectEqual(null, endpoint.send(&output, support.now_ns));
}

test "RFC 9000 §5.2.2: with every slot in use, a client's Initial starts no connection" {
    try support.start_endpoint(null);
    for (&endpoint.live, &endpoint.connections) |*live, *connection| {
        live.* = true;
        connection.closed = true;
    }
    try support.pump(support.rounds_default);
    try testing.expect(!support.server_started);
    @memset(&endpoint.live, false);
}

test "decision 103: a connection that is over is handed back once, and its slot takes the next client" {
    try support.start_endpoint(null);
    try support.connect();
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    const served = support.served;
    served.shutdown(support.now_ns);
    try served.respond(fetch.id, ok, &.{}, true);
    // RFC 9000 §10.2: the closing state lasts three PTOs, which these rounds pass.
    try support.pump(support.rounds_default * 8);
    try testing.expect(served.ended());
    try testing.expectEqual(served, endpoint.ended().?);
    try testing.expectEqual(null, endpoint.ended());
    try testing.expectEqual(null, endpoint.deadline_ns());
}

test "the Unix seconds a connection's tickets carry count on from the endpoint's start" {
    try support.start_endpoint(null);
    const later_ns = support.now_ns + elapsed_seconds * constants.nanoseconds_per_second;
    endpoint.init(&support.endpoint_config, tcp_support.stream.random(), start_seconds, support.now_ns);
    try testing.expectEqual(start_seconds + elapsed_seconds, endpoint.seconds_at(later_ns));
    // An endpoint started at 0 issues no ticket, however late.
    endpoint.init(&support.endpoint_config, tcp_support.stream.random(), 0, support.now_ns);
    try testing.expectEqual(0, endpoint.seconds_at(later_ns));
}
const start_seconds: u64 = 1_790_000_000;
const elapsed_seconds: u64 = 2;

test "RFC 9000 §9.3: a client that moves is followed, and PATH_CHALLENGE validates its new path" {
    try support.start_endpoint(null);
    try support.connect();
    support.client_port_now = support.client_port + 1;
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    const path = &support.served.transport.path;
    try testing.expectEqual(support.client_port_now, path.address.port);
    try testing.expect(path.validated);
    try testing.expectEqual(fetch.id, support.nth(.request, 0).?.id);
}

test "RFC 9000 §8.1.2: a Retry token returned from another address starts no connection" {
    retry = .{ .key = &retry_key, .lifetime_seconds = retry_lifetime_seconds };
    try support.start_endpoint(&retry);
    // The first round carries the client's Initial and the Retry back.
    try support.pump(1);
    support.client_port_now = support.client_port + 1;
    try support.pump(support.rounds_default);
    try testing.expect(!support.server_started);
}

/// An Initial packet of a few octets, which no datagram may start a connection with. Test-only.
threadlocal var short_initial: [short_initial_len_max]u8 = undefined;
const short_initial_len_max: usize = 64;
const short_payload_len: usize = 20;
const short_id: [constants.quic_id_len]u8 = @splat(short_id_octet);
const short_id_octet: u8 = 0x5a;

test "RFC 9000 §14.1: an Initial in a datagram of fewer than 1,200 octets starts no connection" {
    try support.start_endpoint(null);
    var writer = quic.core.Writer.init(&short_initial);
    try quic.packet.header_write.write_long(&writer, .{
        .type = .initial,
        .dcid = &short_id,
        .scid = &short_id,
        .packet_number = try quic.packet.packet_number.encode(0, null),
        .protected_payload_len = short_payload_len,
    });
    const len = writer.written().len + short_payload_len;
    @memset(short_initial[writer.written().len..len], 0);
    try testing.expectEqual(null, endpoint.receive(short_initial[0..len], .not_ect, support.client_address(), support.now_ns));
    try testing.expect(!std.mem.containsAtLeastScalar(bool, &endpoint.live, 1, true));
}
