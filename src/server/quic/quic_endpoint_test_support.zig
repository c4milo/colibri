//! The endpoint a QUIC test may route its datagrams through (`quic_test_support.zig`'s
//! `through_endpoint`), and what it reported of the connections it held. Split off
//! `quic_test_support.zig` for length. Test-only.
const std = @import("std");
const tls = @import("tls");
const event = @import("../event.zig");
const quic_connection = @import("quic_connection.zig");
const internal = @import("quic_connection_internal.zig");
const endpoint_module = @import("../endpoint/endpoint.zig");
const support = @import("quic_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");

const QuicConnection = quic_connection.QuicConnection;

/// Two QUIC connections, each with the default receive pool, as the test's own connection has.
/// Test-only.
pub const TestEndpoint = endpoint_module.EndpointOf(.{ .tcp_connections = 0, .quic_connections = connections });
const connections: usize = 2;
pub var endpoint: TestEndpoint align(@alignOf(TestEndpoint)) = undefined;
pub var endpoint_config: endpoint_module.Config align(@alignOf(endpoint_module.Config)) = undefined;

/// The connections the endpoint reported ended, oldest first, and whether it reported `closed`.
pub var ended: [ended_max]event.Ended align(@alignOf(event.Ended)) = undefined;
pub var ended_len: usize = 0;
pub var closed: bool = false;
const ended_max: usize = 8;

/// As `quic_test_support.start`, with every datagram passing through `endpoint`, which starts the
/// server's connection itself, after a Retry when `retry` is set (RFC 9000 §8.1.2).
pub fn start_endpoint(retry: ?*const tls.quic.Retry) !void {
    try support.start();
    support.through_endpoint = true;
    ended_len = 0;
    closed = false;
    endpoint_config = .{ .tls = support.server_values(), .retry = retry };
    try restart();
}

/// Starts `endpoint` again from `endpoint_config`, which a test changed, holding no connection.
pub fn restart() !void {
    try endpoint.init(&endpoint_config, tcp_support.stream.random(), 0, support.now_ns);
}

/// The QUIC connection in the endpoint's lowest slot that holds one, read off the endpoint's
/// fields, as a test reads what a program does not.
pub fn live_connection() ?*QuicConnection {
    for (endpoint.live, 0..) |live, slot| {
        if (live) return endpoint.held.connections.at(@intCast(slot));
    }
    return null;
}

/// Fails the connection in the endpoint's lowest live slot, as colibri does when its peer breaks a
/// rule, and marks the slot changed, as each call through the endpoint does.
pub fn fail_live() void {
    for (endpoint.live, 0..) |live, index| {
        if (!live) continue;
        const slot: u32 = @intCast(index);
        internal.fail(endpoint.held.connections.at(slot));
        endpoint.held.ready.touch(slot);
        endpoint.held.heap.mark_stale(slot);
        return;
    }
    unreachable;
}

/// INV-31: the endpoint's deadline is the soonest its slots hold, each read from its own
/// connection, after any call the fixture makes.
pub fn check_deadline() void {
    var soonest: ?u64 = null;
    for (0..endpoint.live.len) |slot| {
        const at_ns = endpoint.held.deadline_of(@intCast(slot)) orelse continue;
        soonest = @min(soonest orelse at_ns, at_ns);
    }
    std.debug.assert(std.meta.eql(soonest, endpoint.deadline_ns()));
}

/// The id of the request the client sent as `number`, naming the connection the endpoint reported
/// it on.
pub fn id_of(number: u64) event.Id {
    for (support.seen_support.seen[0..support.seen_support.seen_len]) |*entry| {
        if (entry.kind == .request and entry.id == number) return .{ .connection = entry.connection, .number = number };
    }
    unreachable;
}

/// Notes an event only the endpoint reports, which `quic_test_support.keep` hands it.
pub fn note(reported: event.Event) void {
    switch (reported) {
        .ended => |connection| {
            std.debug.assert(ended_len < ended.len);
            ended[ended_len] = connection;
            ended_len += 1;
        },
        .closed => closed = true,
        // QUIC connections alone: no TCP connection owes octets or a close.
        .send, .close => unreachable,
        .request, .body, .trailers, .cancelled, .done, .writable => unreachable,
    }
}
