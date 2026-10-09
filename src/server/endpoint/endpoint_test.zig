//! The tests of the server's QUIC endpoint (`endpoint.zig`): an h3 client in the same process sends
//! every datagram through the endpoint, which routes it (RFC 9000 §5.2), starts the connection
//! from the client's first Initial (§7.2), answers Retry and Version Negotiation (§8.1.2, §6.1),
//! and hands back a connection once it is over.
const std = @import("std");
const quic = @import("quic");
const tls = @import("tls");
const support = @import("../quic/quic_test_support.zig");
const internal = @import("../quic/quic_connection_internal.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const constants = @import("../constants.zig");
const endpoint_module = @import("endpoint.zig");

const testing = std.testing;
const endpoint_support = support.endpoint_support;
const endpoint = &endpoint_support.endpoint;

const ok: u16 = 200;

test "RFC 9000 §7.2, §5.2: a client's first Initial starts a connection, which takes its datagrams" {
    try support.start_endpoint(null);
    try support.connect();
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    // Decision 119: the request's id names its connection, and the endpoint answers by it.
    const id = endpoint_support.id_of(fetch.id);
    try testing.expectEqual(1, id.connection.generation);
    try endpoint.respond(id, .{ .status = ok, .end = false });
    _ = try endpoint.write_body(id, .{ .octets = "through the endpoint", .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqualStrings("through the endpoint", support.content_of(fetch));
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
    // RFC 9000 §5.1.1: once the handshake is confirmed the client holds spare IDs to move to.
    try testing.expect(support.client.remote_ids.active_len() > 1);
    try testing.expectEqual(0, endpoint_support.ended_len);
}

/// What the endpoint reports of `octets`, a datagram from `from`.
fn give(octets: []u8, from: quic.PeerAddress) ?server_event.Event {
    return endpoint.receive(.{ .datagram = .{ .octets = octets, .from = from } }, support.now_ns).event;
}

const server_event = @import("../event.zig");

/// The deployment's Retry token key (decision 55). Test-only.
const retry_key: [tls.quic.token_key_len]u8 = @splat(retry_key_octet);
const retry_key_octet: u8 = 0x2e;
const retry_lifetime_seconds: u64 = 10;
threadlocal var retry: tls.quic.Retry align(@alignOf(tls.quic.Retry)) = undefined;

test "RFC 9000 §8.1.2: with Retry set, the Initial that returns the Retry's token starts the connection" {
    // RFC 9369 §4.1: a Retry and its token are in the client's original version, whichever it is.
    defer support.client_version = .v1;
    for ([_]quic.packet.header.Version{ .v1, .v2 }) |version| {
        support.client_version = version;
        retry = .{ .key = &retry_key, .lifetime_seconds = retry_lifetime_seconds };
        try support.start_endpoint(&retry);
        try support.connect();
        // RFC 9000 §7.3: the server sends back the Retry's Source Connection ID.
        try testing.expect(support.served.transport.identity.retry_source != null);
        try testing.expectEqual(version, support.served.transport.versions.original);
        const fetch = try support.request("GET", "/", "");
        try support.pump(support.rounds_default);
        try endpoint.respond(endpoint_support.id_of(fetch.id), .{ .status = ok, .end = true });
        try support.pump(support.rounds_default);
        try testing.expectEqual(ok, fetch.status);
    }
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
    try testing.expectEqual(null, give(&probe, from));
    try testing.expectEqual(null, endpoint_support.live_connection());
    var output: [quic.constants.datagram_len_max]u8 = undefined;
    const reply = endpoint.send_datagram(&output, support.now_ns).?;
    try testing.expect((try quic.packet.invariant.read_long(reply.octets)).is_version_negotiation());
    try testing.expect(reply.to.eql(&from));
    try testing.expectEqual(null, endpoint.send_datagram(&output, support.now_ns));
    // RFC 9000 §5.2.2: a datagram too small to start a connection gets nothing.
    try testing.expectEqual(null, give(probe[0 .. probe.len - 1], from));
    try testing.expectEqual(null, endpoint.send_datagram(&output, support.now_ns));
}

test "decision 111: a server switches a client of version 1 that lists version 2 to version 2" {
    try support.start_endpoint(null);
    try support.connect();
    try testing.expectEqual(.v1, support.served.transport.versions.original);
    try testing.expectEqual(.v2, support.served.transport.versions.negotiated);
    try testing.expectEqual(.v2, support.client.versions.negotiated);
    // RFC 9368 §3: the server's Chosen Version names the version it chose, which the client held
    // to the Negotiated Version (§4).
    try testing.expectEqual(0x6b33_43cf, support.client.peer_parameters.?.version_information.?.chosen_version);
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    try endpoint.respond(endpoint_support.id_of(fetch.id), .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(ok, fetch.status);
}

test "decision 111: a server whose configuration names no version to switch to keeps the client" {
    try support.start_endpoint(null);
    endpoint_support.endpoint_config.switch_to = null;
    try endpoint_support.restart();
    try support.connect();
    try testing.expectEqual(.v1, support.served.transport.versions.negotiated);
    try testing.expectEqual(.v1, support.client.versions.negotiated);
}

test "RFC 9368 §2: a client's first Initial in version 2 starts a connection that runs version 2" {
    support.client_version = .v2;
    defer support.client_version = .v1;
    try support.start_endpoint(null);
    try support.connect();
    try testing.expectEqual(.v2, support.served.transport.versions.original);
    try testing.expectEqual(.v2, support.client.versions.negotiated);
    // RFC 9369 §4.1: a packet of version 1 reaches the connection, which drops it, and the server
    // owes no Version Negotiation packet for a version it speaks (RFC 9000 §6.1).
    @memset(&probe, 0);
    var writer = quic.core.Writer.init(&probe);
    try quic.packet.header_write.write_long(&writer, .{
        .version = .v1,
        .type = .handshake,
        .dcid = support.client.identity.destination().slice(),
        .scid = support.client.identity.source().slice(),
        .packet_number = try quic.packet.packet_number.encode(0, null),
        .protected_payload_len = short_payload_len,
    });
    _ = give(&probe, support.client_address());
    var output: [quic.constants.datagram_len_max]u8 = undefined;
    try testing.expectEqual(null, endpoint.held.connections.replies.take(&output));
}

test "RFC 9000 §5.2.2: with every slot in use, a client's Initial starts no connection" {
    try support.start_endpoint(null);
    // Every slot is taken, and no datagram addresses the connections the test leaves in them.
    var taken: [endpoint.quic.len]server_event.ConnectionHandle = undefined;
    for (&taken, &endpoint.quic) |*handle, *connection| {
        handle.* = endpoint.held.slots.take(.quic).?;
        connection.closed = true;
    }
    try support.pump(support.rounds_default);
    // The client's Initials started nothing: every slot holds what the test put there, and no
    // request came.
    try testing.expectEqual(endpoint.quic.len, endpoint.held.slots.holding());
    try testing.expectEqual(0, support.seen_support.seen_len);
    for (taken) |handle| endpoint.held.slots.release(handle);
}

test "decision 103: a connection that is over is handed back once, and its slot takes the next client" {
    try support.start_endpoint(null);
    try support.connect();
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    const id = endpoint_support.id_of(fetch.id);
    endpoint.shutdown(support.now_ns);
    try endpoint.respond(id, .{ .status = ok, .end = true });
    // RFC 9000 §10.2: the closing state lasts three PTOs, which these rounds pass.
    try support.pump(support.rounds_default * 8);
    // INV-30: the request ended first, then its connection, once, and then the endpoint.
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
    try testing.expectEqual(1, endpoint_support.ended_len);
    try testing.expectEqual(id.connection, endpoint_support.ended[0].connection);
    try testing.expect(endpoint_support.closed);
    try testing.expectEqual(null, endpoint.deadline_ns());
    // The ended connection's id names nothing.
    try testing.expectError(error.RequestUnknown, endpoint.respond(id, .{ .status = ok, .end = true }));
}

test "the Unix seconds a connection's tickets carry count on from the endpoint's start" {
    try support.start_endpoint(null);
    const later_ns = support.now_ns + elapsed_seconds * constants.nanoseconds_per_second;
    try endpoint.init(&endpoint_support.endpoint_config, tcp_support.stream.random(), start_seconds, support.now_ns);
    try testing.expectEqual(start_seconds + elapsed_seconds, endpoint.held.connections.seconds_at(later_ns));
    // An endpoint started at 0 issues no ticket, however late.
    try endpoint.init(&endpoint_support.endpoint_config, tcp_support.stream.random(), 0, support.now_ns);
    try testing.expectEqual(0, endpoint.held.connections.seconds_at(later_ns));
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
        .version = .v1,
        .type = .initial,
        .dcid = &short_id,
        .scid = &short_id,
        .packet_number = try quic.packet.packet_number.encode(0, null),
        .protected_payload_len = short_payload_len,
    });
    const len = writer.written().len + short_payload_len;
    @memset(short_initial[writer.written().len..len], 0);
    try testing.expectEqual(null, give(short_initial[0..len], support.client_address()));
    try testing.expectEqual(null, endpoint_support.live_connection());
}

/// A client's first Initial, padded to RFC 9000 §14.1's 1,200 octets. Test-only.
threadlocal var padded_initial: [padded_initial_len]u8 = undefined;
const padded_initial_len: usize = quic.constants.datagram_len_max;
const padded_payload_len: usize = quic.constants.datagram_len_min;

test "RFC 9000 §7.2: a first Initial whose Destination Connection ID is under 8 octets starts no connection" {
    for ([_]bool{ false, true }) |with_retry| {
        retry = .{ .key = &retry_key, .lifetime_seconds = retry_lifetime_seconds };
        try support.start_endpoint(if (with_retry) &retry else null);
        // Seven octets is one under the RFC's eight, written apart from the constant it checks.
        for ([_]usize{ 0, short_id.len - 1 }) |dcid_len| {
            var writer = quic.core.Writer.init(&padded_initial);
            try quic.packet.header_write.write_long(&writer, .{
                .version = .v1,
                .type = .initial,
                .dcid = short_id[0..dcid_len],
                .scid = &short_id,
                .packet_number = try quic.packet.packet_number.encode(0, null),
                .protected_payload_len = padded_payload_len,
            });
            const len = writer.written().len + padded_payload_len;
            @memset(padded_initial[writer.written().len..len], 0);
            try testing.expectEqual(null, give(padded_initial[0..len], support.client_address()));
            try testing.expectEqual(null, endpoint_support.live_connection());
            // With Retry set, no Retry is owed for it either.
            var output: [quic.constants.datagram_len_max]u8 = undefined;
            try testing.expectEqual(null, endpoint.held.connections.replies.take(&output));
        }
    }
}

/// A log provider for the tests below: one log, given to the connection that asks when `giving`
/// is set, and what the provider was asked. Test-only.
const TestLogs = struct {
    log: quic.qlog.Log,
    buffer: [test_log_len]u8,
    giving: bool,
    opened: u32,
    closed: u32,
    original_destination: [quic.constants.connection_id_len_max]u8,
    original_destination_len: usize,
};
threadlocal var test_logs: TestLogs align(@alignOf(TestLogs)) = undefined;
const test_log_len: usize = 65_536;
const test_schemas = [_][]const u8{ quic.qlog.quic_event_schema, quic.qlog.http3_event_schema };
const test_log_vtable: endpoint_module.LogProvider.VTable = .{ .open = open_test_log, .close = close_test_log };

fn open_test_log(context: *anyopaque, original_destination: []const u8, now_ns: u64) ?*quic.qlog.Log {
    const logs: *TestLogs = @ptrCast(@alignCast(context));
    logs.opened += 1;
    @memcpy(logs.original_destination[0..original_destination.len], original_destination);
    logs.original_destination_len = original_destination.len;
    if (!logs.giving) return null;
    logs.log = quic.qlog.Log.init(&logs.buffer, quic.qlog.Features.none());
    logs.log.start(.{ .vantage_point = .server, .group_id = original_destination, .event_schemas = &test_schemas }, now_ns) catch return null;
    return &logs.log;
}

fn close_test_log(context: *anyopaque, log: *quic.qlog.Log) void {
    const logs: *TestLogs = @ptrCast(@alignCast(context));
    std.debug.assert(log == &logs.log);
    logs.closed += 1;
}

/// An endpoint whose connections ask `test_logs` for their logs.
fn start_logged_endpoint(giving: bool) !void {
    try support.start_endpoint(null);
    test_logs.giving = giving;
    test_logs.opened = 0;
    test_logs.closed = 0;
    endpoint_support.endpoint_config.logs = .{ .context = &test_logs, .vtable = &test_log_vtable };
}

fn expect_in_log(expected: []const u8) !void {
    if (std.mem.indexOf(u8, test_logs.log.bytes(), expected) != null) return;
    std.debug.print("record not in the log: {s}\n", .{expected});
    return error.TestExpectedRecord;
}

test "decision 102: each connection the endpoint starts asks for a log, and hands it back once over" {
    try start_logged_endpoint(true);
    try support.connect();
    try testing.expectEqual(1, test_logs.opened);
    // Main schema §12.1 names a log's file after the original destination connection ID.
    const original = support.served.transport.identity.original_destination.slice();
    try testing.expectEqualSlices(u8, original, test_logs.original_destination[0..test_logs.original_destination_len]);
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    // The QUIC connection's events and h3's go into the one log (h3-events §1.1).
    try expect_in_log("\"name\":\"quic:version_information\"");
    try expect_in_log("\"name\":\"http3:frame_parsed\"");
    endpoint.shutdown(support.now_ns);
    try endpoint.respond(endpoint_support.id_of(fetch.id), .{ .status = ok, .end = true });
    try testing.expectEqual(0, test_logs.closed);
    // RFC 9000 §10.2: the closing state lasts three PTOs, which these rounds pass, and the log
    // comes back with the connection's `ended`.
    try support.pump(support.rounds_default * 8);
    try testing.expectEqual(1, endpoint_support.ended_len);
    try testing.expectEqual(1, test_logs.closed);
}

test "decision 102: a connection the provider gives no log writes none, and hands none back" {
    try start_logged_endpoint(false);
    try support.connect();
    try testing.expectEqual(1, test_logs.opened);
    try testing.expectEqual(null, support.served.transport.qlog.log);
    try testing.expectEqual(null, support.served.h3.options.qlog);
}

test "decision 110 as amended: an endpoint refuses, when it starts, deadlines a connection would refuse" {
    try support.start_endpoint(null);
    const config = &endpoint_support.endpoint_config;
    // A limit of 0 is one `Deadlines.validate` refuses: null says no limit.
    config.deadlines.idle_ns = 0;
    try testing.expectError(error.DeadlineInvalid, endpoint_support.restart());
    // A body rate of one octet a second is one `validate_units` refuses: twice that rate over a
    // window brings less than a unit.
    config.deadlines = .{ .body_rate_min = 1 };
    try testing.expectError(error.DeadlineInvalid, endpoint_support.restart());
    // The default limits are ones an endpoint takes.
    config.deadlines = .{};
    try endpoint_support.restart();
}
