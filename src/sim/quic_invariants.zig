//! Invariants 17 to 21 of docs/invariants.md, read off one endpoint of the QUIC connection check
//! after every datagram it sends and every step of the run (design §8 step 9e).
//!
//! Each compares what the endpoint does now against what it did before, so `History` holds that
//! and nothing else. The checks read the endpoint and never change it. A broken one is a
//! `Violation`, which ends the run and names the seed.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const quic_endpoint = @import("quic_endpoint.zig");

const Endpoint = quic_endpoint.Endpoint;
const Sent = quic.connection_send.Sent;
const invariant = quic.packet.invariant;

pub const Violation = error{
    /// Invariant 17: a packet number was used twice in one space, or went backward.
    PacketNumberReused,
    /// Invariant 18: a server sent more than three times what it received before the client's
    /// address was validated (RFC 9000 §8.1).
    AmplificationExceeded,
    /// Invariant 19: a flow control limit this endpoint advertised or was given went down.
    FlowLimitDecreased,
    /// Invariant 20: a datagram went to a connection ID other than the one path's.
    OtherPath,
    /// Invariant 21: colibri asked the suite for a level it holds no keys for.
    KeysUnavailable,
};

/// What one endpoint did so far, which each invariant is measured against.
pub const History = struct {
    /// The largest packet number sent in each space (RFC 9000 §12.3), or null before the first.
    largest_sent: [quic.core.levels_count]?u64,
    /// Octets of every datagram this endpoint sent and received, counted by the harness and not
    /// read off the path, so invariant 18 is checked against the network and not colibri's count.
    octets_sent: u64,
    octets_received: u64,
    /// The flow control limits of the last check (RFC 9000 §4.1).
    receive_limit: u64,
    send_limit: u64,

    pub fn init(history: *History, endpoint: *const Endpoint) void {
        history.* = .{
            .largest_sent = @splat(null),
            .octets_sent = 0,
            .octets_received = 0,
            .receive_limit = endpoint.connection.receive_flow.limit,
            .send_limit = endpoint.connection.send_flow.limit,
        };
    }

    pub fn on_received(history: *History, len: usize) void {
        history.octets_received += len;
    }

    /// Invariants 17, 18 and 20, over one datagram the endpoint just built into `octets`.
    pub fn on_sent(history: *History, endpoint: *const Endpoint, sent: Sent, octets: []const u8) Violation!void {
        assert(octets.len == sent.len);
        history.octets_sent += octets.len;
        // Bounded by the packets one datagram coalesces, one per level (RFC 9000 §12.2).
        for (sent.written()) |packet| {
            const held = &history.largest_sent[@intFromEnum(packet.level)];
            // Invariant 17: numbers only increase within a space (RFC 9000 §12.3).
            if (held.*) |largest| {
                if (packet.packet_number <= largest) return Violation.PacketNumberReused;
            }
            held.* = packet.packet_number;
        }
        try check_amplification(history, endpoint);
        try check_path(endpoint, octets);
    }

    /// Invariants 19 and 21, after any step.
    pub fn check(history: *History, endpoint: *const Endpoint) Violation!void {
        const connection = &endpoint.connection;
        // Invariant 19: both limits are high-water marks (RFC 9000 §4.1, decision 13).
        if (connection.receive_flow.limit < history.receive_limit) return Violation.FlowLimitDecreased;
        if (connection.send_flow.limit < history.send_limit) return Violation.FlowLimitDecreased;
        history.receive_limit = connection.receive_flow.limit;
        history.send_limit = connection.send_flow.limit;
        // Invariant 21: colibri asks only at levels it was told are available.
        if (endpoint.suite.keys_unavailable != 0) return Violation.KeysUnavailable;
    }
};

/// Invariant 18: a server whose client's address is not yet validated sends at most three times
/// what it received (RFC 9000 §8.1). A client is exempt (§21.1.1.1).
fn check_amplification(history: *const History, endpoint: *const Endpoint) Violation!void {
    const connection = &endpoint.connection;
    if (connection.role != .server or connection.path.validated) return;
    const permitted = history.octets_received *| quic.constants.anti_amplification_factor;
    if (history.octets_sent > permitted) return Violation.AmplificationExceeded;
}

/// Invariant 20: every datagram is addressed to the connection ID of the one path the connection
/// holds, which is where its send path addresses every packet.
fn check_path(endpoint: *const Endpoint, octets: []const u8) Violation!void {
    const destination = endpoint.connection.identity.destination().slice();
    const dcid = switch (invariant.form_of(octets[0])) {
        .long => (invariant.read_long(octets) catch return Violation.OtherPath).dcid,
        .short => (invariant.read_short(octets, destination.len) catch return Violation.OtherPath).dcid,
    };
    if (!std.mem.eql(u8, dcid, destination)) return Violation.OtherPath;
}

const testing = std.testing;

/// The endpoints a test drives, placed outside any stack frame (decision 35). Test-only.
var test_client: Endpoint = undefined;
var test_server: Endpoint = undefined;
var test_history: History = undefined;
const test_now_ns: u64 = 1_000_000;

/// The client's first datagram, which is a real one: its ClientHello in a padded Initial.
fn first_datagram() !Sent {
    test_client.init(.client, test_now_ns);
    test_history.init(&test_client);
    return try test_client.send(test_now_ns) orelse error.NothingSent;
}

test "each invariant this file reads is reported when it breaks" {
    const sent = try first_datagram();
    const octets = test_client.output[0..sent.len];
    try test_history.on_sent(&test_client, sent, octets);
    try test_history.check(&test_client);
    // Invariant 17: the same number again in the same space.
    try testing.expectError(Violation.PacketNumberReused, test_history.on_sent(&test_client, sent, octets));
    // Invariant 20: a datagram addressed to another connection ID. The Destination Connection
    // ID of a long header starts after byte 0, the Version and its length octet (RFC 8999 §5.1).
    test_history.init(&test_client);
    const dcid_offset = invariant.first_octet_len + invariant.version_len + invariant.connection_id_length_len;
    octets[dcid_offset] ^= 1;
    try testing.expectError(Violation.OtherPath, test_history.on_sent(&test_client, sent, octets));
    octets[dcid_offset] ^= 1;
    // Invariant 18: a server that has received nothing sends nothing (RFC 9000 §8.1).
    test_server.init(.server, test_now_ns);
    test_history.init(&test_server);
    try testing.expectError(Violation.AmplificationExceeded, test_history.on_sent(&test_server, sent, octets));
    // Invariant 19: a limit below the one seen before.
    test_history.init(&test_client);
    test_history.receive_limit += 1;
    try testing.expectError(Violation.FlowLimitDecreased, test_history.check(&test_client));
    test_history.init(&test_client);
    test_history.send_limit += 1;
    try testing.expectError(Violation.FlowLimitDecreased, test_history.check(&test_client));
    // Invariant 21: the suite was asked for a level it holds no keys for.
    test_history.init(&test_client);
    test_client.suite.keys_unavailable = 1;
    try testing.expectError(Violation.KeysUnavailable, test_history.check(&test_client));
}
