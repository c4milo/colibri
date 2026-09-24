//! One connection of design §9's UDP QUIC endpoints: a `quic.Connection` over a chapulin session,
//! and the storage colibri runs it on. Part of design §8 step 9e, piece 11.
//!
//! The caller's four duties are the loopback check's (`loopback_endpoint.zig`): it derives the
//! Initial keys (RFC 9001 §5.2), gives the provider this endpoint's transport parameters before
//! the handshake (§8.2), places the receive pool (decision 61) and supplies the octets of the
//! streams it sends (decision 57). colibri reads each later level's keys from the suite on its
//! own (decision 62). The application on top, `hq_server.zig` or `hq_client.zig`, owns the
//! streams, and `udp_run.zig` owns the socket and the instant (decision 63).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../../constants.zig");
const chapulin_quic = @import("../chapulin_quic.zig");
const udp = @import("../../udp.zig");

const Parameters = quic.transport_parameters.Parameters;
const StreamProvider = quic.stream.stream_provider.StreamProvider;

pub const Error = quic.connection_datagram.Error || quic.connection_send.Error || quic.connection_recovery.Error ||
    error{
        /// chapulin refused to start or to derive its Initial keys.
        SessionRefused,
    };

/// A datagram `Peer.send` built, the ECN codepoint colibri names for its IP header (decision
/// 68), and the address colibri names for it (decision 72).
pub const Outgoing = struct {
    octets: []const u8,
    ecn: udp.Ecn,
    to: udp.Address,
};

const PeerAddress = quic.peer_address.PeerAddress;

/// A socket address as colibri names a peer's (decision 72): four octets for IPv4 and sixteen for
/// IPv6, and the port.
pub fn peer_address(address: udp.Address) PeerAddress {
    const len: usize = if (address.family == .ipv4) udp.Address.ipv4_bytes else address.bytes.len;
    return PeerAddress.of(address.bytes[0..len], address.port);
}

/// The socket address colibri named, back in rotor's form.
pub fn udp_address(address: PeerAddress) udp.Address {
    if (address.len == udp.Address.ipv4_bytes) return udp.Address.ipv4(address.octets[0..udp.Address.ipv4_bytes].*, address.port);
    assert(address.len == address.octets.len);
    return udp.Address.ipv6(address.octets, address.port, 0);
}

const ReceivedEcn = quic.connection_receive.Datagram.Ecn;

/// The codepoint rotor read off a datagram's IP header, as colibri names it (RFC 9000 §13.4), or
/// Not-ECT when the kernel reported none.
pub fn received_ecn(from: *const udp.Received) ReceivedEcn {
    if (!from.flags.ecn) return .not_ect;
    return switch (from.ecn) {
        .not_ect => .not_ect,
        .ect0 => .ect_0,
        .ect1 => .ect_1,
        .ce => .ecn_ce,
    };
}

/// The codepoint colibri named for a datagram, as rotor sets it (RFC 9000 §13.4).
fn sent_ecn(ecn: quic.connection_send.Ecn) udp.Ecn {
    return switch (ecn) {
        .not_ect => .not_ect,
        .ect_0 => .ect0,
        .ect_1 => .ect1,
        .ecn_ce => .ce,
    };
}

/// The connection IDs a connection starts from (RFC 9000 §7.2, §7.3).
pub const Identity = struct {
    /// The Source Connection ID this endpoint puts in its Initial packets.
    local_source: []const u8,
    /// The Destination Connection ID of the client's first Initial, which both endpoints derive
    /// the Initial keys from (RFC 9001 §5.2).
    original_destination: []const u8,
    /// The client's Source Connection ID, which a server reads off that same Initial.
    peer_source: ?[]const u8 = null,
    /// A server's Retry Source Connection ID, when the Initial it answers returned a Retry token
    /// that carried it (decision 55).
    retry_source: ?[]const u8 = null,
};

/// The connection IDs of a client's first Initial packet, which a server starts a connection
/// from (RFC 9000 §7.2), or null for any other datagram: a short header or another long type
/// belongs to no connection a server that holds none could start.
pub fn first_initial(datagram: []const u8, local_id_len: usize) ?quic.packet.header.Long {
    const parsed = quic.packet.header.read(datagram, local_id_len) catch return null;
    const long = switch (parsed) {
        .long => |held| held,
        else => return null,
    };
    // RFC 9000 §17.2.2: the client's first packet is an Initial.
    if (long.type != .initial) return null;
    return long;
}

/// The Destination Connection ID of a datagram's first packet, which RFC 9000 §5.2 matches to a
/// connection, or null for a packet that names none. §12.2: "Receivers SHOULD ignore any
/// subsequent packets with a different Destination Connection ID than the first packet in the
/// datagram", so the first one routes the whole datagram.
pub fn destination_of(datagram: []const u8, local_id_len: usize) ?[]const u8 {
    const parsed = quic.packet.header.read(datagram, local_id_len) catch return null;
    return switch (parsed) {
        .long => |long| long.dcid,
        .short => |short| short.dcid,
        else => null,
    };
}

/// Octets of the longest address a Retry token binds: an IPv6 address and a port.
pub const token_address_len_max: usize = udp.Address.ipv6_bytes + @sizeOf(u16);

/// The client's address as the opaque octets a Retry token binds. RFC 9000 §8.1.4: a token lets
/// "the server verify that the source IP address and port in client packets remain constant", so
/// it covers both: the address, then the port in network byte order.
pub fn token_address(address: udp.Address, into: *[token_address_len_max]u8) []const u8 {
    const address_len: usize = switch (address.family) {
        .ipv4 => udp.Address.ipv4_bytes,
        .ipv6 => udp.Address.ipv6_bytes,
    };
    @memcpy(into[0..address_len], address.bytes[0..address_len]);
    std.mem.writeInt(u16, into[address_len..][0..@sizeOf(u16)], address.port, .big);
    return into[0 .. address_len + @sizeOf(u16)];
}

/// The Version Negotiation packet a server owes a datagram that asks for a version it does not
/// speak, written into `output`, or null when it owes none. RFC 9000 §6.1: a server "SHOULD send
/// a Version Negotiation packet" when the packet "is large enough to initiate a new connection
/// for any supported version", which §14.1 makes 1,200 octets, and §5.2.2 has it drop a smaller
/// one.
pub fn version_negotiation(datagram: []const u8, output: []u8) ?[]const u8 {
    const invariant = quic.packet.invariant;
    const long = invariant.read_long(datagram) catch return null;
    // RFC 8999 §6: a Version Negotiation packet is never answered with one.
    if (long.is_version_negotiation() or long.version == quic.constants.version_1) return null;
    if (datagram.len < quic.constants.datagram_len_min) return null;
    var writer = quic.core.Writer.init(output);
    // RFC 9000 §17.2.1: the server "SHOULD set the most significant bit of this field (0x40) to
    // 1", so the packet reads as QUIC to a version that uses the Fixed Bit.
    invariant.write_version_negotiation(&writer, version_negotiation_unused_bits, long, &.{quic.constants.version_1}) catch return null;
    return writer.written();
}

/// The seven bits RFC 8999 §6 leaves free, with RFC 9000 §17.2.1's 0x40 set.
const version_negotiation_unused_bits: u7 = 0x40;

pub const Peer = struct {
    connection: quic.Connection,
    session: chapulin_quic.Session,
    send_scratch: quic.connection_send.DefaultScratch,
    scratch: quic.connection_datagram.Scratch,
    pool: quic.stream.stream_incoming.DefaultPool,

    /// Starts the connection and its session. `options` is the session's.
    pub fn init(
        peer: *Peer,
        options: chapulin_quic.Options,
        identity: Identity,
        parameters: Parameters,
        now_ns: u64,
        address: udp.Address,
    ) Error!void {
        const role = options.role;
        peer.connection.init(.{
            .role = role,
            .local_parameters = parameters,
            .now_ns = now_ns,
            .identity = .{
                .local_initial_source = identity.local_source,
                .original_destination = identity.original_destination,
                .peer_initial_source = identity.peer_source,
                .retry_source = identity.retry_source,
            },
            .receive = peer.pool.storage(),
            // Decision 68: rotor reads each datagram's codepoint and sets the one colibri names.
            .ecn_reads = true,
            .ecn_marks = true,
            // Decision 72: where the peer is, which a NAT may change under a client.
            .peer_address = peer_address(address),
        });
        peer.session.init(options);
        peer.send_scratch = .{};
        // RFC 9001 §8.2: the parameters travel in the handshake. `Connection.init` wrote the
        // connection IDs into them (RFC 9000 §7.3).
        var body: [constants.quic_peer_params_len_max]u8 = undefined;
        var writer = quic.core.Writer.init(&body);
        quic.transport_parameters.write(&writer, &peer.connection.local_parameters, role) catch
            return error.SessionRefused;
        peer.session.provider().set_transport_params(writer.written()) catch return error.SessionRefused;
        const suite = peer.session.suite();
        // RFC 9001 §5.2: the Initial keys derive from the client's Destination Connection ID. RFC
        // 9000 §17.2.5.2: after a Retry that is the Retry's Source Connection ID, and "Changing the
        // Destination Connection ID field also results in a change to the keys".
        const keys_destination = identity.retry_source orelse identity.original_destination;
        suite.vtable.install_initial_keys(suite.context, role, keys_destination) catch
            return error.SessionRefused;
    }

    /// Takes one datagram the peer sent from `from`, which arrived with `ecn`. The suite opens it
    /// in place, so `octets` changes.
    pub fn receive(peer: *Peer, octets: []u8, ecn: ReceivedEcn, from: udp.Address, now_ns: u64) Error!quic.connection_datagram.Received {
        return quic.connection_datagram.receive(
            &peer.connection,
            peer.session.suite(),
            peer.session.provider(),
            .{ .octets = octets, .now_ns = now_ns, .ecn = ecn, .from = peer_address(from) },
            &peer.scratch,
        );
    }

    /// Builds the next datagram into `output` and returns it, or null when nothing is owed.
    pub fn send(peer: *Peer, stream_provider: StreamProvider, output: []u8, now_ns: u64) Error!?Outgoing {
        const sent = try quic.connection_send.send(
            &peer.connection,
            peer.session.suite(),
            peer.session.provider(),
            stream_provider,
            &peer.send_scratch,
            output,
            now_ns,
        ) orelse return null;
        assert(sent.len <= output.len);
        return .{ .octets = output[0..sent.len], .ecn = sent_ecn(sent.ecn), .to = udp_address(sent.to) };
    }

    /// The instant this connection next wants to be called at (design §4.2), or null for none.
    pub fn deadline_ns(peer: *Peer) ?u64 {
        const deadline = quic.connection_timer.next(&peer.connection) orelse return null;
        return deadline.at_ns;
    }

    /// Fires whichever deadlines `now_ns` has reached.
    pub fn on_instant(peer: *Peer, now_ns: u64) Error!void {
        const at_ns = peer.deadline_ns() orelse return;
        if (now_ns < at_ns) return;
        _ = try quic.connection_timer.on_instant(&peer.connection, peer.session.suite(), &peer.scratch.recovery, now_ns);
    }

    /// Whether the connection has ended: its closing or draining period is over, or it timed out
    /// (RFC 9000 §10).
    pub fn is_closed(peer: *const Peer) bool {
        return peer.connection.termination.state == .closed;
    }

    /// Ends the connection with the application's `code` (RFC 9000 §10.2): 0 for hq-interop once
    /// every file has arrived, and h3's H3_NO_ERROR, which RFC 9114 §5.2 has a graceful close use.
    pub fn close(peer: *Peer, code: u64) void {
        quic.connection_close.owe(&peer.connection, .{
            .layer = .application,
            .error_code = code,
            // RFC 9000 §19.19: only a transport close (type 0x1c) carries the Frame Type field.
            .frame_type = null,
            .reason = "",
        });
    }
};

const testing = std.testing;

/// A connection ID and a payload length for the test packets. Test-only.
const test_id_octet: u8 = 0x0d;
const test_id_len: usize = 8;
const test_id: [test_id_len]u8 = @splat(test_id_octet);
const test_payload_len: usize = 20;
var test_packet: [quic.constants.datagram_len_min]u8 = undefined;

/// A long header of `long_type` followed by its payload's room, as colibri writes one. Test-only.
fn long_packet(long_type: quic.packet.header.LongType) ![]const u8 {
    var writer = quic.core.Writer.init(&test_packet);
    try quic.packet.header_write.write_long(&writer, .{
        .type = long_type,
        .dcid = &test_id,
        .scid = &test_id,
        .packet_number = try quic.packet.packet_number.encode(0, null),
        .protected_payload_len = test_payload_len,
    });
    const header_len = writer.written().len;
    @memset(test_packet[header_len..][0..test_payload_len], 0);
    return test_packet[0 .. header_len + test_payload_len];
}

test "RFC 9000 §6.1: a server answers an unknown version with Version Negotiation, and only then" {
    var answer: [quic.constants.datagram_len_min]u8 = undefined;
    // A version 1 Initial, expanded to 1,200 octets, asks for a version the server speaks.
    const initial = try long_packet(.initial);
    @memset(test_packet[initial.len..], 0);
    const expanded = test_packet[0..quic.constants.datagram_len_min];
    try testing.expectEqual(null, version_negotiation(expanded, &answer));
    // The same datagram under a reserved version (RFC 9000 §15).
    const reserved_version = [_]u8{ 0x1a, 0x2a, 0x3a, 0x4a };
    @memcpy(test_packet[1..][0..reserved_version.len], &reserved_version);
    const probe = expanded;
    const written = version_negotiation(probe, &answer).?;
    const parsed = try quic.packet.invariant.read_long(written);
    try testing.expect(parsed.is_version_negotiation());
    // RFC 8999 §6: the connection IDs come back swapped, and here they are the same octets.
    try testing.expectEqualSlices(u8, &test_id, parsed.dcid);
    // RFC 9000 §5.2.2: a datagram too small to start a connection gets nothing.
    try testing.expectEqual(null, version_negotiation(probe[0 .. probe.len - 1], &answer));
}

test "RFC 9000 §7.2: a server starts a connection from a client's Initial and nothing else" {
    const found = first_initial(try long_packet(.initial), test_id.len).?;
    try testing.expectEqualSlices(u8, &test_id, found.dcid);
    try testing.expectEqual(null, first_initial(try long_packet(.handshake), test_id.len));
    // A short header, whose Header Form bit is clear (RFC 9000 §17.3.1).
    const short_first_octet: u8 = 0x40;
    @memset(&test_packet, 0);
    test_packet[0] = short_first_octet;
    try testing.expectEqual(null, first_initial(&test_packet, test_id.len));
}

test "RFC 9000 §5.2: a datagram is routed by its first packet's Destination Connection ID" {
    try testing.expectEqualSlices(u8, &test_id, destination_of(try long_packet(.handshake), test_id.len).?);
    // A short header carries no length, so the ID is as long as the ones this endpoint issued.
    const short_first_octet: u8 = 0x40;
    @memset(&test_packet, 0);
    test_packet[0] = short_first_octet;
    @memcpy(test_packet[1..][0..test_id.len], &test_id);
    try testing.expectEqualSlices(u8, &test_id, destination_of(&test_packet, test_id.len).?);
    // A Version Negotiation packet names no connection a server holds (RFC 9000 §6.1): its
    // Header Form bit is set and its Version is 0 (RFC 8999 §6).
    const long_first_octet: u8 = 0x80;
    test_packet[0] = long_first_octet;
    @memset(test_packet[1..][0..quic.packet.invariant.version_len], 0);
    try testing.expectEqual(null, destination_of(&test_packet, test_id.len));
}

test "RFC 9000 §8.1.4: a Retry token binds the client's address and its port" {
    var octets: [token_address_len_max]u8 = undefined;
    const port: u16 = 0x1f90;
    const bound = token_address(udp.Address.ipv4(.{ 192, 0, 2, 7 }, port), &octets);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7, 0x1f, 0x90 }, bound);
    // Another port is another address.
    var other: [token_address_len_max]u8 = undefined;
    try testing.expect(!std.mem.eql(u8, bound, token_address(udp.Address.ipv4(.{ 192, 0, 2, 7 }, port + 1), &other)));
}
