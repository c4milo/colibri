//! What the QUIC session tests share (`quic_test.zig`): a client and a server of one QUIC object,
//! run against each other in memory through the provider, level by level, over the identity the
//! record tests use (`../record/record_test_support.zig`).
const std = @import("std");
const tls_provider = @import("tls_provider");
const crypto = @import("crypto");
const quic = @import("quic.zig");
const values = @import("../values.zig");
const identity = @import("../record/record_test_support.zig");

const Level = tls_provider.Level;
const Writer = tls_provider.core.Writer;

pub var client_config: quic.ClientConfig align(@alignOf(quic.ClientConfig)) = undefined;
pub var server_config: quic.ServerConfig align(@alignOf(quic.ServerConfig)) = undefined;
pub var client: quic.Client align(@alignOf(quic.Client)) = undefined;
pub var server: quic.Server align(@alignOf(quic.Server)) = undefined;
/// Where one level's handshake octets cross, and where a sealed packet lands.
pub var scratch: [scratch_len]u8 = undefined;
pub var packet: [scratch_len]u8 = undefined;

const scratch_len: usize = 32_768;
/// Rounds each side takes before a handshake in memory must have completed.
const rounds_max: usize = 8;

pub const protocols = [_][]const u8{"h3"};
/// Transport parameters, which chapulin carries in the handshake without reading them (RFC 9001
/// §8.2), so any octets do.
pub const client_parameters = "client-parameters";
pub const server_parameters = "server-parameters";

pub const levels = [_]Level{ .initial, .handshake, .application };

/// What the tests vary on the server.
pub const ServerChoice = struct {
    tickets: bool = false,
    suites: []const u16 = &.{},
};

pub fn configure(client_values: values.Client, choice: ServerChoice) !void {
    try client_config.init(client_values);
    try server_config.init(.{
        .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
        .cookie_key = &identity.cookie_key,
        .ticket_key = if (choice.tickets) &identity.ticket_key else null,
        .alpn = &protocols,
        .cipher_suites = choice.suites,
    });
}

pub const web_pki: values.Client = .{
    .trust = .{ .web_pki = .{ .anchors = &identity.anchors, .server_name = "localhost" } },
    .alpn = &protocols,
};

/// Starts both sessions and gives each its transport parameters, which starts chapulin's.
pub fn start_both(resumption: ?values.Resumption) !void {
    try client.start(&client_config, identity.random(), identity.now_seconds, resumption);
    server.start(&server_config, identity.random(), identity.now_seconds);
    try client.provider().set_transport_params(client_parameters);
    try server.provider().set_transport_params(server_parameters);
}

/// Starts both sessions and moves handshake octets between them until both complete.
pub fn handshake_both(resumption: ?values.Resumption) !void {
    try start_both(resumption);
    for (0..rounds_max) |_| {
        try move(client.provider(), server.provider());
        try move(server.provider(), client.provider());
        if (complete(client.provider()) and complete(server.provider())) return;
    }
    return error.TestUnexpectedResult;
}

pub fn complete(provider: tls_provider.QuicProvider) bool {
    return provider.vtable.handshake_complete(provider.context);
}

/// Moves what `from` owes at each level to `to`.
pub fn move(from: tls_provider.QuicProvider, to: tls_provider.QuicProvider) !void {
    for (levels) |level| {
        const written = try from.vtable.write_handshake(from.context, level, &scratch);
        if (written > 0) try to.vtable.provide_handshake(to.context, level, scratch[0..written]);
    }
}

/// The connection IDs the test packets carry, each an octet repeated, and the Packet Number Length
/// they use. RFC 9000 §7.2: a client's first Destination Connection ID is at least 8 octets.
const connection_id_len: usize = 8;
const destination_octet: u8 = 0xdc;
const source_octet: u8 = 0x5c;
pub const destination_id: [connection_id_len]u8 = @splat(destination_octet);
const source_id: [connection_id_len]u8 = @splat(source_octet);
pub const packet_number_len: u8 = 4;

/// RFC 9000 §17.2.2: an Initial packet's first octet is the long form, the fixed bit and type 0,
/// and its low bits the Packet Number Length less one. RFC 9000 §15: version 1.
const initial_first_octet: u8 = 0xc0;
const version_1: u32 = 0x0000_0001;
/// RFC 9000 §16: a two-octet variable-length integer carries 0b01 in its top bits.
const varint_two_octets: u16 = 0x4000;
/// RFC 9000 §17.3.1: a 1-RTT packet's first octet is the short form and the fixed bit, then the
/// Key Phase bit at 0x04.
const short_first_octet: u8 = 0x40;
const key_phase_bit: u8 = 0x04;

/// RFC 9000 §17.2.2: an Initial packet's header through its Packet Number field, for a payload
/// of `payload_len` octets.
pub fn initial_header(packet_number: u32, payload_len: usize, output: []u8) ![]const u8 {
    var writer = Writer.init(output);
    try writer.write_byte(initial_first_octet | (packet_number_len - 1));
    try writer.write_int(u32, version_1);
    try writer.write_byte(destination_id.len);
    try writer.write_bytes(&destination_id);
    try writer.write_byte(source_id.len);
    try writer.write_bytes(&source_id);
    // RFC 9000 §17.2.2: no token.
    try writer.write_byte(0);
    const length = packet_number_len + payload_len + crypto.constants.aead_tag_len;
    try writer.write_int(u16, varint_two_octets | @as(u16, @intCast(length)));
    try writer.write_int(u32, packet_number);
    return writer.written();
}

/// RFC 9000 §17.3.1: a 1-RTT packet's header through its Packet Number field.
pub fn short_header(packet_number: u32, key_phase: bool, output: []u8) ![]const u8 {
    var writer = Writer.init(output);
    const phase: u8 = if (key_phase) key_phase_bit else 0;
    try writer.write_byte(short_first_octet | phase | (packet_number_len - 1));
    try writer.write_bytes(&destination_id);
    try writer.write_int(u32, packet_number);
    return writer.written();
}

/// What the opening side has processed before this packet (RFC 9000 Appendix A.3, RFC 9001 §6.5).
pub const Processed = struct {
    largest: ?u64 = null,
    current_phase_lowest: ?u64 = null,
};

/// Seals `payload` at `level` with `from`, opens the packet with `to`, and returns what opened.
pub fn seal_and_open(from: crypto.Suite, to: crypto.Suite, level: Level, header: []const u8, packet_number: u64, payload: []const u8, processed: Processed) !crypto.suite.Opened {
    const written = try from.vtable.seal(from.context, .{
        .level = level,
        .packet_number = packet_number,
        .header = header,
        .packet_number_len = packet_number_len,
        .payload = payload,
    }, &packet);
    return to.vtable.open(to.context, .{
        .level = level,
        .packet = packet[0..written],
        .packet_number_offset = header.len - packet_number_len,
        .largest_packet_number = processed.largest,
        .current_phase_lowest = processed.current_phase_lowest,
    });
}

/// The payload `seal_and_open` recovered, which follows the Packet Number field.
pub fn opened_payload(header_len: usize, opened: crypto.suite.Opened) []const u8 {
    return packet[header_len..][0..opened.payload_len];
}
