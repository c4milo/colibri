//! The TLS server the client's tests run a connection or a channel against: a `tls.record.Server`
//! over the test identity of `connection_test_support.zig`, its configuration and the client's,
//! the handshake between the two, and the records the server opens and seals. The octets in
//! flight are the ones of `connection_test_support.zig`. Test-only.
const std = @import("std");
const tls = @import("tls");
const support = @import("connection_test_support.zig");

/// The server, its configuration and the client's, outside any stack frame.
pub var server: tls.record.Server align(@alignOf(tls.record.Server)) = undefined;
pub var server_config: tls.record.ServerConfig align(@alignOf(tls.record.ServerConfig)) = undefined;
pub var client_config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
/// The protocol's octets the server opened and has not read, and the ones it writes to seal.
pub var peer_plain: [support.buffer_len]u8 = undefined;
pub var peer_plain_len: usize = 0;
pub var peer_out: [support.buffer_len]u8 = undefined;

/// Rounds a handshake in memory takes at most.
const handshake_rounds_max: usize = 8;
/// The octets a forged record carries after its header: room for a content type and a 16-octet
/// tag.
const forged_octets_len: usize = 32;
/// Octets that are no record chapulin will open: an application_data header over octets no key
/// sealed (RFC 9846 §5.2).
pub const forged_record = "\x17\x03\x03\x00" ++ [1]u8{forged_octets_len} ++ "\x00" ** forged_octets_len;

/// The configurations of a server that selects from `server_protocols` and a client that offers
/// `client_protocols` and trusts the root for `server_name`. With `tickets` the server issues
/// resumption tickets (RFC 9846 §4.6.1).
pub fn prepare_configs(server_protocols: []const []const u8, client_protocols: []const []const u8, server_name: []const u8, tickets: bool) !void {
    try prepare_server(server_protocols, tickets);
    var values = client_values(server_name);
    values.alpn = client_protocols;
    try client_config.init(values);
}

/// The configuration of a server that selects from `server_protocols`, as `prepare_configs` makes
/// it, for a client that converts its own values, as a channel does.
pub fn prepare_server(server_protocols: []const []const u8, tickets: bool) !void {
    try server_config.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .ticket_key = if (tickets) &support.ticket_key else null,
        .alpn = server_protocols,
        .cpu = support.cpu,
    });
}

/// The values of a client that trusts the root for `server_name` and names no protocol.
pub fn client_values(server_name: []const u8) tls.Client {
    return .{ .trust = .{ .web_pki = .{ .anchors = &support.anchors, .server_name = server_name } }, .cpu = support.cpu };
}

/// Starts the server over `server_config`, with nothing in flight either way.
pub fn start_server() !void {
    try server.start(&server_config, support.stream.random(), support.now_seconds);
    support.to_peer_len = 0;
    support.to_client_len = 0;
    support.events_len = 0;
    peer_plain_len = 0;
}

/// The connection of `connection_test_support.zig` over the configurations of `prepare_configs`,
/// and the server, before the handshake runs.
pub fn prepare_tls(server_protocols: []const []const u8, client_protocols: []const []const u8, server_name: []const u8, tickets: bool) !void {
    try prepare_configs(server_protocols, client_protocols, server_name, tickets);
    support.config = .{ .authority = support.authority, .tls = &client_config };
    try support.connection.init(&support.config, support.stream.random(), support.now_seconds, null);
    try start_server();
}

/// Moves the flights between the connection and the server until the server completes, or the
/// client gives up.
pub fn run_handshake() !void {
    var complete = false;
    for (0..handshake_rounds_max) |_| {
        support.client_send();
        if (!complete) complete = server_flight() orelse return;
        try support.client_receive();
        if (complete and support.connection.protocol() != null) return;
        if (support.find(.closed) != null) return;
    }
    return error.TestUnexpectedResult;
}

/// The server reads what the client sent and writes the flight it owes. Returns whether its
/// handshake completed, or null when it refused what it read.
pub fn server_flight() ?bool {
    const progress = server.handshake(support.to_peer[0..support.to_peer_len], support.to_client[support.to_client_len..]) catch return null;
    take_to_peer(progress.consumed);
    support.to_client_len += progress.written;
    return progress.complete;
}

/// Drops the first `consumed` octets the client sent, which the server has read.
pub fn take_to_peer(consumed: usize) void {
    std.mem.copyForwards(u8, &support.to_peer, support.to_peer[consumed..support.to_peer_len]);
    support.to_peer_len -= consumed;
}

/// The server opens every whole record the client sent into `peer_plain`.
pub fn server_open() !void {
    const provider = server.provider();
    for (0..support.buffer_len) |_| {
        const record = try provider.vtable.decrypt_record(provider.context, support.to_peer[0..support.to_peer_len], peer_plain[peer_plain_len..]);
        if (record.content == .incomplete) return;
        take_to_peer(record.consumed);
        if (record.content == .application_data) peer_plain_len += record.plaintext_len;
    }
}

/// The server seals `plaintext` into records for the client.
pub fn server_seal(plaintext: []const u8) !void {
    const provider = server.provider();
    var taken: usize = 0;
    for (0..plaintext.len) |_| {
        if (taken == plaintext.len) return;
        const sealed = try provider.vtable.encrypt_record(provider.context, plaintext[taken..], support.to_client[support.to_client_len..]);
        taken += sealed.consumed;
        support.to_client_len += sealed.written;
    }
}
