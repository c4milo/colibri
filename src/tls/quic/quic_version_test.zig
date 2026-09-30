//! Decision 111's server choice through chapulin's `choose_version`: a server whose chooser answers
//! version 2 once the client's transport parameters are here, and rewrites the server's own
//! parameters before EncryptedExtensions carries them. Split out of `quic_test.zig` for length.
const std = @import("std");
const crypto = @import("crypto");
const identity = @import("../record/record_test_support.zig");
const support = @import("quic_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;

/// What the test's chooser was asked. Test-only.
const Asked = struct {
    calls: usize = 0,
    client_parameters_matched: bool = false,
};

/// The server's parameters as the chooser rewrites them, as long as the ones it replaces.
const rewritten = "SERVER-parameters";

comptime {
    std.debug.assert(rewritten.len == support.server_parameters.len);
}

/// Rounds each side takes before a handshake in memory must have completed.
const rounds_max: usize = 8;

/// A payload long enough for RFC 9001 §5.4.2's header protection sample.
const payload = "a payload colibri frames, 32 oct";

fn choose(context: *anyopaque, client_parameters: []const u8, own_parameters: []u8) u32 {
    const asked: *Asked = @ptrCast(@alignCast(context));
    asked.calls += 1;
    asked.client_parameters_matched = std.mem.eql(u8, client_parameters, support.client_parameters);
    @memcpy(own_parameters, rewritten);
    return @intFromEnum(crypto.suite.Version.v2);
}

test "decision 111: a server's chooser picks version 2 once, and its own parameters name it" {
    try support.configure(support.web_pki, .{});
    var asked: Asked = .{};
    try client.start(&support.client_config, identity.random(), identity.now_seconds, null);
    server.start(&support.server_config, identity.random(), identity.now_seconds, .v1);
    server.set_version_chooser(.{ .context = &asked, .choose = choose });
    try client.provider().set_transport_params(support.client_parameters);
    try server.provider().set_transport_params(support.server_parameters);
    // The ClientHello reaches the server, which asks before it answers (chapulin's decision 79).
    try support.move(client.provider(), server.provider());
    try testing.expectEqual(1, asked.calls);
    try testing.expect(asked.client_parameters_matched);
    // RFC 9369 §4.1: the client switches at the server's first long header in version 2, before it
    // reads the server's CRYPTO octets.
    try client.suite().vtable.switch_version(client.suite().context, .v2);
    for (0..rounds_max) |_| {
        try support.move(server.provider(), client.provider());
        try support.move(client.provider(), server.provider());
        if (support.complete(client.provider()) and support.complete(server.provider())) break;
    }
    try testing.expect(support.complete(client.provider()) and support.complete(server.provider()));
    try testing.expectEqual(1, asked.calls);
    // RFC 9368 §3: EncryptedExtensions carried the parameters the chooser rewrote.
    const provider = client.provider();
    try testing.expectEqualStrings(rewritten, provider.vtable.peer_transport_params(provider.context).?);
    // RFC 9369 §4.1: 1-RTT packets go in version 2, the negotiated version.
    var header_storage: [support.packet.len]u8 = undefined;
    const header = try support.short_header(1, false, &header_storage);
    const sealed = try server.suite().vtable.seal(server.suite().context, .{ .level = .application, .version = .v2, .packet_number = 1, .header = header, .packet_number_len = support.packet_number_len, .payload = payload }, &support.packet);
    const opened = try client.suite().vtable.open(client.suite().context, .{ .level = .application, .version = .v2, .packet = support.packet[0..sealed], .packet_number_offset = header.len - support.packet_number_len, .largest_packet_number = null });
    try testing.expectEqualStrings(payload, support.opened_payload(header.len, opened));
    client.close();
    server.close();
}
