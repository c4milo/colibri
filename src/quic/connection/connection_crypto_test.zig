//! The tests of `connection_crypto.zig`, split out because a hand-written source file stays at or
//! under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const core = @import("core");
const tls = @import("tls");
const error_code = @import("../error_code.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const identity_module = @import("connection_identity.zig");
const connection_crypto = @import("connection_crypto.zig");

const testing = std.testing;
const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

var test_connection: Connection = undefined;
const test_now_ns: u64 = 1_000_000;

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
/// Octets a test writes a CRYPTO frame into. Larger than any payload below.
const test_output_len: usize = 512;
var test_output: [test_output_len]u8 = undefined;

/// Octets the fake provider remembers of what it was handed. Larger than any test hands it.
const fake_taken_len: usize = 64;

/// The connection-level window the tests grant, large enough that no test is bounded by it.
const test_local_max_data: u64 = 65_536;

/// A provider the tests drive, which runs no handshake and answers what the test sets.
const Fake = struct {
    /// What the last `provide_handshake` was given, and at which level. Test-only.
    taken: [fake_taken_len]u8 = @splat(0),
    taken_len: usize = 0,
    taken_level: ?Level = null,
    /// What the next `write_handshake` produces at `owed_level`. Test-only.
    owed: []const u8 = "",
    owed_level: Level = .initial,
    /// The peer's transport parameters body, or null before they arrive. Test-only.
    peer_body: ?[]const u8 = null,
    /// What the next call fails with, or null. Test-only.
    failure: ?anyerror = null,
    /// What `take_alert` reports once. Test-only.
    alert_held: ?tls.Alert = null,

    fn provider(self: *Fake) tls.QuicProvider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }

    fn set_params(context: *anyopaque, body: []const u8) tls.quic_provider.TransportParamsError!void {
        _ = .{ context, body };
    }
    fn peer_params(context: *const anyopaque) ?[]const u8 {
        const self: *const Fake = @ptrCast(@alignCast(context));
        return self.peer_body;
    }
    fn provide(context: *anyopaque, level: Level, data: []const u8) tls.quic_provider.ProvideError!void {
        const self: *Fake = @ptrCast(@alignCast(context));
        if (self.failure) |held| return @errorCast(held);
        @memcpy(self.taken[0..data.len], data);
        self.taken_len = data.len;
        self.taken_level = level;
    }
    fn write(context: *anyopaque, level: Level, output: []u8) tls.quic_provider.WriteError!usize {
        const self: *Fake = @ptrCast(@alignCast(context));
        if (self.failure) |held| return @errorCast(held);
        if (level != self.owed_level or self.owed.len == 0) return 0;
        if (self.owed.len > output.len) return error.NoSpaceLeft;
        @memcpy(output[0..self.owed.len], self.owed);
        return self.owed.len;
    }
    fn alpn(context: *const anyopaque) ?[]const u8 {
        _ = context;
        return &tls.constants.alpn_h3;
    }
    fn complete(context: *const anyopaque) bool {
        _ = context;
        return false;
    }
    fn alert_of(context: *anyopaque) ?tls.Alert {
        const self: *Fake = @ptrCast(@alignCast(context));
        defer self.alert_held = null;
        return self.alert_held;
    }
    fn exported(context: *anyopaque, label: []const u8, value: ?[]const u8, output: []u8) tls.quic_provider.ExportError!void {
        _ = .{ context, label, value, output };
        // RFC 9846 §7.5 standardises the exporter without obliging a stack to offer it, and no
        // test below needs one.
        return error.Unsupported;
    }

    const table: tls.QuicVTable = .{
        .set_transport_params = set_params,
        .peer_transport_params = peer_params,
        .provide_handshake = provide,
        .write_handshake = write,
        .negotiated_alpn = alpn,
        .handshake_complete = complete,
        .take_alert = alert_of,
        .export_keying_material = exported,
    };
};

fn fresh(role: connection_module.Role) void {
    var parameters = Parameters.initial();
    parameters.initial_max_data = test_local_max_data;
    test_connection.init(.{ .role = role, .local_parameters = parameters, .now_ns = test_now_ns, .identity = test_identity });
}

test "RFC 9001 §4.1.3: a CRYPTO frame's octets reach the provider at their own level" {
    fresh(.client);
    var state: Fake = .{};
    try connection_crypto.receive_crypto(&test_connection, .handshake, .{ .offset = 0, .data = "EE" });
    try connection_crypto.provide_handshake(&test_connection, state.provider());
    try testing.expectEqualStrings("EE", state.taken[0..state.taken_len]);
    try testing.expectEqual(Level.handshake, state.taken_level.?);
    // What the provider took is forgotten, so a second pass hands over nothing.
    state.taken_len = 0;
    try connection_crypto.provide_handshake(&test_connection, state.provider());
    try testing.expectEqual(0, state.taken_len);
}

test "RFC 9000 §19.6: frames out of order reach the provider once the gap fills" {
    fresh(.server);
    var state: Fake = .{};
    try connection_crypto.receive_crypto(&test_connection, .initial, .{ .offset = 5, .data = "world" });
    try connection_crypto.provide_handshake(&test_connection, state.provider());
    // Nothing is in order yet, so the provider was handed nothing.
    try testing.expectEqual(0, state.taken_len);
    try connection_crypto.receive_crypto(&test_connection, .initial, .{ .offset = 0, .data = "hello" });
    try connection_crypto.provide_handshake(&test_connection, state.provider());
    try testing.expectEqualStrings("helloworld", state.taken[0..state.taken_len]);
}

test "RFC 9000 §19.6: what the provider owes becomes a frame at the level's own offset" {
    fresh(.client);
    var state: Fake = .{ .owed = "CH", .owed_level = .initial };
    const first = try connection_crypto.write_crypto(&test_connection, state.provider(), .initial, &test_output);
    try testing.expect(first > 0);
    // The frame is readable as the one colibri wrote, at offset 0.
    var reader = core.Reader.init(test_output[0..first]);
    const read = try @import("../frame/frame.zig").read(&reader);
    try testing.expectEqual(0, read.crypto.offset);
    try testing.expectEqualStrings("CH", read.crypto.data);
    // The next frame continues where that one ended, which is what §19.6's Offset means.
    state.owed = "FIN";
    const second = try connection_crypto.write_crypto(&test_connection, state.provider(), .initial, &test_output);
    var next = core.Reader.init(test_output[0..second]);
    const after = try @import("../frame/frame.zig").read(&next);
    try testing.expectEqual(2, after.crypto.offset);
    try testing.expectEqualStrings("FIN", after.crypto.data);
    // A level the provider owes nothing at writes no frame.
    try testing.expectEqual(0, try connection_crypto.write_crypto(&test_connection, state.provider(), .handshake, &test_output));
}

test "RFC 9001 §8.2: the peer's parameters arrive through the provider and raise the limits" {
    fresh(.client);
    var peer = Parameters.initial();
    peer.initial_max_data = 4096;
    // A server-only parameter (RFC 9000 §18.2), so the read must be told the sender is the peer
    // and not colibri: reading it as a client's own would refuse this and the test would say so.
    peer.stateless_reset_token = @splat(7);
    var body: [test_output_len]u8 = undefined;
    var writer = core.Writer.init(&body);
    try transport_parameters.write(&writer, &peer, .server);
    var state: Fake = .{};
    // Before they arrive there is nothing to take, and that is not an error yet.
    try testing.expect(!try connection_crypto.take_peer_parameters(&test_connection, state.provider()));
    try testing.expectEqual(0, test_connection.send_flow.available());
    state.peer_body = writer.written();
    try testing.expect(try connection_crypto.take_peer_parameters(&test_connection, state.provider()));
    try testing.expectEqual(peer.initial_max_data, test_connection.send_flow.available());
    try testing.expectEqualSlices(u8, &peer.stateless_reset_token.?, &test_connection.peer_parameters.?.stateless_reset_token.?);
    // RFC 9000 §7.4: a peer sends them once, so a second call is a no-op rather than a reapply.
    try testing.expect(try connection_crypto.take_peer_parameters(&test_connection, state.provider()));
}

test "RFC 9001 §8.2: a handshake that carried no parameters is a connection error" {
    fresh(.server);
    try testing.expectError(error.ParametersMissing, connection_crypto.require_peer_parameters(&test_connection));
    try testing.expectEqual(
        error_code.transport_parameter_error,
        connection_crypto.connection_error_code(error.ParametersMissing),
    );
}

test "RFC 9001 §4.8: an alert becomes a CRYPTO_ERROR code, and each failure names its own" {
    fresh(.client);
    var state: Fake = .{ .failure = error.TlsFailed, .alert_held = .handshake_failure };
    try connection_crypto.receive_crypto(&test_connection, .initial, .{ .offset = 0, .data = "x" });
    try testing.expectError(
        error.TlsAlert,
        connection_crypto.provide_handshake(&test_connection, state.provider()),
    );
    // §4.8: the description is added to 0x0100, which is 0x0128 for handshake_failure (40).
    try testing.expectEqual(0x0128, connection_crypto.alert_error_code(.handshake_failure));
    // A provider that fails and names no description is still a connection error.
    var silent: Fake = .{ .failure = error.TlsFailed };
    fresh(.client);
    try connection_crypto.receive_crypto(&test_connection, .initial, .{ .offset = 0, .data = "x" });
    try testing.expectError(
        error.TlsFailed,
        connection_crypto.provide_handshake(&test_connection, silent.provider()),
    );
}

test "each failure carries the code RFC 9000 §20.1 gives it" {
    try testing.expectEqual(error_code.crypto_buffer_exceeded, connection_crypto.connection_error_code(error.CryptoBufferExceeded));
    try testing.expectEqual(error_code.protocol_violation, connection_crypto.connection_error_code(error.WrongLevel));
    try testing.expectEqual(error_code.transport_parameter_error, connection_crypto.connection_error_code(error.ParametersRefused));
    try testing.expectEqual(error_code.internal_error, connection_crypto.connection_error_code(error.NoSpaceLeft));
}
