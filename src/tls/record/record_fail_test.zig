//! The tests of `fail` (`record.zig`, https://github.com/c4milo/colibri/issues/114): a session
//! that sends a fatal alert the caller names, for an error the caller found itself, and then fails
//! (RFC 9846 §6.2). The peer reads the alert, and a refused call leaves the session as it was.
const std = @import("std");
const tls_provider = @import("tls_provider");
const record = @import("record.zig");
const support = @import("record_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;
const to_server = &support.to_server;
const to_client = &support.to_client;

/// Octets of application data each side seals to show its session still works.
const greeting = "hello";

/// Checks that `provider`'s side reports the alert `description` once, from `origin`.
fn expect_alert(provider: tls_provider.Provider, description: tls_provider.Alert, origin: tls_provider.AlertReport.Origin) !void {
    const report = provider.vtable.take_alert(provider.context).?;
    try testing.expectEqual(origin, report.origin);
    try testing.expectEqual(description, report.description);
}

/// Seals `greeting` through `from` into `wire` and opens it through `to`.
fn expect_data_moves(from: tls_provider.Provider, to: tls_provider.Provider, wire: *support.Wire) !void {
    const sealed = try from.vtable.encrypt_record(from.context, greeting, wire.free());
    try testing.expectEqual(greeting.len, sealed.consumed);
    wire.len += sealed.written;
    try testing.expectEqualStrings(greeting, support.scratch[0..try support.open_all(to, wire, &support.scratch)]);
}

test "RFC 9846 §6.2: a client's fail sends the alert it names, and the server reads it as fatal" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    to_client.* = .{};
    // RFC 9846 §5.2: a record longer than 2^14 + 256 octets is the error record_overflow names.
    const written = try client.fail(.record_overflow, to_server.free());
    try testing.expectEqual(record.alert_record_len, written);
    to_server.len += written;
    const opener = server.provider();
    try testing.expectError(error.TlsFailed, opener.vtable.decrypt_record(opener.context, to_server.held(), &support.scratch));
    try expect_alert(opener, .record_overflow, .peer);
    // The client failed: it reports the alert it sent, seals nothing, and sends no second alert.
    const sealer = client.provider();
    try expect_alert(sealer, .record_overflow, .local);
    try testing.expectError(error.TlsFailed, sealer.vtable.encrypt_record(sealer.context, greeting, to_server.free()));
    try testing.expectError(error.NotConnected, client.fail(.internal_error, to_server.free()));
}

test "RFC 9846 §6.2: a server's fail sends the alert it names, and the client reads it as fatal" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    to_client.* = .{};
    const written = try server.fail(.decode_error, to_client.free());
    try testing.expectEqual(record.alert_record_len, written);
    to_client.len += written;
    const opener = client.provider();
    try testing.expectError(error.TlsFailed, opener.vtable.decrypt_record(opener.context, to_client.held(), &support.scratch));
    try expect_alert(opener, .decode_error, .peer);
    try expect_alert(server.provider(), .decode_error, .local);
}

test "RFC 9846 §6.2: fail refuses a closure alert, a value no alert holds and a short output, and the session goes on" {
    try support.configure(support.web_pki, .{});
    try support.handshake_both(null);
    to_client.* = .{};
    // RFC 9846 §6.1: close_notify and user_canceled close in order; they are not error alerts.
    try testing.expectError(error.NotErrorAlert, client.fail(.close_notify, to_server.free()));
    try testing.expectError(error.NotErrorAlert, client.fail(.user_canceled, to_server.free()));
    try testing.expectError(error.NotErrorAlert, client.fail(@enumFromInt(255), to_server.free()));
    var short: [record.alert_record_len - 1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, client.fail(.internal_error, &short));
    try testing.expectError(error.NoSpaceLeft, server.fail(.internal_error, &short));
    // Nothing was written and nothing failed: data still moves both ways.
    try testing.expectEqual(0, to_server.len);
    try expect_data_moves(client.provider(), server.provider(), to_server);
    try expect_data_moves(server.provider(), client.provider(), to_client);
    try testing.expectEqual(null, client.provider().vtable.take_alert(client.provider().context));
}

test "RFC 9846 §6: fail sends nothing before the handshake completes or after close_notify" {
    try support.configure(support.web_pki, .{});
    to_server.* = .{};
    try client.start(&support.client_config, support.random(), support.now_seconds, null);
    try testing.expectError(error.NotConnected, client.fail(.internal_error, to_server.free()));
    // The refused call left the session as it was: the client still writes its ClientHello.
    try testing.expect((try client.handshake(&.{}, to_server.free())).written > 0);
    try support.handshake_both(null);
    const closer = client.provider();
    to_server.* = .{};
    to_server.len += try closer.vtable.send_close_notify(closer.context, to_server.free());
    try testing.expectError(error.NotConnected, client.fail(.internal_error, to_server.free()));
}
