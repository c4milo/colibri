//! The tests of `connection_tls.zig`, split out because a hand-written source file stays at or
//! under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const core = @import("core");
const tls = @import("tls");
const connection = @import("connection.zig");
const connection_tls = @import("connection_tls.zig");

const attach = connection_tls.attach;
const check = connection_tls.check;
const decrypt = connection_tls.decrypt;
const encrypt = connection_tls.encrypt;
const close_notify = connection_tls.close_notify;
const Connection = connection.Connection;

const testing = std.testing;

/// A provider the tests drive, which performs no cryptography and answers what the test sets.
/// Test-only.
const Fake = struct {
    complete: bool = true,
    selected: ?[]const u8 = tls.constants.alpn_http_1_1,
    parameters: ?tls.Negotiated = .{
        .version = tls.constants.version_tls_1_3,
        .cipher_suite = tls.constants.cipher_suite_aes_128_gcm_sha256,
    },
    /// What the next `decrypt_record` reports. Test-only.
    content: tls.Content = .application_data,
    /// What the next `take_alert` reports, or null. Test-only.
    alert_held: ?tls.AlertReport = null,
    /// The plaintext the next `decrypt_record` writes. Test-only.
    body: []const u8 = "",
    /// The handshake octets the provider owes, which `handshake_write` hands over whole once.
    /// Test-only.
    owed: []const u8 = "",

    fn alpn(context: *const anyopaque) ?[]const u8 {
        const self: *const Fake = @ptrCast(@alignCast(context));
        return self.selected;
    }
    fn done(context: *const anyopaque) bool {
        const self: *const Fake = @ptrCast(@alignCast(context));
        return self.complete;
    }
    fn parameters_of(context: *const anyopaque) ?tls.Negotiated {
        const self: *const Fake = @ptrCast(@alignCast(context));
        return self.parameters;
    }

    fn provider(self: *Fake) tls.Provider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }

    fn open(context: *anyopaque, input: []const u8, plaintext: []u8) tls.provider.OpenError!tls.provider.Opened {
        const self: *Fake = @ptrCast(@alignCast(context));
        if (self.body.len > plaintext.len) return error.NoSpaceLeft;
        @memcpy(plaintext[0..self.body.len], self.body);
        // The plaintext length is reported whatever the content is, so a test can see that
        // colibri, and not this provider, is what keeps a non-application record out of h2.
        return .{ .consumed = input.len, .plaintext_len = self.body.len, .content = self.content };
    }

    fn seal(context: *anyopaque, plaintext: []const u8, output: []u8) tls.provider.SealError!tls.provider.Sealed {
        _ = context;
        if (output.len < plaintext.len) return error.NoSpaceLeft;
        @memcpy(output[0..plaintext.len], plaintext);
        return .{ .consumed = plaintext.len, .written = plaintext.len };
    }

    fn write_owed(context: *anyopaque, output: []u8, now_ns: u64) tls.provider.HandshakeWriteError!usize {
        _ = now_ns;
        const self: *Fake = @ptrCast(@alignCast(context));
        if (self.owed.len > output.len) return error.NoSpaceLeft;
        @memcpy(output[0..self.owed.len], self.owed);
        defer self.owed = "";
        return self.owed.len;
    }

    fn alert_of(context: *anyopaque) ?tls.AlertReport {
        const self: *Fake = @ptrCast(@alignCast(context));
        defer self.alert_held = null;
        return self.alert_held;
    }

    fn close(context: *anyopaque, output: []u8) tls.provider.CloseError!usize {
        _ = context;
        if (output.len == 0) return error.NoSpaceLeft;
        output[0] = 0;
        return 1;
    }

    var table: tls.VTable = undefined;

    fn init_table() void {
        table.negotiated_alpn = alpn;
        table.handshake_complete = done;
        table.negotiated_parameters = parameters_of;
        table.decrypt_record = open;
        table.encrypt_record = seal;
        table.take_alert = alert_of;
        table.send_close_notify = close;
        table.handshake_write = write_owed;
    }
};

/// The connection and buffers the tests use, outside any stack frame. Test-only.
var test_connection: Connection = undefined;
var test_plaintext: [test_buffer_len]u8 = undefined;
var test_output: [test_buffer_len]u8 = undefined;
const test_buffer_len = 64;

/// A connection of `role` with `state` attached as its provider. Test-only.
fn attached(role: connection.Role, state: *Fake) !*Connection {
    Fake.init_table();
    test_connection.init(role, .{});
    try attach(&test_connection, state.provider());
    return &test_connection;
}

test "decision 88: h11 runs on a finished TLS 1.3 handshake that selected http/1.1 or nothing" {
    Fake.init_table();
    var state: Fake = .{};
    try check(state.provider());
    // RFC 9846 §4.2.2: a server that ignores ALPN selects nothing, and h11 still runs.
    state = .{ .selected = null };
    try check(state.provider());
    // RFC 7301 §3.2: any other selection is definitive, and it is not h11.
    state = .{ .selected = &tls.constants.alpn_h2 };
    try testing.expectEqual(error.AlpnNotHttp11, check(state.provider()));
    state = .{ .selected = "http/1.0" };
    try testing.expectEqual(error.AlpnNotHttp11, check(state.provider()));
    // RFC 9846 Appendix E.5: nothing is decided before the handshake completes.
    state = .{ .complete = false };
    try testing.expectEqual(error.HandshakeIncomplete, check(state.provider()));
    state = .{ .parameters = null };
    try testing.expectEqual(error.ParametersUnknown, check(state.provider()));
}

test "decision 45: TLS 1.3 alone, and the three suites of RFC 9846 §9.1" {
    Fake.init_table();
    var state: Fake = .{ .parameters = .{ .version = tls.constants.version_tls_1_2, .cipher_suite = tls.constants.cipher_suite_aes_128_gcm_sha256 } };
    try testing.expectEqual(error.TlsVersionRefused, check(state.provider()));
    state = .{ .parameters = .{ .version = tls.constants.version_tls_1_3, .cipher_suite = tls.constants.cipher_suite_aes_128_ccm_8_sha256 } };
    try testing.expectEqual(error.CipherSuiteRefused, check(state.provider()));
    state = .{ .parameters = .{ .version = tls.constants.version_tls_1_3, .cipher_suite = tls.constants.cipher_suite_chacha20_poly1305_sha256 } };
    try check(state.provider());
}

test "application data reaches the caller's buffer, and a cleartext connection has no record path" {
    var state: Fake = .{ .body = "GET / HTTP/1.1\r\n" };
    const target = try attached(.server, &state);
    const opened = try decrypt(target, "record", &test_plaintext);
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n", test_plaintext[0..opened.plaintext_len]);
    try testing.expectEqual(1, try close_notify(target, &test_output));
    test_connection.init(.client, .{});
    try testing.expectEqual(error.NoProvider, decrypt(&test_connection, "record", &test_plaintext));
    try testing.expectEqual(error.NoProvider, encrypt(&test_connection, "x", &test_output, 0));
    try testing.expectEqual(error.NoProvider, close_notify(&test_connection, &test_output));
}

test "RFC 9846 §4.7.3: a KeyUpdate yields nothing, and its reply goes out ahead of the next record" {
    var state: Fake = .{ .content = .key_update, .body = "ignored", .owed = "reply" };
    const target = try attached(.client, &state);
    const opened = try decrypt(target, "record", &test_plaintext);
    try testing.expectEqual(0, opened.plaintext_len);
    try testing.expect(opened.owes_handshake);
    const sealed = try encrypt(target, "data", &test_output, 0);
    try testing.expectEqualStrings("replydata", test_output[0..sealed.written]);
    // The reply went out once, and nothing more is owed.
    try testing.expect(!target.handshake_owed);
    const again = try encrypt(target, "more", &test_output, 0);
    try testing.expectEqualStrings("more", test_output[0..again.written]);
}

test "RFC 9846 §6.1: close_notify ends the data, user_canceled does not, and other alerts are fatal" {
    var state: Fake = .{ .content = .alert, .alert_held = .{ .description = .user_canceled, .origin = .peer } };
    const target = try attached(.client, &state);
    const kept = try decrypt(target, "record", &test_plaintext);
    try testing.expect(!kept.end_of_data);
    try testing.expectEqual(1, target.records_without_data);
    state.alert_held = .{ .description = .close_notify, .origin = .peer };
    const closed = try decrypt(target, "record", &test_plaintext);
    try testing.expect(closed.end_of_data and target.close_notify_received);
    state.alert_held = .{ .description = .bad_record_mac, .origin = .local };
    try testing.expectEqual(error.TlsFailed, decrypt(target, "record", &test_plaintext));
    // RFC 9846 §4.7.2: colibri offers no post-handshake authentication.
    state = .{ .content = .certificate_request };
    try testing.expectEqual(error.TlsFailed, decrypt(target, "record", &test_plaintext));
}

test "a run of records carrying no data is bounded, and one carrying data resets it" {
    var state: Fake = .{ .content = .new_session_ticket };
    const target = try attached(.server, &state);
    for (0..core.constants.records_without_data_max) |_| _ = try decrypt(target, "record", &test_plaintext);
    state.content = .application_data;
    _ = try decrypt(target, "record", &test_plaintext);
    try testing.expectEqual(0, target.records_without_data);
    state.content = .new_session_ticket;
    for (0..core.constants.records_without_data_max) |_| _ = try decrypt(target, "record", &test_plaintext);
    try testing.expectEqual(error.ConnectionFailed, decrypt(target, "record", &test_plaintext));
    try testing.expectEqual(error.RecordsWithoutData, target.failure.?);
    // The failure is the transport's: a server owes no response to it.
    try testing.expect(!target.has_pending() and target.should_close());
}

test "RFC 9112 §9.8: over TLS, a body that runs until the close ends only at a close_notify" {
    var state: Fake = .{};
    var target = try attached(.client, &state);
    const input = "HTTP/1.1 200 OK\r\n\r\nrest";
    _ = try target.write_request(&test_output, "GET", "/", &.{.{ .name = "Host", .value = "a" }});
    const head = try target.receive(input);
    _ = try target.receive(input[head.consumed..]);
    // The transport closed with no closure alert: the body may be truncated.
    const cut = target.transport_closed();
    try testing.expect(!cut.ended_body and cut.incomplete);
    try testing.expectEqual(1, cut.unanswered);
    target = try attached(.client, &state);
    _ = try target.write_request(&test_output, "GET", "/", &.{.{ .name = "Host", .value = "a" }});
    const again = try target.receive(input);
    _ = try target.receive(input[again.consumed..]);
    state.content = .alert;
    state.alert_held = .{ .description = .close_notify, .origin = .peer };
    _ = try decrypt(target, "record", &test_plaintext);
    const whole = target.transport_closed();
    try testing.expect(whole.ended_body and !whole.incomplete);
    try testing.expectEqual(0, whole.unanswered);
}
