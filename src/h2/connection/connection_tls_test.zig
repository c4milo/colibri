//! The tests of `connection_tls.zig`, split out because a hand-written source file stays at or
//! under 500 lines with its tests included (CLAUDE.md). Every function they drive is already
//! `pub`, so nothing was widened to make the split.
const std = @import("std");
const core = @import("core");
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const connection = @import("connection.zig");
const connection_tls = @import("connection_tls.zig");

const attach = connection_tls.attach;
const check = connection_tls.check;
const decrypt = connection_tls.decrypt;
const encrypt = connection_tls.encrypt;
const close_notify = connection_tls.close_notify;

const testing = std.testing;
const support = @import("connection_test_support.zig");

/// A provider the tests drive, which performs no cryptography and answers what the test sets.
/// Test-only.
const Fake = struct {
    complete: bool = true,
    selected: ?[]const u8 = &tls_provider.constants.alpn_h2,
    parameters: ?tls_provider.Negotiated = .{
        .version = tls_provider.constants.version_tls_1_3,
        .cipher_suite = tls_provider.constants.cipher_suite_aes_128_gcm_sha256,
    },
    /// What the next `decrypt_record` reports. Test-only.
    content: tls_provider.Content = .application_data,
    /// What the next `take_alert` reports, or null. Test-only.
    alert_held: ?tls_provider.AlertReport = null,
    /// The plaintext the next `decrypt_record` writes. Test-only.
    body: []const u8 = "",
    /// The handshake octets the provider owes, which `handshake_write` hands over whole once.
    /// Test-only.
    owed: []const u8 = "",
    /// Whether the next `decrypt_record` refuses the record, owing `refusal_alert` as chapulin
    /// owes the alert of a record it could not open. Test-only.
    refuse: bool = false,
    /// Whether `encrypt_record` refuses to seal. Test-only.
    refuse_seal: bool = false,
    /// Calls to `encrypt_record` and to `send_close_notify`. Test-only.
    seals: u32 = 0,
    closes: u32 = 0,

    fn alpn(context: *const anyopaque) ?[]const u8 {
        const self: *const Fake = @ptrCast(@alignCast(context));
        return self.selected;
    }
    fn done(context: *const anyopaque) bool {
        const self: *const Fake = @ptrCast(@alignCast(context));
        return self.complete;
    }
    fn parameters_of(context: *const anyopaque) ?tls_provider.Negotiated {
        const self: *const Fake = @ptrCast(@alignCast(context));
        return self.parameters;
    }

    fn provider(self: *Fake) tls_provider.Provider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }

    fn open(context: *anyopaque, input: []const u8, plaintext: []u8) tls_provider.provider.OpenError!tls_provider.provider.Opened {
        const self: *Fake = @ptrCast(@alignCast(context));
        if (self.refuse) {
            self.owed = refusal_alert;
            // RFC 9846 §5.2: a record that does not authenticate fails, and its alert is owed.
            return error.TlsFailed;
        }
        if (self.body.len > plaintext.len) return error.NoSpaceLeft;
        @memcpy(plaintext[0..self.body.len], self.body);
        // The plaintext length is reported whatever the content is, so a test can see that
        // colibri, and not this provider, is what keeps a non-application record out of h2.
        return .{ .consumed = input.len, .plaintext_len = self.body.len, .content = self.content };
    }

    fn seal(context: *anyopaque, plaintext: []const u8, output: []u8) tls_provider.provider.SealError!tls_provider.provider.Sealed {
        const self: *Fake = @ptrCast(@alignCast(context));
        self.seals += 1;
        // RFC 9846 §6: a session that failed seals nothing more.
        if (self.refuse_seal) return error.TlsFailed;
        if (output.len < plaintext.len) return error.NoSpaceLeft;
        @memcpy(output[0..plaintext.len], plaintext);
        return .{ .consumed = plaintext.len, .written = plaintext.len };
    }

    fn write_owed(context: *anyopaque, output: []u8, now_ns: u64) tls_provider.provider.HandshakeWriteError!usize {
        _ = now_ns;
        const self: *Fake = @ptrCast(@alignCast(context));
        if (self.owed.len > output.len) return error.NoSpaceLeft;
        @memcpy(output[0..self.owed.len], self.owed);
        defer self.owed = "";
        return self.owed.len;
    }

    fn alert_of(context: *anyopaque) ?tls_provider.AlertReport {
        const self: *Fake = @ptrCast(@alignCast(context));
        defer self.alert_held = null;
        return self.alert_held;
    }

    fn close(context: *anyopaque, output: []u8) tls_provider.provider.CloseError!usize {
        const self: *Fake = @ptrCast(@alignCast(context));
        self.closes += 1;
        if (output.len == 0) return error.NoSpaceLeft;
        output[0] = 0;
        return 1;
    }

    /// A sealed alert record's length in octets, as a provider owes one. Test-only.
    const refusal_alert = "a sealed alert, 24 octets";

    var table: tls_provider.VTable align(@alignOf(tls_provider.VTable)) = undefined;

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

test "§3.3 and §9.2: h2 runs only on a complete handshake that chose h2 at TLS 1.2 or higher" {
    Fake.init_table();
    var state: Fake = .{};
    try check(state.provider());

    // RFC 9846 Appendix E.5: nothing is decided before the handshake completes.
    state = .{ .complete = false };
    try testing.expectEqual(error.HandshakeIncomplete, check(state.provider()));

    // RFC 9113 §3.3: protocol negotiation is required, and §3.1 fixes the identifier.
    state = .{ .selected = null };
    try testing.expectEqual(error.AlpnNotH2, check(state.provider()));
    state = .{ .selected = "http/1.1" };
    try testing.expectEqual(error.AlpnNotH2, check(state.provider()));
    // RFC 9113 §3.2: the "h2c" identifier is never selected over TLS.
    state = .{ .selected = "h2c" };
    try testing.expectEqual(error.AlpnNotH2, check(state.provider()));

    // Decision 45: TLS 1.3 alone, which is inside RFC 9113 §9.2's floor of 1.2.
    state = .{ .parameters = .{ .version = tls_provider.constants.version_tls_1_2, .cipher_suite = tls_provider.constants.cipher_suite_aes_128_gcm_sha256 } };
    try testing.expectEqual(error.TlsVersionRefused, check(state.provider()));
    state = .{ .parameters = null };
    try testing.expectEqual(error.ParametersUnknown, check(state.provider()));
}

test "decision 45: the three suites of RFC 9846 §9.1 are admitted and nothing else is" {
    Fake.init_table();
    var state: Fake = .{};
    // RFC 9846 Appendix B.4: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and
    // TLS_CHACHA20_POLY1305_SHA256.
    for (tls_provider.constants.cipher_suites_admitted) |suite| {
        state = .{ .parameters = .{ .version = tls_provider.constants.version_tls_1_3, .cipher_suite = suite } };
        try check(state.provider());
    }
    // RFC 9001 §5.3 excludes TLS_AES_128_CCM_8_SHA256 by name, and RFC 9846 §9.1 makes neither
    // CCM suite a MUST or a SHOULD.
    for ([_]u16{
        tls_provider.constants.cipher_suite_aes_128_ccm_sha256,
        tls_provider.constants.cipher_suite_aes_128_ccm_8_sha256,
    }) |suite| {
        state = .{ .parameters = .{ .version = tls_provider.constants.version_tls_1_3, .cipher_suite = suite } };
        try testing.expectEqual(error.CipherSuiteRefused, check(state.provider()));
    }
}

test "a cleartext connection holds no provider, and attach stores one before any octet moves" {
    Fake.init_table();
    var state: Fake = .{};
    support.test_connection.init(.server);
    // RFC 9113 §3.3: prior-knowledge cleartext h2 has no TLS connection under it at all.
    try testing.expectEqual(null, support.test_connection.provider);
    try attach(&support.test_connection, state.provider());
    try testing.expect(support.test_connection.provider != null);
    try testing.expect(support.test_connection.provider.?.speaks_h2());
}

test "§9.2.3: a post-handshake CertificateRequest is a connection error of PROTOCOL_ERROR" {
    Fake.init_table();
    var state: Fake = .{ .content = .certificate_request };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    var plaintext: [16]u8 = undefined;
    try testing.expectEqual(
        error.ConnectionFailed,
        decrypt(&support.test_connection, "record", &plaintext, 0),
    );
    try testing.expectEqual(constants.error_protocol_error, support.test_connection.failure.?);
}

test "§9.2.3: a NewSessionTicket and a KeyUpdate are consumed and yield no plaintext" {
    Fake.init_table();
    var plaintext: [16]u8 = undefined;
    for ([_]tls_provider.Content{ .new_session_ticket, .key_update }) |content| {
        var state: Fake = .{ .content = content, .body = "ignored" };
        support.test_connection.init(.client);
        try attach(&support.test_connection, state.provider());
        const opened = try decrypt(&support.test_connection, "record", &plaintext, 0);
        try testing.expectEqual(0, opened.plaintext_len);
        try testing.expect(!opened.end_of_data);
        try testing.expect(!support.test_connection.has_failed());
        // RFC 9846 §4.7.3: only a KeyUpdate may leave a reply owed.
        try testing.expectEqual(content == .key_update, opened.owes_handshake);
    }
}

/// Room for what a fake record opens to. Test-only.
const opened_len_max: usize = 16;

/// Opens one KeyUpdate record, which leaves the provider owing `reply`. Test-only.
fn key_update_owing(state: *Fake, reply: []const u8) !void {
    var plaintext: [opened_len_max]u8 = undefined;
    state.content = .key_update;
    state.owed = reply;
    const opened = try decrypt(&support.test_connection, "record", &plaintext, 0);
    try testing.expect(opened.owes_handshake);
}

test "RFC 9846 §4.7.3: a KeyUpdate's reply goes out ahead of every record sealed after it" {
    Fake.init_table();
    var state: Fake = .{};
    support.test_connection.init(.server);
    try attach(&support.test_connection, state.provider());
    var output: [16]u8 = undefined;
    try key_update_owing(&state, "reply");
    const sealed = try encrypt(&support.test_connection, "data", &output, 0);
    try testing.expectEqual(4, sealed.consumed);
    try testing.expectEqualStrings("replydata", output[0..sealed.written]);
    // With nothing to seal, the owed octets still go out.
    try key_update_owing(&state, "reply");
    const alone = try encrypt(&support.test_connection, "", &output, 0);
    try testing.expectEqual(0, alone.consumed);
    try testing.expectEqualStrings("reply", output[0..alone.written]);
    // An output that cannot hold the reply takes nothing, and seals nothing after it.
    try key_update_owing(&state, "reply");
    try testing.expectError(error.NoSpaceLeft, encrypt(&support.test_connection, "data", output[0..4], 0));
    try testing.expectEqualStrings("reply", state.owed);
    // Room for the reply and not for a record: the reply alone.
    const tight = try encrypt(&support.test_connection, "data", output[0..7], 0);
    try testing.expectEqual(0, tight.consumed);
    try testing.expectEqualStrings("reply", output[0..tight.written]);
    // Once the reply is out nothing is owed, and the provider is not asked again.
    state.owed = "stray";
    const after = try encrypt(&support.test_connection, "data", &output, 0);
    try testing.expectEqualStrings("data", output[0..after.written]);
}

test "without a KeyUpdate, sealing asks the provider for nothing owed" {
    Fake.init_table();
    // The provider says it owes octets without any KeyUpdate: colibri does not ask, so the
    // common record costs one crossing of the vtable.
    var state: Fake = .{ .owed = "stray" };
    support.test_connection.init(.server);
    try attach(&support.test_connection, state.provider());
    var output: [16]u8 = undefined;
    const sealed = try encrypt(&support.test_connection, "data", &output, 0);
    try testing.expectEqualStrings("data", output[0..sealed.written]);
    try testing.expectEqualStrings("stray", state.owed);
}

test "RFC 9846 §6.1: a peer close_notify is the end of data, and an error alert ends the transport" {
    Fake.init_table();
    var plaintext: [16]u8 = undefined;
    var state: Fake = .{
        .content = .alert,
        .alert_held = .{ .description = .close_notify, .origin = .peer },
    };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    const closed = try decrypt(&support.test_connection, "record", &plaintext, 0);
    try testing.expect(closed.end_of_data);
    try testing.expectEqual(0, closed.plaintext_len);
    // RFC 9846 §6.1 makes this an orderly close, so no HTTP/2 connection error is raised.
    try testing.expect(!support.test_connection.has_failed());

    // RFC 9846 §6.2: every other description is an error alert.
    state = .{ .content = .alert, .alert_held = .{ .description = .bad_record_mac, .origin = .local } };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    try testing.expectEqual(
        error.TlsFailed,
        decrypt(&support.test_connection, "record", &plaintext, 0),
    );
}

test "application data reaches the caller's buffer, and a cleartext connection has no record path" {
    Fake.init_table();
    var state: Fake = .{ .body = "frame octets" };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    var plaintext: [32]u8 = undefined;
    const opened = try decrypt(&support.test_connection, "record", &plaintext, 0);
    try testing.expectEqualStrings("frame octets", plaintext[0..opened.plaintext_len]);
    var output: [32]u8 = undefined;
    const sealed = try encrypt(&support.test_connection, "reply", &output, 0);
    try testing.expectEqual(5, sealed.written);
    try testing.expectEqual(1, try close_notify(&support.test_connection, &output));

    // RFC 9113 §3.3: a prior-knowledge cleartext connection has no records at all.
    support.test_connection.init(.server);
    try testing.expectEqual(
        error.NoProvider,
        decrypt(&support.test_connection, "record", &plaintext, 0),
    );
    try testing.expectEqual(error.NoProvider, encrypt(&support.test_connection, "reply", &output, 0));
    try testing.expectEqual(error.NoProvider, close_notify(&support.test_connection, &output));
}

test "RFC 9846 §5.1: a record that is not whole consumes nothing, whatever the provider reports" {
    Fake.init_table();
    // This provider reports octets consumed alongside `incomplete`, which is a contradiction. The
    // caller must be told nothing was taken, or it would drop the start of the record it is
    // still waiting for.
    var state: Fake = .{ .content = .incomplete, .body = "partial" };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    var plaintext: [32]u8 = undefined;
    const opened = try decrypt(&support.test_connection, "half a record", &plaintext, 0);
    try testing.expectEqual(0, opened.consumed);
    try testing.expectEqual(0, opened.plaintext_len);
    try testing.expect(!opened.end_of_data);
}

test "RFC 9846 §6.1: a user_canceled is neither the end of data nor an error" {
    Fake.init_table();
    var plaintext: [16]u8 = undefined;
    var state: Fake = .{
        .content = .alert,
        .alert_held = .{ .description = .user_canceled, .origin = .peer },
    };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    // RFC 9846 §6.1: the alert precedes a close_notify, so the reader carries on and waits.
    const opened = try decrypt(&support.test_connection, "record", &plaintext, 0);
    try testing.expect(!opened.end_of_data);
    try testing.expectEqual(0, opened.plaintext_len);
    try testing.expect(!support.test_connection.has_failed());
    // It carried no data, so it counts against the run that bounds a hostile stream of them.
    try testing.expectEqual(1, support.test_connection.records_without_data);
    // RFC 9846 §6.1: the close_notify that must follow is what ends the peer's data.
    state.alert_held = .{ .description = .close_notify, .origin = .peer };
    const closed = try decrypt(&support.test_connection, "record", &plaintext, 0);
    try testing.expect(closed.end_of_data);
}

test "a run of records carrying no data is bounded, and one past it is ENHANCE_YOUR_CALM" {
    Fake.init_table();
    var state: Fake = .{ .content = .new_session_ticket };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    var plaintext: [16]u8 = undefined;
    // The bound is what a peer may send, so the last permitted record still succeeds.
    for (0..core.constants.records_without_data_max) |_| {
        const opened = try decrypt(&support.test_connection, "record", &plaintext, 0);
        try testing.expectEqual(0, opened.plaintext_len);
    }
    try testing.expect(!support.test_connection.has_failed());
    // RFC 9113 §10.5: a peer generating excessive load is a connection error.
    try testing.expectEqual(
        error.ConnectionFailed,
        decrypt(&support.test_connection, "record", &plaintext, 0),
    );
    try testing.expectEqual(constants.error_enhance_your_calm, support.test_connection.failure.?);
}

test "a record carrying data ends the run, so an interleaved stream never reaches the bound" {
    Fake.init_table();
    var state: Fake = .{};
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    var plaintext: [16]u8 = undefined;
    // Many times the bound in total, with one record carrying data after every full run of them.
    for (0..interleaved_runs) |_| {
        state.content = .new_session_ticket;
        state.body = "";
        for (0..core.constants.records_without_data_max) |_| {
            _ = try decrypt(&support.test_connection, "record", &plaintext, 0);
        }
        state.content = .application_data;
        state.body = "h2";
        const opened = try decrypt(&support.test_connection, "record", &plaintext, 0);
        try testing.expectEqual(2, opened.plaintext_len);
    }
    try testing.expect(!support.test_connection.has_failed());
    try testing.expectEqual(0, support.test_connection.records_without_data);
}

/// Runs of records carrying no data the interleaving test drives, each a whole bound's worth.
const interleaved_runs: u32 = 8;

/// Room for what `expect_ended` writes and opens: the fake's alert, and the plaintext of one
/// record it offers. Test-only.
const ended_output_len = 64;
const ended_plaintext_len = 16;

/// Checks what a connection whose record layer failed still does. It reads no record and writes no
/// frame, `encrypt` writes `alert` once and seals nothing, and no close_notify follows. Test-only.
fn expect_ended(state: *Fake, alert: []const u8) !void {
    const target = &support.test_connection;
    try testing.expect(target.has_failed());
    try testing.expect(!target.has_pending());
    var output: [ended_output_len]u8 = undefined;
    try testing.expectEqual(0, target.write_pending(&output, 0));
    // A record that would open is not read.
    state.* = .{ .body = "late", .owed = state.owed, .seals = state.seals, .closes = state.closes };
    var plaintext: [ended_plaintext_len]u8 = undefined;
    try testing.expectEqual(error.TlsFailed, decrypt(target, "record", &plaintext, 0));
    const first = try encrypt(target, "data", &output, 0);
    try testing.expectEqual(0, first.consumed);
    try testing.expectEqualStrings(alert, output[0..first.written]);
    const second = try encrypt(target, "data", &output, 0);
    try testing.expectEqual(0, second.consumed + second.written);
    try testing.expectEqual(0, try close_notify(target, &output));
    try testing.expectEqual(0, state.closes);
}

test "RFC 9846 §5.2: a record the provider refuses ends the connection, and only its alert goes out" {
    Fake.init_table();
    var state: Fake = .{ .refuse = true };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    var plaintext: [16]u8 = undefined;
    try testing.expectEqual(error.TlsFailed, decrypt(&support.test_connection, "record", &plaintext, 0));
    try expect_ended(&state, Fake.refusal_alert);
    try testing.expectEqual(0, state.seals);
}

test "RFC 9846 §6.2: an error alert from the peer ends the connection, and nothing is owed" {
    Fake.init_table();
    var state: Fake = .{ .content = .alert, .alert_held = .{ .description = .bad_record_mac, .origin = .peer } };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    var plaintext: [16]u8 = undefined;
    try testing.expectEqual(error.TlsFailed, decrypt(&support.test_connection, "record", &plaintext, 0));
    try expect_ended(&state, "");
    try testing.expectEqual(0, state.seals);
}

test "RFC 9846 §6: a record the provider will not seal ends the connection too" {
    Fake.init_table();
    var state: Fake = .{ .refuse_seal = true };
    support.test_connection.init(.client);
    try attach(&support.test_connection, state.provider());
    var output: [64]u8 = undefined;
    try testing.expectEqual(error.TlsFailed, encrypt(&support.test_connection, "data", &output, 0));
    try expect_ended(&state, "");
    try testing.expectEqual(1, state.seals);
}
