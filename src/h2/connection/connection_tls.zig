//! What colibri checks about a TLS connection before h2 runs on it (RFC 9113 §3.2, §9.2), and
//! where the provider a connection holds is attached (decision 44).
//!
//! A connection with no provider is the cleartext prior-knowledge endpoint of §3.3, which step 4
//! built and nothing here changes. A connection with one runs h2 over TLS, and `attach` is the
//! call that says the handshake is done and the rules §9.2 places on it hold.
//!
//! An ALPN mismatch does not go through `Connection.fail`. That queues a GOAWAY, and §3.2 sends
//! the connection preface only after TLS completes, so there is no HTTP/2 connection to send one
//! on: RFC 7301 §3.2 makes it the provider's fatal `no_application_protocol` alert, value 120.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const constants = @import("../constants.zig");
const connection = @import("connection.zig");

const Connection = connection.Connection;

/// Why h2 does not run on this TLS connection. None of them is an HTTP/2 error: no HTTP/2
/// connection exists yet, so the caller closes the transport and the provider sends the alert.
pub const AttachError = error{
    /// `attach` was called before the handshake finished (RFC 8446 Appendix E.5).
    HandshakeIncomplete,
    /// The handshake selected something other than "h2", or selected nothing. RFC 9113 §3.3:
    /// HTTP/2 connections over TLS MUST use protocol negotiation, and §3.1 makes the identifier
    /// the two octets 0x68 and 0x32.
    AlpnNotH2,
    /// The provider reports no version or suite although the handshake is complete.
    ParametersUnknown,
    /// The negotiated version is not TLS 1.3. RFC 9113 §9.2 makes TLS 1.2 the floor, and
    /// colibri admits 1.3 alone, which is stricter than the floor and so within it (decision 45).
    TlsVersionRefused,
    /// The negotiated cipher suite is not one of the three colibri admits (decision 45).
    CipherSuiteRefused,
};

/// Checks a TLS connection against everything RFC 9113 requires of it before h2 runs, and stores
/// the provider on success. The check order is the one §3.2 and §9.2 imply (invariant 7).
pub fn attach(target: *Connection, provider: tls.Provider) AttachError!void {
    // A provider is attached once, before any h2 octet moves in either direction.
    assert(target.provider == null);
    assert(!target.preface_written and target.preface_read_len == 0);
    try check(provider);
    target.provider = provider;
    assert(target.provider != null);
}

/// The rules themselves, separated from the storing so a test and a caller can ask the question
/// without a connection.
pub fn check(provider: tls.Provider) AttachError!void {
    // RFC 8446 Appendix E.5: the application must be able to tell whether the handshake completed,
    // and nothing below is decided until it has.
    if (!provider.is_complete()) return error.HandshakeIncomplete;
    // RFC 9113 §3.3: HTTP/2 connections over TLS MUST use protocol negotiation, and §3.1 names the
    // identifier. A client's provider reports what the server chose, so any other answer, null
    // included, means h2 does not run here.
    if (!provider.speaks_h2()) return error.AlpnNotH2;
    const negotiated = provider.vtable.negotiated_parameters(provider.context) orelse
        // The handshake is complete, so a provider that reports neither codepoint is one colibri
        // cannot check RFC 9113 §9.2 against, and §9.2's floor is a MUST.
        return error.ParametersUnknown;
    // RFC 9113 §9.2 makes TLS 1.2 the floor for HTTP/2 over TLS, and colibri admits TLS 1.3 alone
    // (decision 45). Admitting less than the floor permits is the endpoint's choice; §7 names
    // INADEQUATE_SECURITY for a transport that does not meet the requirements of §9.2.
    if (negotiated.version != tls.constants.version_tls_1_3) return error.TlsVersionRefused;
    // RFC 8446 Appendix B.4: the suite is a codepoint, and colibri admits the three of §9.1
    // (decision 45). Refusing here needs no part of RFC 9113 Appendix A, whose prohibited suites
    // are TLS 1.2's and are listed by name with no codepoint.
    if (!admits_cipher_suite(negotiated.cipher_suite)) return error.CipherSuiteRefused;
}

/// True when the suite is one colibri admits (RFC 8446 Appendix B.4, decision 45).
fn admits_cipher_suite(suite: u16) bool {
    for (tls.constants.cipher_suites_admitted) |admitted| {
        if (suite == admitted) return true;
    }
    return false;
}

/// Why a record did not open or did not go out. `ConnectionFailed` is an HTTP/2 connection error
/// whose GOAWAY is queued (§5.4.1); the rest end the transport with no HTTP/2 frame, because a
/// connection whose TLS has failed can carry none.
pub const RecordError = error{
    /// RFC 9113 §9.2.3 was broken, or another HTTP/2 rule this file checks. `failure` holds the
    /// code and the GOAWAY is queued.
    ConnectionFailed,
    /// The provider refused the record. RFC 8446 §6 forbids data in either direction afterwards.
    TlsFailed,
    /// The plaintext buffer cannot hold the record's fragment (RFC 8446 §5.1), or the output
    /// cannot hold one record (§5.2). Nothing moved.
    NoSpaceLeft,
    /// A protected record arrived or was asked for before the keys exist (RFC 8446 §7.1).
    HandshakeIncomplete,
    /// No provider is attached: this is a cleartext connection and its octets need no record.
    NoProvider,
};

/// What `decrypt` took from the peer's octets.
pub const Decrypted = struct {
    /// Octets of the input the record occupied, header and tag included. 0 means no whole record
    /// was there.
    consumed: usize,
    /// Octets of plaintext written, which are h2's byte stream and are fed to `receive`.
    plaintext_len: usize,
    /// RFC 8446 §6.1: the peer sent `close_notify`, so its data has ended. No octet the peer
    /// sends afterwards is read.
    end_of_data: bool,
};

/// Opens one record the peer sent and applies the rules RFC 9113 places on what it holds. The
/// plaintext buffer is the caller's, and what lands in it is fed to `receive` (design §4.1).
pub fn decrypt(target: *Connection, input: []const u8, plaintext: []u8, now_ns: u64) RecordError!Decrypted {
    _ = now_ns;
    // RFC 9113 §3.3: a prior-knowledge cleartext connection runs h2 directly over TCP, so its
    // octets pass through no record layer at all.
    const provider = target.provider orelse return error.NoProvider;
    // The provider writes into the caller's buffer and reads the caller's input; the two are
    // never the same storage.
    assert(input.ptr != plaintext.ptr);
    const opened = provider.vtable.decrypt_record(provider.context, input, plaintext) catch |failure| {
        return switch (failure) {
            error.TlsFailed => error.TlsFailed,
            error.NoSpaceLeft => error.NoSpaceLeft,
            error.HandshakeIncomplete => error.HandshakeIncomplete,
        };
    };
    assert(opened.consumed <= input.len and opened.plaintext_len <= plaintext.len);
    return switch (opened.content) {
        // RFC 8446 §5.1: a record that is not whole yet is not an error; the caller reads more.
        .incomplete => .{ .consumed = 0, .plaintext_len = 0, .end_of_data = false },
        .application_data => .{
            .consumed = opened.consumed,
            .plaintext_len = opened.plaintext_len,
            .end_of_data = false,
        },
        // RFC 9113 §9.2.3: a NewSessionTicket and a KeyUpdate are permitted after the handshake,
        // and h2 does nothing with either. RFC 8446 §4.6.3 makes the answering KeyUpdate the
        // provider's, which `handshake_write` carries.
        .new_session_ticket, .key_update => .{
            .consumed = opened.consumed,
            .plaintext_len = 0,
            .end_of_data = false,
        },
        // RFC 9113 §9.2.3: HTTP/2 clients MUST treat a post-handshake CertificateRequest as a
        // connection error of type PROTOCOL_ERROR.
        .certificate_request => return target.fail(constants.error_protocol_error),
        .alert => try on_alert(target, provider, opened.consumed),
    };
}

/// What an alert record means to the connection (RFC 8446 §6).
fn on_alert(target: *Connection, provider: tls.Provider, consumed: usize) RecordError!Decrypted {
    _ = target;
    // RFC 8446 §6: an alert record carries a description, so a provider that classified this
    // record as an alert and then reports none has broken its own contract.
    const report = provider.vtable.take_alert(provider.context) orelse return error.TlsFailed;
    // RFC 8446 §6.1: close_notify tells the recipient that the sender will not send any more
    // messages, which design §8 step 5 makes the end of the h2 byte stream.
    if (tls.alert.is_orderly_close(report)) {
        return .{ .consumed = consumed, .plaintext_len = 0, .end_of_data = true };
    }
    // RFC 8446 §6.2: every other description is an error alert, after which §6 forbids sending or
    // receiving any further data.
    return error.TlsFailed;
}

/// Protects what `write_pending` produced, as one or more records (RFC 8446 §5.2). Both buffers
/// are the caller's.
pub fn encrypt(target: *Connection, plaintext: []const u8, output: []u8) RecordError!tls.provider.Sealed {
    // RFC 9113 §3.3: a cleartext connection writes its frames straight to the transport.
    const provider = target.provider orelse return error.NoProvider;
    assert(plaintext.ptr != output.ptr);
    const sealed = provider.vtable.encrypt_record(provider.context, plaintext, output) catch |failure| {
        return switch (failure) {
            error.TlsFailed, error.KeyExhausted => error.TlsFailed,
            error.NoSpaceLeft => error.NoSpaceLeft,
            error.HandshakeIncomplete => error.HandshakeIncomplete,
        };
    };
    assert(sealed.consumed <= plaintext.len and sealed.written <= output.len);
    return sealed;
}

/// Writes the `close_notify` RFC 8446 §6.1 requires before the write side closes.
pub fn close_notify(target: *Connection, output: []u8) RecordError!usize {
    // RFC 9113 §3.3: a cleartext connection has no TLS to close.
    const provider = target.provider orelse return error.NoProvider;
    return provider.vtable.send_close_notify(provider.context, output) catch error.NoSpaceLeft;
}

const testing = std.testing;

/// A provider the tests drive, which performs no cryptography and answers what the test sets.
/// Test-only.
const Fake = struct {
    complete: bool = true,
    selected: ?[]const u8 = &tls.constants.alpn_h2,
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
    }
};

test "§3.3 and §9.2: h2 runs only on a complete handshake that chose h2 at TLS 1.2 or higher" {
    Fake.init_table();
    var state: Fake = .{};
    try check(state.provider());

    // RFC 8446 Appendix E.5: nothing is decided before the handshake completes.
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
    state = .{ .parameters = .{ .version = tls.constants.version_tls_1_2, .cipher_suite = tls.constants.cipher_suite_aes_128_gcm_sha256 } };
    try testing.expectEqual(error.TlsVersionRefused, check(state.provider()));
    state = .{ .parameters = null };
    try testing.expectEqual(error.ParametersUnknown, check(state.provider()));
}

test "decision 45: the three suites of RFC 8446 §9.1 are admitted and nothing else is" {
    Fake.init_table();
    var state: Fake = .{};
    // RFC 8446 Appendix B.4: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and
    // TLS_CHACHA20_POLY1305_SHA256.
    for (tls.constants.cipher_suites_admitted) |suite| {
        state = .{ .parameters = .{ .version = tls.constants.version_tls_1_3, .cipher_suite = suite } };
        try check(state.provider());
    }
    // RFC 9001 §5.3 excludes TLS_AES_128_CCM_8_SHA256 by name, and RFC 8446 §9.1 makes neither
    // CCM suite a MUST or a SHOULD.
    for ([_]u16{
        tls.constants.cipher_suite_aes_128_ccm_sha256,
        tls.constants.cipher_suite_aes_128_ccm_8_sha256,
    }) |suite| {
        state = .{ .parameters = .{ .version = tls.constants.version_tls_1_3, .cipher_suite = suite } };
        try testing.expectEqual(error.CipherSuiteRefused, check(state.provider()));
    }
}

test "a cleartext connection holds no provider, and attach stores one before any octet moves" {
    Fake.init_table();
    var state: Fake = .{};
    connection.test_connection.init(.server);
    // RFC 9113 §3.3: prior-knowledge cleartext h2 has no TLS connection under it at all.
    try testing.expectEqual(null, connection.test_connection.provider);
    try attach(&connection.test_connection, state.provider());
    try testing.expect(connection.test_connection.provider != null);
    try testing.expect(connection.test_connection.provider.?.speaks_h2());
}

test "§9.2.3: a post-handshake CertificateRequest is a connection error of PROTOCOL_ERROR" {
    Fake.init_table();
    var state: Fake = .{ .content = .certificate_request };
    connection.test_connection.init(.client);
    try attach(&connection.test_connection, state.provider());
    var plaintext: [16]u8 = undefined;
    try testing.expectEqual(
        error.ConnectionFailed,
        decrypt(&connection.test_connection, "record", &plaintext, 0),
    );
    try testing.expectEqual(constants.error_protocol_error, connection.test_connection.failure.?);
}

test "§9.2.3: a NewSessionTicket and a KeyUpdate are consumed and yield no plaintext" {
    Fake.init_table();
    var plaintext: [16]u8 = undefined;
    for ([_]tls.Content{ .new_session_ticket, .key_update }) |content| {
        var state: Fake = .{ .content = content, .body = "ignored" };
        connection.test_connection.init(.client);
        try attach(&connection.test_connection, state.provider());
        const opened = try decrypt(&connection.test_connection, "record", &plaintext, 0);
        try testing.expectEqual(0, opened.plaintext_len);
        try testing.expect(!opened.end_of_data);
        try testing.expect(!connection.test_connection.has_failed());
    }
}

test "RFC 8446 §6.1: a peer close_notify is the end of data, and an error alert ends the transport" {
    Fake.init_table();
    var plaintext: [16]u8 = undefined;
    var state: Fake = .{
        .content = .alert,
        .alert_held = .{ .description = .close_notify, .origin = .peer },
    };
    connection.test_connection.init(.client);
    try attach(&connection.test_connection, state.provider());
    const closed = try decrypt(&connection.test_connection, "record", &plaintext, 0);
    try testing.expect(closed.end_of_data);
    try testing.expectEqual(0, closed.plaintext_len);
    // RFC 8446 §6.1 makes this an orderly close, so no HTTP/2 connection error is raised.
    try testing.expect(!connection.test_connection.has_failed());

    // RFC 8446 §6.2: every other description is an error alert.
    state = .{ .content = .alert, .alert_held = .{ .description = .bad_record_mac, .origin = .local } };
    connection.test_connection.init(.client);
    try attach(&connection.test_connection, state.provider());
    try testing.expectEqual(
        error.TlsFailed,
        decrypt(&connection.test_connection, "record", &plaintext, 0),
    );
}

test "application data reaches the caller's buffer, and a cleartext connection has no record path" {
    Fake.init_table();
    var state: Fake = .{ .body = "frame octets" };
    connection.test_connection.init(.client);
    try attach(&connection.test_connection, state.provider());
    var plaintext: [32]u8 = undefined;
    const opened = try decrypt(&connection.test_connection, "record", &plaintext, 0);
    try testing.expectEqualStrings("frame octets", plaintext[0..opened.plaintext_len]);
    var output: [32]u8 = undefined;
    const sealed = try encrypt(&connection.test_connection, "reply", &output);
    try testing.expectEqual(5, sealed.written);
    try testing.expectEqual(1, try close_notify(&connection.test_connection, &output));

    // RFC 9113 §3.3: a prior-knowledge cleartext connection has no records at all.
    connection.test_connection.init(.server);
    try testing.expectEqual(
        error.NoProvider,
        decrypt(&connection.test_connection, "record", &plaintext, 0),
    );
    try testing.expectEqual(error.NoProvider, encrypt(&connection.test_connection, "reply", &output));
    try testing.expectEqual(error.NoProvider, close_notify(&connection.test_connection, &output));
}
