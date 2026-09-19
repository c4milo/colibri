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

    var table: tls.VTable = undefined;

    fn init_table() void {
        table.negotiated_alpn = alpn;
        table.handshake_complete = done;
        table.negotiated_parameters = parameters_of;
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
