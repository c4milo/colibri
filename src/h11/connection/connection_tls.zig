//! What colibri checks about a TLS connection before h11 runs on it, and the record layer h11's
//! octets cross once it does (RFC 9112 §9.7, decision 88). h2 has its own
//! (`h2/connection/connection_tls.zig`): the rules on the handshake and on what a record may carry
//! differ, and so does what a failure sends.
//!
//! A connection with no provider is cleartext, and nothing here changes it. A connection with one
//! runs h11 over TLS, and `attach` is the call that says the handshake is done and acceptable.
//!
//! RFC 9112 §9.7: all HTTP data is sent as TLS application data. A record that carries none — a
//! ticket, a key update, a `user_canceled` alert — reaches no h11 parser, and a run of them is
//! bounded. A failure here writes no HTTP octet: the connection closes, and the provider names
//! the alert.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const tls = @import("tls");
const connection = @import("connection.zig");

const Connection = connection.Connection;

/// Why h11 does not run on this TLS connection. The caller closes the transport, and the provider
/// sends the alert.
pub const AttachError = error{
    /// `attach` was called before the handshake finished (RFC 9846 Appendix E.5).
    HandshakeIncomplete,
    /// The handshake selected a protocol other than "http/1.1" (RFC 7301 §3.2).
    AlpnNotHttp11,
    /// The provider reports no version or suite although the handshake is complete.
    ParametersUnknown,
    /// The negotiated version is not TLS 1.3 (decision 45).
    TlsVersionRefused,
    /// The negotiated cipher suite is not one of the three colibri admits (decision 45).
    CipherSuiteRefused,
};

/// Checks a finished handshake, and stores the provider on success.
pub fn attach(target: *Connection, provider: tls.Provider) AttachError!void {
    // A provider is attached once, before any HTTP octet moves in either direction.
    assert(target.provider == null);
    assert(target.phase == .head and target.scanner.scanned == 0 and target.outstanding_len == 0);
    try check(provider);
    target.provider = provider;
    assert(target.provider != null);
}

/// The rules themselves, apart from the storing, so a test and a caller can ask the question
/// without a connection.
pub fn check(provider: tls.Provider) AttachError!void {
    // RFC 9846 Appendix E.5: the application must be able to tell whether the handshake completed,
    // and nothing below is decided until it has.
    if (!provider.is_complete()) return error.HandshakeIncomplete;
    if (provider.vtable.negotiated_alpn(provider.context)) |selected| {
        // RFC 7301 §3.2: the selected protocol is definitive for the connection, so any other
        // selection means h11 does not run here.
        if (!std.mem.eql(u8, selected, tls.constants.alpn_http_1_1)) return error.AlpnNotHttp11;
    }
    // A handshake that selected nothing runs h11 too: RFC 9846 §4.2.2 has a server ignore an
    // extension it does not recognise, and RFC 9112 §9.7 asks for no ALPN (decision 88).
    const negotiated = provider.vtable.negotiated_parameters(provider.context) orelse
        // The handshake is complete, so a provider that reports neither codepoint is one colibri
        // cannot check decision 45 against.
        return error.ParametersUnknown;
    // Decision 45: colibri admits TLS 1.3 alone (RFC 9846 Appendix B.1).
    if (negotiated.version != tls.constants.version_tls_1_3) return error.TlsVersionRefused;
    // Decision 45: and three suites (RFC 9846 Appendix B.4).
    if (!tls.provider.cipher_suite_admitted(negotiated.cipher_suite)) return error.CipherSuiteRefused;
}

/// Why a record did not open or did not go out. Each ends the connection with no HTTP octet.
pub const RecordError = error{
    /// A run of records carrying no data passed its bound. `failure` names it, and the
    /// connection is closed.
    ConnectionFailed,
    /// The provider refused the record. RFC 9846 §6 forbids data in either direction afterwards.
    TlsFailed,
    /// The plaintext buffer cannot hold the record's fragment (RFC 9846 §5.1), or the output
    /// cannot hold one record (§5.2). Nothing moved.
    NoSpaceLeft,
    /// A protected record arrived or was asked for before the keys exist (RFC 9846 §7.1).
    HandshakeIncomplete,
    /// No provider is attached: this is a cleartext connection and its octets need no record.
    NoProvider,
};

/// Why a connection failed on its records, as `Connection.failure` holds it.
pub const Failure = error{
    /// More than `records_without_data_max` records in a row carried no application data.
    RecordsWithoutData,
};

/// What `decrypt` took from the peer's octets.
pub const Decrypted = struct {
    /// Octets of the input the record occupied, header and tag included. 0 means no whole record
    /// was there.
    consumed: usize,
    /// Octets of plaintext written, which are h11's octets and are fed to `receive`.
    plaintext_len: usize,
    /// RFC 9846 §6.1: the peer sent `close_notify`, so its data has ended. No octet the peer
    /// sends afterwards is read.
    end_of_data: bool,
    /// The record was a KeyUpdate, and the provider may now owe its reply (RFC 9846 §4.7.3).
    /// `encrypt` writes the reply ahead of any record it seals, so a caller seals before it opens
    /// the next record.
    owes_handshake: bool = false,
};

/// Opens one record the peer sent. The plaintext buffer is the caller's, and what lands in it is
/// fed to `receive` (design §4.1).
pub fn decrypt(target: *Connection, input: []const u8, plaintext: []u8) RecordError!Decrypted {
    // RFC 9112 §9.7: only a connection secured via TLS carries HTTP as application data, so a
    // cleartext connection's octets pass through no record layer.
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
        // RFC 9846 §5.1: a record that is not whole yet is not an error; the caller reads more.
        .incomplete => .{ .consumed = 0, .plaintext_len = 0, .end_of_data = false },
        .application_data => with_data(target, opened),
        // RFC 9846 §4.7.1: a server may send a NewSessionTicket at any time after the client's
        // Finished, and h11 does nothing with it.
        .new_session_ticket => try without_data(target, opened.consumed),
        // RFC 9846 §4.7.3 makes the answering KeyUpdate the provider's, which `encrypt` writes
        // first.
        .key_update => owing(target, try without_data(target, opened.consumed)),
        // RFC 9846 §4.7.2: colibri never offers post-handshake authentication, so a
        // CertificateRequest after the handshake is one the provider should have refused.
        .certificate_request => error.TlsFailed,
        .alert => try on_alert(target, provider, opened.consumed),
    };
}

/// A record that carried application data, which ends any run of records that carried none.
fn with_data(target: *Connection, opened: tls.provider.Opened) Decrypted {
    target.records_without_data = 0;
    return .{ .consumed = opened.consumed, .plaintext_len = opened.plaintext_len, .end_of_data = false };
}

/// A whole record that yielded no application data. Each is legitimate on its own and an endless
/// run of them is not, and the peer picks how long the run is, so one past the bound ends the
/// connection (`core.constants.records_without_data_max`).
fn without_data(target: *Connection, consumed: usize) RecordError!Decrypted {
    target.records_without_data += 1;
    if (target.records_without_data > core.constants.records_without_data_max) {
        // The failure is the transport's and not a request's, so a server owes no response.
        return target.fail(error.RecordsWithoutData, null);
    }
    return .{ .consumed = consumed, .plaintext_len = 0, .end_of_data = false };
}

/// A record that carried no data and may have left the provider owing a reply.
fn owing(target: *Connection, decrypted: Decrypted) Decrypted {
    target.handshake_owed = true;
    var owed = decrypted;
    owed.owes_handshake = true;
    return owed;
}

/// What an alert record means to the connection (RFC 9846 §6).
fn on_alert(target: *Connection, provider: tls.Provider, consumed: usize) RecordError!Decrypted {
    // RFC 9846 §6: an alert record carries a description, so a provider that classified this
    // record as an alert and then reports none has broken its own contract.
    const report = provider.vtable.take_alert(provider.context) orelse return error.TlsFailed;
    switch (tls.alert.verdict(report)) {
        .end_of_data => {
            // RFC 9112 §9.8: a valid closure alert, which alone completes a body that runs until
            // the close.
            target.close_notify_received = true;
            return .{ .consumed = consumed, .plaintext_len = 0, .end_of_data = true };
        },
        // RFC 9846 §6.1: a user_canceled is followed by a close_notify, so the reader carries on
        // and this record counts against the run that carried no data.
        .keep_reading => return without_data(target, consumed),
        // RFC 9846 §6.2: every other description is an error alert, after which §6 forbids
        // sending or receiving any further data.
        .fatal => return error.TlsFailed,
    }
}

/// Protects h11's octets as one or more records (RFC 9846 §5.2), after the handshake octets the
/// provider owes. A caller with no plaintext calls it too, so an owed reply does not wait for h11
/// to have something to say. `now_ns` is the instant the provider's handshake writing takes.
///
/// RFC 9846 §4.7.3: a KeyUpdate's reply is protected under the keys it replaces, and every record
/// after it under the new ones, so the reply is written first. When the output cannot hold it,
/// nothing is written and nothing is sealed.
pub fn encrypt(target: *Connection, plaintext: []const u8, output: []u8, now_ns: u64) RecordError!tls.provider.Sealed {
    // RFC 9112 §9.7: a cleartext connection writes its octets straight to the transport.
    const provider = target.provider orelse return error.NoProvider;
    assert(plaintext.len == 0 or plaintext.ptr != output.ptr);
    const owed = if (target.handshake_owed) try write_owed(target, provider, output, now_ns) else 0;
    assert(owed <= output.len);
    if (plaintext.len == 0) return .{ .consumed = 0, .written = owed };
    const sealed = provider.vtable.encrypt_record(provider.context, plaintext, output[owed..]) catch |failure| {
        // What the provider owed is written, and goes out whether or not a record fits after it.
        if (failure == error.NoSpaceLeft and owed > 0) return .{ .consumed = 0, .written = owed };
        return switch (failure) {
            error.TlsFailed, error.KeyExhausted => error.TlsFailed,
            error.NoSpaceLeft => error.NoSpaceLeft,
            error.HandshakeIncomplete => error.HandshakeIncomplete,
        };
    };
    assert(sealed.consumed <= plaintext.len and owed + sealed.written <= output.len);
    return .{ .consumed = sealed.consumed, .written = owed + sealed.written };
}

/// Writes what the provider owes after a KeyUpdate, whole, and clears the debt once it is out.
fn write_owed(target: *Connection, provider: tls.Provider, output: []u8, now_ns: u64) RecordError!usize {
    const written = provider.vtable.handshake_write(provider.context, output, now_ns) catch |failure| {
        return switch (failure) {
            error.TlsFailed => error.TlsFailed,
            error.NoSpaceLeft => error.NoSpaceLeft,
        };
    };
    target.handshake_owed = false;
    return written;
}

/// Writes the `close_notify` RFC 9112 §9.8 asks of each side before it closes: a client MUST send
/// one, and a server MUST attempt the exchange.
pub fn close_notify(target: *Connection, output: []u8) RecordError!usize {
    // RFC 9112 §9.8: the closure alerts are TLS's, so a cleartext connection has none to send.
    const provider = target.provider orelse return error.NoProvider;
    return provider.vtable.send_close_notify(provider.context, output) catch error.NoSpaceLeft;
}

test {
    _ = @import("connection_tls_test.zig");
}
