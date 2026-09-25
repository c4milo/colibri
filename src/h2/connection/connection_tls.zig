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
const core = @import("core");
const tls = @import("tls");
const constants = @import("../constants.zig");
const connection = @import("connection.zig");

const Connection = connection.Connection;

/// Why h2 does not run on this TLS connection. None of them is an HTTP/2 error: no HTTP/2
/// connection exists yet, so the caller closes the transport and the provider sends the alert.
pub const AttachError = error{
    /// `attach` was called before the handshake finished (RFC 9846 Appendix E.5).
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
    // RFC 9846 Appendix E.5: the application must be able to tell whether the handshake completed,
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
    // RFC 9846 Appendix B.4: the suite is a codepoint, and colibri admits the three of §9.1
    // (decision 45). Refusing here needs no part of RFC 9113 Appendix A, whose prohibited suites
    // are TLS 1.2's and are listed by name with no codepoint.
    if (!tls.provider.cipher_suite_admitted(negotiated.cipher_suite)) return error.CipherSuiteRefused;
}

/// Why a record did not open or did not go out. `ConnectionFailed` is an HTTP/2 connection error
/// whose GOAWAY is queued (§5.4.1); the rest end the transport with no HTTP/2 frame, because a
/// connection whose TLS has failed can carry none.
pub const RecordError = error{
    /// RFC 9113 §9.2.3 was broken, or another HTTP/2 rule this file checks. `failure` holds the
    /// code and the GOAWAY is queued.
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

/// What `decrypt` took from the peer's octets.
pub const Decrypted = struct {
    /// Octets of the input the record occupied, header and tag included. 0 means no whole record
    /// was there.
    consumed: usize,
    /// Octets of plaintext written, which are h2's byte stream and are fed to `receive`.
    plaintext_len: usize,
    /// RFC 9846 §6.1: the peer sent `close_notify`, so its data has ended. No octet the peer
    /// sends afterwards is read.
    end_of_data: bool,
    /// The record was a KeyUpdate, and the provider may now owe its reply (RFC 9846 §4.6.3).
    /// `encrypt` writes the reply ahead of any record it seals, so a caller seals before it opens
    /// the next record, and at most one reply is owed at a time.
    owes_handshake: bool = false,
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
        // RFC 9846 §5.1: a record that is not whole yet is not an error; the caller reads more.
        // It consumed nothing, so it is not a record that carried no data — it is not a record.
        .incomplete => .{ .consumed = 0, .plaintext_len = 0, .end_of_data = false },
        .application_data => with_data(target, opened),
        // RFC 9113 §9.2.3: a NewSessionTicket and a KeyUpdate are permitted after the handshake,
        // and h2 does nothing with either.
        .new_session_ticket => try without_data(target, opened.consumed),
        // RFC 9846 §4.6.3 makes the answering KeyUpdate the provider's, which `handshake_write`
        // carries and `encrypt` writes first.
        .key_update => owing(target, try without_data(target, opened.consumed)),
        // RFC 9113 §9.2.3: HTTP/2 clients MUST treat a post-handshake CertificateRequest as a
        // connection error of type PROTOCOL_ERROR.
        .certificate_request => return target.fail(constants.error_protocol_error),
        .alert => try on_alert(target, provider, opened.consumed),
    };
}

/// A record that carried application data, which ends any run of records that carried none.
fn with_data(target: *Connection, opened: tls.provider.Opened) Decrypted {
    target.records_without_data = 0;
    return .{
        .consumed = opened.consumed,
        .plaintext_len = opened.plaintext_len,
        .end_of_data = false,
    };
}

/// A whole record that yielded no application data: a ticket, a key update, or a `user_canceled`
/// alert. Each is legitimate on its own and an endless run of them is not, and the peer picks how
/// long the run is — RFC 9846 §6.1 even obliges colibri to keep reading past a `user_canceled`
/// rather than close. So the run is bounded here, and one past the bound ends the connection.
fn without_data(target: *Connection, consumed: usize) RecordError!Decrypted {
    target.records_without_data += 1;
    // RFC 9113 §10.5: a peer generating excessive load is a connection error of
    // ENHANCE_YOUR_CALM, which is what a run of records carrying nothing is.
    if (target.records_without_data > core.constants.records_without_data_max) {
        return target.fail(constants.error_enhance_your_calm);
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
    return switch (tls.alert.verdict(report)) {
        // RFC 9846 §6.1: close_notify tells the recipient that the sender will not send any more
        // messages, which design §8 step 5 makes the end of the h2 byte stream.
        .end_of_data => .{ .consumed = consumed, .plaintext_len = 0, .end_of_data = true },
        // RFC 9846 §6.1: a user_canceled is followed by a close_notify, so the reader carries on
        // and this record counts against the run that carried no data.
        .keep_reading => try without_data(target, consumed),
        // RFC 9846 §6.2: every other description is an error alert, after which §6 forbids
        // sending or receiving any further data.
        .fatal => error.TlsFailed,
    };
}

/// Protects what `write_pending` produced, as one or more records (RFC 9846 §5.2), after the
/// handshake octets the provider owes. Both buffers are the caller's, and a caller with no
/// plaintext calls it too, so an owed reply does not wait for h2 to have something to say.
///
/// RFC 9846 §4.6.3: a KeyUpdate's reply is protected under the keys it replaces, and every record
/// after it under the new ones, so the reply is written first. When the output cannot hold it,
/// nothing is written and nothing is sealed.
pub fn encrypt(target: *Connection, plaintext: []const u8, output: []u8, now_ns: u64) RecordError!tls.provider.Sealed {
    // RFC 9113 §3.3: a cleartext connection writes its frames straight to the transport.
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

/// Writes the `close_notify` RFC 9846 §6.1 requires before the write side closes.
pub fn close_notify(target: *Connection, output: []u8) RecordError!usize {
    // RFC 9113 §3.3: a cleartext connection has no TLS to close.
    const provider = target.provider orelse return error.NoProvider;
    return provider.vtable.send_close_notify(provider.context, output) catch error.NoSpaceLeft;
}

test {
    _ = @import("connection_tls_test.zig");
}
