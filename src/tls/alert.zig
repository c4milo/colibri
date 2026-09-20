//! TLS alerts as values (RFC 9846 §6). colibri never parses an alert record: a provider reports
//! the description it raised or received, and colibri decides what to do with the connection.
//!
//! QUIC mode reuses `Alert` unchanged, where RFC 9001 §4.8 maps each description to the QUIC error
//! code 0x0100 plus its value.
const std = @import("std");

/// The alert descriptions RFC 9846 §6 names. The enum is not exhaustive, because §6 requires an
/// endpoint that receives an unknown alert description to treat it as a fatal error, which a
/// closed enum could not carry.
pub const Alert = enum(u8) {
    /// RFC 9846 §6.1: the sender will not send any more messages on this connection.
    close_notify = 0,
    /// RFC 9846 §6.2: an inappropriate message was received.
    unexpected_message = 10,
    /// RFC 9846 §6.2: a record was received with an incorrect MAC or failed to decrypt.
    bad_record_mac = 20,
    /// RFC 9846 §6.2: a record was received longer than the permitted length.
    record_overflow = 22,
    /// RFC 9846 §6.2: the handshake failed for a reason the other alerts do not name.
    handshake_failure = 40,
    /// RFC 9846 §6.2: a certificate was corrupt.
    bad_certificate = 42,
    /// RFC 9846 §6.2: a certificate was of an unsupported type.
    unsupported_certificate = 43,
    /// RFC 9846 §6.2: a certificate was revoked by its signer.
    certificate_revoked = 44,
    /// RFC 9846 §6.2: a certificate has expired or is not currently valid.
    certificate_expired = 45,
    /// RFC 9846 §6.2: a certificate could not be processed for an unspecified reason.
    certificate_unknown = 46,
    /// RFC 9846 §6.2: a field of the handshake was incorrect or inconsistent.
    illegal_parameter = 47,
    /// RFC 9846 §6.2: a valid certificate chain was received but the CA is not trusted.
    unknown_ca = 48,
    /// RFC 9846 §6.2: a valid certificate was received but access control refused it.
    access_denied = 49,
    /// RFC 9846 §6.2: a message could not be decoded.
    decode_error = 50,
    /// RFC 9846 §6.2: a cryptographic operation failed.
    decrypt_error = 51,
    /// RFC 9846 §6.2: the peer requires a protocol version the sender will not use.
    protocol_version = 70,
    /// RFC 9846 §6.2: the peer requires stronger parameters than this endpoint offers.
    insufficient_security = 71,
    /// RFC 9846 §6.2: an internal error unrelated to the peer or the protocol.
    internal_error = 80,
    /// RFC 9846 §6.2: the sender is downgrading from a higher version it detected.
    inappropriate_fallback = 86,
    /// RFC 9846 §6.2: the user cancelled the handshake.
    user_canceled = 90,
    /// RFC 9846 §6.2: a required extension was missing.
    missing_extension = 109,
    /// RFC 9846 §6.2: an extension was sent that the sender may not offer.
    unsupported_extension = 110,
    /// RFC 9846 §6.2: no server certificate matches the name the client offered.
    unrecognized_name = 112,
    /// RFC 9846 §6.2: an invalid or unacceptable OCSP response was received.
    bad_certificate_status_response = 113,
    /// RFC 9846 §6.2: PSK key establishment was required and no acceptable identity was offered.
    unknown_psk_identity = 115,
    /// RFC 9846 §6.2: a certificate is required and none was sent.
    certificate_required = 116,
    /// RFC 9846 §6.2: no more specific error is available, or the sender chose to conceal which
    /// one it is. RFC 9846 added this description; RFC 8446 did not name it.
    general_error = 117,
    /// RFC 7301 §3.2: the server supports no protocol the client advertised. This is the alert an
    /// ALPN negotiation that shares no protocol ends with.
    no_application_protocol = 120,
    /// RFC 9846 §6: a description this version does not name. It is still an error.
    _,
};

/// One alert a provider reports, and which side raised it (RFC 9846 §6).
pub const AlertReport = struct {
    /// The description RFC 9846 §6 names.
    description: Alert,
    /// Which endpoint raised it.
    origin: Origin,

    /// RFC 9846 §6.1 makes a peer's `close_notify` the end of the peer's data, which is not the
    /// same event as a provider of colibri's own refusing a record.
    pub const Origin = enum { peer, local };
};

/// What an alert means to the connection that received it (RFC 9846 §6).
///
/// Three answers and not two, because RFC 9846 §6.1 gives `user_canceled` a meaning that is
/// neither an error nor the end of the peer's data. RFC 8446 left that unclear and the revision
/// tightened it, which is one of the changes RFC 9846 §1.2 lists.
pub const Verdict = enum {
    /// The peer's data has not ended and nothing is in error, so the reader carries on.
    keep_reading,
    /// The sender will send no more messages, so its data has ended (RFC 9846 §6.1).
    end_of_data,
    /// An error alert, after which RFC 9846 §6 forbids data in either direction (§6.2).
    fatal,
};

/// What `report` means to the connection that received it.
pub fn verdict(report: AlertReport) Verdict {
    return switch (report.description) {
        // RFC 9846 §6.1: close_notify tells the recipient that the sender will not send any more
        // messages, which design §8 step 5 makes the end of the h2 byte stream.
        .close_notify => .end_of_data,
        // RFC 9846 §6.1: user_canceled "MUST be followed by a close_notify", and "Receiving
        // implementations SHOULD continue to read data" after it. So the peer's data ends at that
        // close_notify and not here, and this alert is neither an error nor an ending.
        .user_canceled => .keep_reading,
        // RFC 9846 §6.2: every other description is an error alert.
        else => .fatal,
    };
}

test "each description gets the one verdict RFC 9846 §6 gives it" {
    const testing = std.testing;
    // RFC 9846 §6.1: close_notify ends the peer's data.
    try testing.expectEqual(Verdict.end_of_data, verdict(.{ .description = .close_notify, .origin = .peer }));
    // RFC 9846 §6.1: user_canceled is followed by a close_notify, so the reader waits for it.
    // It is neither an ending nor an error, which is the whole reason this answer is three-way.
    try testing.expectEqual(Verdict.keep_reading, verdict(.{ .description = .user_canceled, .origin = .peer }));
    // RFC 9846 §6.2: every other description is an error alert.
    try testing.expectEqual(Verdict.fatal, verdict(.{ .description = .bad_record_mac, .origin = .local }));
    // RFC 7301 §3.2: the ALPN alert is 120.
    try testing.expectEqual(120, @intFromEnum(Alert.no_application_protocol));
    // RFC 9846 §6.2: general_error is 117, and it is an error alert like any other.
    try testing.expectEqual(117, @intFromEnum(Alert.general_error));
    try testing.expectEqual(Verdict.fatal, verdict(.{ .description = .general_error, .origin = .peer }));
    // RFC 9846 §6: an endpoint that receives an unknown description treats it as an error.
    const unknown: Alert = @enumFromInt(200);
    try testing.expectEqual(Verdict.fatal, verdict(.{ .description = unknown, .origin = .peer }));
}
