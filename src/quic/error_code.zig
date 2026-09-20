//! The transport error codes of RFC 9000 §20.1, which a CONNECTION_CLOSE frame of type 0x1c
//! carries (§19.19). They are named once, here, so every part of `quic` closes a connection with
//! the same number for the same rule and no file writes one inline.
//!
//! Application error codes are not here: §20.2 leaves their meaning to the application protocol,
//! and a CONNECTION_CLOSE of type 0x1d carries one colibri never chooses.
const std = @import("std");
const assert = std.debug.assert;

pub const no_error: u64 = 0x00;
pub const internal_error: u64 = 0x01;
pub const connection_refused: u64 = 0x02;
pub const flow_control_error: u64 = 0x03;
pub const stream_limit_error: u64 = 0x04;
pub const stream_state_error: u64 = 0x05;
pub const final_size_error: u64 = 0x06;
pub const frame_encoding_error: u64 = 0x07;
pub const transport_parameter_error: u64 = 0x08;
pub const connection_id_limit_error: u64 = 0x09;
pub const protocol_violation: u64 = 0x0a;
pub const invalid_token: u64 = 0x0b;
pub const application_error: u64 = 0x0c;
pub const crypto_buffer_exceeded: u64 = 0x0d;
pub const key_update_error: u64 = 0x0e;
pub const aead_limit_reached: u64 = 0x0f;

/// RFC 9000 §20.1: a TLS alert of description `d` is reported as 0x0100 + d, so the range is
/// 0x0100 to 0x01ff. RFC 9001 §4.8 is what maps an alert into it.
pub const crypto_error_first: u64 = 0x0100;
pub const crypto_error_last: u64 = 0x01ff;

/// The code a TLS alert closes the connection with (RFC 9000 §20.1, RFC 9001 §4.8).
pub fn crypto_error(alert_description: u8) u64 {
    return crypto_error_first + alert_description;
}

comptime {
    // RFC 9000 §20.1: the codes run from 0x00 to 0x0f with no gap, and the CRYPTO_ERROR range
    // holds one code per alert description.
    assert(aead_limit_reached == 0x0f);
    assert(crypto_error_last - crypto_error_first == std.math.maxInt(u8));
}

test "§20.1: a TLS alert maps into the CRYPTO_ERROR range and fills it" {
    const testing = std.testing;
    try testing.expectEqual(crypto_error_first, crypto_error(0));
    try testing.expectEqual(crypto_error_last, crypto_error(std.math.maxInt(u8)));
    // RFC 9001 §4.8: an unexpected_message alert is description 10.
    try testing.expectEqual(0x010a, crypto_error(10));
}
