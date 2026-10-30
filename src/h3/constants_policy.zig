//! The values colibri chose for h3 within what the RFCs allow, which size nothing.
//! Decision 137 groups them, and `constants.zig` exports this file as `policy`.

/// The send priority of colibri's control and QPACK streams in `quic` (RFC 9000 §2.3): the
/// highest, so each goes out before any request stream's octets.
pub const local_stream_priority: u8 = 0;

/// One in this many errors the connection would send as H3_NO_ERROR goes out as a reserved code
/// instead (RFC 9114 §8.1: "with some probability").
pub const grease_error_one_in: u64 = 2;
