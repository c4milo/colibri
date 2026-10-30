//! The values colibri chose for client within what the RFCs allow, which size nothing.
//! Decision 137 groups them, and `constants.zig` exports this file as `policy`.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("constants.zig");

/// Octets of each connection ID the QUIC client chooses: its own Source Connection ID and the
/// Destination Connection ID of its first Initial (RFC 9000 §7.2), which RFC 9000 §7.2 asks to be
/// at least 8 octets of unpredictable value.
pub const quic_id_len: usize = 8;

/// The idle timeout the QUIC client advertises unless the caller names another (RFC 9000 §10.1),
/// in milliseconds.
pub const quic_idle_timeout_ms_default: u64 = 30_000;

/// The least margin before a QUIC connection's idle deadline at which the client acts on it (RFC
/// 9114 §5.1, design §8 step 17g): a connection holding an exchange sends a PING, and one holding
/// none takes no new exchange and closes. The margin is one PTO (RFC 9002 §6.2.1) and at least
/// this, as the owner ruled on 2026-09-28, since RFC 9000 §10.1.2 warns that a packet sent close
/// to the timeout can arrive after the peer's timer ran out.
pub const quic_idle_margin_ns_min: u64 = constants.nanoseconds_per_second;

/// The margin never exceeds the idle timeout divided by this, so a short timeout still leaves the
/// connection its first half, and a keep-alive's own acknowledgment does not come due again at
/// once.
pub const quic_idle_margin_timeout_divisor: u64 = 2;

/// The window the QUIC client grants each unidirectional stream the server opens: h3's control
/// stream and QPACK's two (RFC 9114 §6.2), whose frames are small.
pub const quic_stream_window: u64 = 65_536;

/// How long a pool lets QUIC's handshake run before TCP opens beside it, unless the caller
/// names another delay, in nanoseconds: 250 ms (decision 120). No RFC in docs/rfcs gives a value.
/// It is the delay the test-only client used before the pool had a default.
pub const fallback_delay_ns_default: u64 = 250 * quic.constants.nanoseconds_per_millisecond;

comptime {
    // A margin shorter than the idle timeout the client advertises leaves the connection time to
    // work in.
    assert(quic_idle_margin_ns_min < quic_idle_timeout_ms_default * quic.constants.nanoseconds_per_millisecond);
    assert(quic_idle_margin_timeout_divisor > 1);
    // A fallback delay of zero would open TCP beside every QUIC handshake.
    assert(fallback_delay_ns_default > 0);
}
