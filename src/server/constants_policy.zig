//! The values colibri chose for server within what the RFCs allow, which size nothing.
//! Decision 137 groups them, and `constants.zig` exports this file as `policy`.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const h3 = @import("h3");
const tls_provider = @import("tls_provider");
const constants = @import("constants.zig");

/// The period over which a QUIC connection counts the request streams its client opens and then
/// cancels, against `Limits.peer_resets_max` (RFC 9114 §10.5). The stream limit above bounds how
/// many are open at once, not how fast they are opened and cancelled. The period is h2's, which
/// the owner ruled for h3 (decision 110 as amended).
pub const quic_peer_reset_rate_period_ns: u64 = h2.constants.policy.peer_reset_rate_period_ns;

/// The period over which a QUIC connection counts the request streams h3 refuses, against
/// `Limits.resets_sent_max`: h2's, as the limit is (decision 110 as amended).
pub const quic_resets_sent_period_ns: u64 = h2.constants.policy.rst_stream_rate_period_ns;

/// The length of every connection ID the endpoint chooses. RFC 9000 §7.2 has a client's first
/// Destination Connection ID be at least 8 octets, and the server's are as long.
pub const quic_id_len: usize = 8;

/// The window each QUIC connection grants a request stream's content, and each of the client's
/// unidirectional streams: h3's control stream and QPACK's two (RFC 9114 §6.2).
pub const quic_stream_window: u64 = 65_536;

/// The idle timeout a QUIC connection advertises unless the caller names another (RFC 9000 §10.1),
/// in milliseconds.
pub const quic_idle_timeout_ms_default: u64 = 30_000;

pub const encoder_level_default: u4 = 6;

/// Decision 110's deadlines for a connection over TCP, each the default `Config.deadlines` carries
/// and a caller may change: from the instant the connection opens to its first whole request head,
/// the TLS handshake included; between requests, after at least one response, while none is open;
/// and from the first octet of a request head to its end.
pub const first_request_timeout_ns: u64 = 10 * constants.nanoseconds_per_second;
pub const idle_timeout_ns: u64 = 30 * constants.nanoseconds_per_second;
pub const head_timeout_ns: u64 = 10 * constants.nanoseconds_per_second;

/// Decision 110's body deadlines. From the end of a request's head, its body must bring
/// `body_rate_min` octets a second over each window of `rate_window_ns`, the first window taking
/// `rate_grace_ns` more, and must end within `body_timeout_ns`. In h2 each stream's body does, and
/// the bodies together do as well.
pub const body_rate_min: u32 = 1_024;
pub const rate_grace_ns: u64 = 10 * constants.nanoseconds_per_second;
pub const rate_window_ns: u64 = 10 * constants.nanoseconds_per_second;
pub const body_timeout_ns: u64 = 300 * constants.nanoseconds_per_second;

/// Decision 110's send deadline: while the connection holds octets its peer has not taken, the
/// peer must take `send_rate_min` octets a second over each window, as a body brings them. A
/// connection a deadline ended, or that has nothing more to say, closes once its last octets are
/// out or `close_linger_ns` after it ended, whichever comes first. Once the peer has sent a
/// WINDOW_UPDATE smaller than `data_frame_len_min`, h2 sends no DATA frame shorter than it unless
/// the window holds the whole payload.
pub const send_rate_min: u32 = 1_024;
pub const close_linger_ns: u64 = 2 * constants.nanoseconds_per_second;
pub const data_frame_len_min: u32 = 1_024;

/// Decision 110 as amended a fifth time: over TLS a request body arrives a record at a time
/// (RFC 9846 §5.1), and in h2 a DATA frame at a time (RFC 9113 §4.2), each of up to this many
/// octets. An honest peer sends a body at `honest_rate_factor` times the minimum rate or more, and
/// a server whose bodies arrive in units refuses a `body_rate_min` under which such a peer can fall
/// short (spec/lean/Colibri/Server/RateMeter.lean).
pub const body_unit_len: u64 = tls_provider.constants.protocol.record_plaintext_len_max;
pub const honest_rate_factor: u64 = 2;

/// Decision 110's drain deadline: after the caller's `shutdown`, the time the requests it holds
/// have before the connection closes.
pub const drain_timeout_ns: u64 = 30 * constants.nanoseconds_per_second;

/// The requests a client may cancel in one second by default (`Limits.peer_resets_max`): h2's
/// RST_STREAM on a stream the client opened, and h3's RESET_STREAM or STOP_SENDING on a request
/// stream. One more ends the connection (RFC 9113 §10.5, RFC 9114 §10.5, decision 110).
pub const peer_resets_max: u32 = h2.constants.policy.peer_reset_rate_max;

/// The streams a server may reset in one second by default (`Limits.resets_sent_max`), each for a
/// stream the client broke. One more ends the connection (RFC 9113 §10.5, decision 110).
pub const resets_sent_max: u32 = h2.constants.policy.rst_stream_rate_max;

comptime {
    assert(data_frame_len_min <= h2.constants.protocol.max_frame_size_initial and close_linger_ns > 0);
    // The largest DATA frame a peer may send colibri is a record's plaintext too.
    assert(body_unit_len == h2.constants.protocol.max_frame_size_initial and honest_rate_factor > 1);
    assert(peer_resets_max > 0 and resets_sent_max > 0);
}
