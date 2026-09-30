//! The limits of `client` (decision 100, design §8 step 17c), each named once. A connection's
//! buffers are sized from h2's frame limits and the TLS record limits, so every size is a comptime
//! constant a caller can read (decision 35).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const h2 = @import("h2");
const h11 = @import("h11");
const tls = @import("tls");
const tls_provider = @import("tls_provider");
const quic = @import("quic");
const h3 = @import("h3");

/// Exchanges one connection holds at once: waiting to be written, in flight, or finished and not
/// yet reported. A request past them is refused until one is reported.
pub const exchanges_max: u32 = 16;

/// Octets of an h2 frame of the largest size colibri advertises, its header included (RFC 9113
/// §4.1, §4.2).
pub const frame_len_max: usize = h2.constants.frame_header_len + h2.constants.frame_size_max;

/// Octets of the protocol's stream that records opened and `receive` has not read: a frame waiting
/// for its last octets, and room to open one more record, so the next record always opens while a
/// frame is incomplete. A provider opens a record into room for all that follows its header, which
/// RFC 9846 §5.2 bounds by `record_ciphertext_len_max`, and not only for its plaintext.
pub const plaintext_in_len: usize = frame_len_max + tls_provider.constants.record_ciphertext_len_max;

/// Octets of the most the client's TLS handshake writes in one call: its largest ClientHello
/// record, which a HelloRetryRequest may ask for again, then the alert a refused flight owes.
pub const flight_len_max: usize = tls.record.Client.handshake_output_len_min + tls.record.alert_record_len;

/// The flights a handshake writes at most before the caller sends: a ClientHello, a second one
/// after a HelloRetryRequest (RFC 9846 §4.1.4), and the Finished flight or an alert.
pub const flights_max: usize = 3;

/// Octets a connection writes before `send` takes them: a request's field block cut into frames
/// and a DATA frame after it, or the TLS flight, whichever is larger.
pub const output_len: usize = @max(h2.constants.send_block_len_max + frame_len_max, flight_len_max);

/// The most frames one `receive` reads past that mean nothing to the caller, such as a SETTINGS
/// acknowledgment. Each takes a frame header at least, so the plaintext a call holds bounds them.
pub const frames_per_receive_max: usize = plaintext_in_len / h2.constants.frame_header_len + 1;

/// The most records one `send` seals. chapulin seals what the output holds in one call, and a
/// provider that seals one record a call needs one pass per record the output holds.
pub const seals_per_send_max: usize = output_len / tls_provider.constants.record_header_len + 1;

/// Field lines the client adds to a request's own: Host in h11 (RFC 9112 §3.2), Content-Length
/// (RFC 9110 §8.6) and Accept-Encoding (decision 101).
pub const added_fields_max: usize = 3;

/// Field lines a request may carry, the ones the client adds included.
pub const request_fields_max: usize = core.constants.field_count_max;

/// Octets of the decimal Content-Length the client writes: enough for any `usize`.
pub const content_length_digits_max: usize = 20;

/// Octets of each connection ID the QUIC client chooses: its own Source Connection ID and the
/// Destination Connection ID of its first Initial (RFC 9000 §7.2), which RFC 9000 §7.2 asks to be
/// at least 8 octets of unpredictable value.
pub const quic_id_len: usize = 8;

/// Octets of a request stream's frames the QUIC client keeps until the stream closes (decision
/// 79): the HEADERS frame, the longest field section h3 encodes behind a frame header, then the
/// DATA frame's header. The exchange's content follows them from the caller's memory.
pub const request_prefix_len_max: usize = h3.constants.scratch_len + h3.constants.frame_header_len_max;

/// The idle timeout the QUIC client advertises unless the caller names another (RFC 9000 §10.1),
/// in milliseconds.
pub const quic_idle_timeout_ms_default: u64 = 30_000;

/// The least margin before a QUIC connection's idle deadline at which the client acts on it (RFC
/// 9114 §5.1, design §8 step 17g): a connection holding an exchange sends a PING, and one holding
/// none takes no new exchange and closes. The margin is one PTO (RFC 9002 §6.2.1) and at least
/// this, as the owner ruled on 2026-09-28, since RFC 9000 §10.1.2 warns that a packet sent close
/// to the timeout can arrive after the peer's timer ran out.
pub const quic_idle_margin_ns_min: u64 = nanoseconds_per_second;

/// The margin never exceeds the idle timeout divided by this, so a short timeout still leaves the
/// connection its first half, and a keep-alive's own acknowledgment does not come due again at
/// once.
pub const quic_idle_margin_timeout_divisor: u64 = 2;

/// The window the QUIC client grants each unidirectional stream the server opens: h3's control
/// stream and QPACK's two (RFC 9114 §6.2), whose frames are small.
pub const quic_stream_window: u64 = 65_536;

/// Octets of the transport parameters the QUIC client sends, encoded (RFC 9000 §18): every
/// parameter RFC 9000 §18.2 defines fits.
pub const transport_parameters_len_max: usize = 1024;

/// Octets of content h3 copies out of the receive pool in one event (decision 80).
pub const quic_read_len: usize = 16_384;

/// Events one read of h3 reports at most: one for each octet the receive pool holds, and a few
/// that consume none, such as a stream's end, for each exchange and for the connection.
pub const h3_events_per_read_max: usize = quic.constants.receive_pool_len_default + exchanges_max * h3_events_per_exchange_max + 1;
const h3_events_per_exchange_max: usize = 4;

/// Times an exchange moves to another connection after one that takes no new exchange refused it
/// unprocessed (RFC 9113 §8.7, RFC 9114 §4.1.1): once, so a second refusal is the caller's to
/// judge.
pub const moves_max: u8 = 1;

/// Events the channel reads from its connections in one call at most: each connection's version,
/// ticket, draining and close, and one `finished` event for each exchange it may hold.
pub const channel_events_per_poll_max: usize = transports_count * (exchanges_max + connection_events_max);
const transports_count: usize = 2;
const connection_events_max: usize = 4;

/// Nanoseconds in a second, which an Alt-Svc freshness lifetime counts (RFC 7838 §3.1).
pub const nanoseconds_per_second: u64 = 1_000 * quic.constants.nanoseconds_per_millisecond;

/// The largest window a `br` decoder takes, as the bits RFC 7932 §9.1 names WBITS: 24, a window of
/// 16 MiB less 16 octets, the largest §9.1 allows, as the owner ruled on 2026-09-30 (decision 101
/// as amended). A `br` decoder holds this much.
pub const brotli_window_bits_max: u5 = 24;

comptime {
    // A frame waiting for its last octets never stops the next record from opening.
    assert(plaintext_in_len >= frame_len_max + tls_provider.constants.record_ciphertext_len_max);
    // The output holds every flight a handshake writes before a send, and a whole field block
    // with a frame after it.
    assert(output_len >= flights_max * flight_len_max);
    assert(output_len >= h2.constants.send_block_len_max + frame_len_max);
    // The client adds its lines to at least one of the caller's.
    assert(request_fields_max > added_fields_max);
    // h11 queues every exchange the connection holds, or the rest wait for room (RFC 9112 §9.3.2).
    assert(exchanges_max > 0 and h11.constants.pipeline_depth_max > 0);
    // `std.math.maxInt(usize)` has at most this many decimal digits.
    assert(std.fmt.count("{d}", .{std.math.maxInt(usize)}) <= content_length_digits_max);
    // A margin shorter than the idle timeout the client advertises leaves the connection time to
    // work in.
    assert(quic_idle_margin_ns_min < quic_idle_timeout_ms_default * quic.constants.nanoseconds_per_millisecond);
    assert(quic_idle_margin_timeout_divisor > 1);
}
