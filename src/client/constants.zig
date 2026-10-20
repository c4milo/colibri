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

/// Requests one connection holds at once, each with its response: waiting to be written, in
/// flight, or finished and not yet reported. A request past them is refused until one is reported.
pub const requests_max: u32 = 16;

/// TCP connections one pool holds at most (decision 125). `Options.tcp_connections` is at least 1
/// and at most this, and it bounds each loop over a pool's TCP connections.
pub const pool_tcp_connections_max: u16 = 64;

/// Requests one pool holds at once at most (decision 125). `Options.requests` is at least 1 and
/// at most this, and it bounds each loop over a pool's table of exchanges.
pub const pool_requests_max: u16 = 1024;

/// Octets of an h2 frame of the largest size colibri advertises, its header included (RFC 9113
/// §4.1, §4.2).
pub const frame_len_max: usize = h2.constants.frame_header_len + h2.constants.frame_size_max;

/// Octets of the protocol's stream that records opened and `receive` has not read: the longest
/// unit that is not whole yet, and room to open one more record after it. So the next record always
/// opens while a unit waits for its last octets, as the owner ruled on 2026-10-17. A provider opens
/// a record into room for all that follows its header, and not only for its plaintext. RFC 9846
/// §5.2 bounds that room by `record_ciphertext_len_max`.
pub const plaintext_in_len: usize = partial_unit_len_max + tls_provider.constants.record_ciphertext_len_max;

/// The most octets of a unit that is not whole yet: an h11 head or an h2 frame, whichever is
/// longer, one octet short of its limit. h11 reads a head again from its first octet until the head
/// ends (RFC 9112 §2.1), and h2 takes whole frames (RFC 9113 §4.1).
const partial_unit_len_max: usize = @max(h11.constants.head_len_max, frame_len_max) - 1;

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
/// DATA frame's header. The request's content follows them from the caller's memory.
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
pub const h3_events_per_read_max: usize = quic.constants.receive_pool_len_default + requests_max * h3_events_per_exchange_max + 1;
const h3_events_per_exchange_max: usize = 4;

/// Times an exchange moves to another connection after one that takes no new exchange refused it
/// unprocessed (RFC 9113 §8.7, RFC 9114 §4.1.1), or closed before any of the response to an
/// idempotent request arrived (RFC 9110 §9.2.2, decision 124): once in all, so a second refusal or
/// close is the caller's to judge.
pub const moves_max: u8 = 1;

/// Events the pool reads from its connections in one call at most: each connection's version,
/// ticket, draining and close, and one `finished` event for each exchange it may hold.
pub const pool_events_per_poll_max: usize = transports_count * (requests_max + connection_events_max);
const transports_count: usize = 2;
const connection_events_max: usize = 4;

/// Octets of the largest TLS record: its header and the most ciphertext RFC 9846 §5.2 lets a record
/// carry. A peer may send one, and a provider may write one.
const record_len_max: usize = tls_provider.constants.record_header_len + tls_provider.constants.record_ciphertext_len_max;

/// Octets a program holds of what the TCP socket read, from the first octet `receive` did not take
/// (decision 124). With this many, the octets hold a whole unit, and `receive` takes some of them
/// while `send_stream` has written what the connection owes.
/// Each protocol takes some units whole, and this is the largest of them:
/// - h11 reads a head again from its first octet until the head ends (RFC 9112 §2.1), so it needs
///   the whole head, at most `h11.constants.head_len_max` octets. A trailer section and a
///   chunk-size line are shorter.
/// - h2 takes whole frames (RFC 9113 §4.1), at most `frame_len_max` octets with the frame size
///   colibri advertises (RFC 9113 §4.2).
/// - Over TLS, the connection opens whole records, at most `record_len_max` octets each (RFC 9846
///   §5.2). It holds an h11 head or an h2 frame that is not whole yet beside room for one more
///   record (`plaintext_in_len`), so a whole record always opens.
pub const stream_input_len_min: usize = @max(h11.constants.head_len_max, @max(frame_len_max, record_len_max));

/// The least `output` with which `send_stream` writes some of what the TCP connection owes, when
/// it owes octets (decision 124). In cleartext, one octet is enough: `send_stream` copies any part
/// of what h11 and h2 wrote. Over TLS, a provider writes whole records: the records that hold the
/// protocol's octets, an alert, and the answer to a KeyUpdate. A provider never refuses an output of
/// `tls_provider.constants.record_write_len_min` octets, which holds the largest record (RFC 9846
/// §5.2). It may refuse a shorter output. chapulin seals a shorter record into a shorter output,
/// but the client keeps to what every provider promises.
pub const stream_output_len_min: usize = record_len_max;

/// The events of one transport in a run of `receive` calls that take no octet, at most: its `open`
/// and its `close`, its connection's `connected` and `ticket`, and over TCP one `send`, which
/// waits for the program's `send_stream`. A connection's `draining` and `closed` go to the pool
/// alone. `Pool.receive_events_without_input_max` counts it for each transport (decision 124 as
/// amended by decision 125).
pub const transport_events_max: usize = 5;

/// Nanoseconds in a second, which an Alt-Svc freshness lifetime counts (RFC 7838 §3.1).
pub const nanoseconds_per_second: u64 = 1_000 * quic.constants.nanoseconds_per_millisecond;

/// How long a pool lets QUIC's handshake run before TCP opens beside it, unless the caller
/// names another delay, in nanoseconds: 250 ms (decision 120). No RFC in docs/rfcs gives a value.
/// It is the delay the test-only client used before the pool had a default.
pub const fallback_delay_ns_default: u64 = 250 * quic.constants.nanoseconds_per_millisecond;

/// The largest window a `br` decoder takes, as the bits RFC 7932 §9.1 names WBITS: 24, a window of
/// 16 MiB less 16 octets, the largest §9.1 allows, as the owner ruled on 2026-09-30 (decision 101
/// as amended). A `br` decoder holds this much.
pub const brotli_window_bits_max: u5 = 24;

comptime {
    // A unit that waits for its last octets never stops the next record from opening: an h11 head
    // (RFC 9112 §2.1) or an h2 frame (RFC 9113 §4.1), each one octet short of its limit, then room
    // for the most that follows a record's header (RFC 9846 §5.2).
    assert(plaintext_in_len >= h11.constants.head_len_max - 1 + tls_provider.constants.record_ciphertext_len_max);
    assert(plaintext_in_len >= frame_len_max - 1 + tls_provider.constants.record_ciphertext_len_max);
    // The output holds every flight a handshake writes before a send, and a whole field block
    // with a frame after it.
    assert(output_len >= flights_max * flight_len_max);
    assert(output_len >= h2.constants.send_block_len_max + frame_len_max);
    // The client adds its lines to at least one of the caller's.
    assert(request_fields_max > added_fields_max);
    // h11 queues every exchange the connection holds, or the rest wait for room (RFC 9112 §9.3.2).
    assert(requests_max > 0 and h11.constants.pipeline_depth_max > 0);
    // `std.math.maxInt(usize)` has at most this many decimal digits.
    assert(std.fmt.count("{d}", .{std.math.maxInt(usize)}) <= content_length_digits_max);
    // A margin shorter than the idle timeout the client advertises leaves the connection time to
    // work in.
    assert(quic_idle_margin_ns_min < quic_idle_timeout_ms_default * quic.constants.nanoseconds_per_millisecond);
    assert(quic_idle_margin_timeout_divisor > 1);
    // A fallback delay of zero would open TCP beside every QUIC handshake.
    assert(fallback_delay_ns_default > 0);
    // The program holds each unit a TCP connection takes whole: an h11 head, trailer section or
    // chunk-size line, an h2 frame, and a TLS record.
    assert(stream_input_len_min >= h11.constants.head_len_max);
    assert(stream_input_len_min >= h11.constants.trailer_len_max);
    assert(stream_input_len_min > h11.constants.chunk_line_len_max);
    assert(stream_input_len_min >= frame_len_max);
    assert(stream_input_len_min >= record_len_max);
    // An output a provider never refuses for its length holds an alert too.
    assert(stream_output_len_min >= tls_provider.constants.record_write_len_min);
    assert(stream_output_len_min >= tls.record.alert_record_len);
    // A pool of the default size holds the exchanges of one connection.
    assert(requests_max <= pool_requests_max);
    assert(pool_tcp_connections_max > 0);
}
