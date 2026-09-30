//! The limits of `server` (decision 100, design §8 step 17a), each named once. A connection's
//! buffers are sized from h2's frame limits and the TLS record limits, so every size is a comptime
//! constant a caller can read (decision 35).
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const h3 = @import("h3");
const quic = @import("quic");
const tls_provider = @import("tls_provider");

/// Octets of an h2 frame of the largest size colibri advertises, its header included (RFC 9113
/// §4.1, §4.2).
pub const frame_len_max: usize = h2.constants.frame_header_len + h2.constants.frame_size_max;

/// Octets of the protocol's stream that records opened and `receive` has not read: a frame waiting
/// for its last octets, and room to open one more record, so the next record always opens while a
/// frame is incomplete. A provider opens a record into room for all that follows its header, which
/// RFC 9846 §5.2 bounds by `record_ciphertext_len_max`, and not only for its plaintext.
pub const plaintext_in_len: usize = frame_len_max + tls_provider.constants.record_ciphertext_len_max;

/// Octets of DER one certificate of the server's chain may take, for the bound on its flight.
pub const certificate_len_max: usize = 8 * 1024;

/// Certificates the bound on the flight allows: the end-entity and one intermediate.
pub const chain_certificates_max: usize = 2;

/// The rest of the server's flight: ServerHello, the compatibility ChangeCipherSpec,
/// EncryptedExtensions, CertificateVerify and Finished, and each record's header and tag.
pub const flight_rest_len: usize = 4 * 1024;

/// The most octets the server's TLS flight takes. chapulin writes a flight whole or fails the
/// handshake, so the handshake runs only while `output` has this much room.
pub const flight_len_max: usize = chain_certificates_max * certificate_len_max + flight_rest_len;

/// Octets a connection writes before `send` takes them: a response's field block cut into frames
/// and a DATA frame after it, or the TLS flight, whichever is larger.
pub const output_len: usize = @max(h2.constants.send_block_len_max + frame_len_max, flight_len_max);

/// The most frames one `receive` reads past that mean nothing to the caller, such as a SETTINGS
/// acknowledgment. Each takes a frame header at least, so the plaintext a call holds bounds them.
pub const frames_per_receive_max: usize = plaintext_in_len / h2.constants.frame_header_len + 1;

/// The most records one `send` seals. chapulin seals what the output holds in one call, and a
/// provider that seals one record a call needs one pass per record the output holds.
pub const seals_per_send_max: usize = output_len / tls_provider.constants.record_header_len + 1;

/// The `done` events one connection owes at most (decision 103): one for each request it holds
/// at once, which h2's limit on the peer's streams bounds (RFC 9113 §5.1.2), and h11 answers one
/// request at a time. `receive` reports each before it reads another request.
pub const done_owed_max: usize = h2.constants.concurrent_streams_max;

/// Octets of the chunked coding around one chunk's data: a size line of at most one hex digit per
/// four bits of a `usize`, and two CRLFs (RFC 9112 §7.1).
pub const chunk_framing_len_max: usize = @sizeOf(usize) * 2 + 4;

/// Octets of the last chunk and the empty line after it, `0\r\n\r\n`, which end a chunked body
/// with no trailer field (RFC 9112 §7.1).
pub const last_chunk_len: usize = 5;

/// Request streams a QUIC connection's client may have open at once, which the server grants as
/// `initial_max_streams_bidi` (RFC 9000 §4.6, §18.2) and which sizes each connection's table of
/// responses. h3 tracks more (`h3.constants.request_streams_max`).
pub const quic_requests_max: u32 = 32;

/// Octets of the frames one h3 response keeps until the peer acknowledges them (decision 79): its
/// heads' HEADERS frames, each DATA frame's header, and its trailer section's HEADERS frame.
pub const quic_response_kept_len: usize = 8192;

/// The runs of octets one h3 response holds until the peer acknowledges them: each kept frame,
/// and each run of the caller's octets `write_body` took, which stay the caller's (decision 103).
pub const quic_response_pieces_max: usize = 16;

/// Octets of request content h3 copies out of the receive pool in one event (decision 80).
pub const quic_read_len: usize = 16_384;

/// The length of every connection ID the endpoint chooses. RFC 9000 §7.2 has a client's first
/// Destination Connection ID be at least 8 octets, and the server's are as long.
pub const quic_id_len: usize = 8;

/// The window each QUIC connection grants a request stream's content, and each of the client's
/// unidirectional streams: h3's control stream and QPACK's two (RFC 9114 §6.2).
pub const quic_stream_window: u64 = 65_536;

/// Octets of the transport parameters the server sends, encoded (RFC 9000 §18): every parameter
/// RFC 9000 §18.2 defines fits.
pub const quic_transport_parameters_len_max: usize = 1024;

/// The idle timeout a QUIC connection advertises unless the caller names another (RFC 9000 §10.1),
/// in milliseconds.
pub const quic_idle_timeout_ms_default: u64 = 30_000;

/// Connections `Endpoint` holds at once, the default size (decision 103). `EndpointOf` takes
/// another.
pub const quic_connections_default: usize = 16;

/// Version Negotiation and Retry packets an endpoint owes at once. One more is dropped, and its
/// client sends again.
pub const quic_replies_max: usize = 8;

/// Nanoseconds in a second, which a connection's ticket instant is counted in.
pub const nanoseconds_per_second: u64 = 1_000_000_000;

/// Events one `receive` of a QUIC connection reads past at most: one for each octet the receive
/// pool holds, and a few that consume none, such as a stream's end, for each request.
pub const quic_events_per_read_max: usize = quic.constants.receive_pool_len_default + quic_requests_max * quic_events_per_request_max + 1;
/// The events of one request stream that consume nothing: its head, its end and its reset.
const quic_events_per_request_max: usize = 3;

/// The requests one TCP connection keeps coding state for (decision 101): one for each request it
/// holds at once, as `done_owed_max` counts them.
pub const coding_requests_max: usize = h2.constants.concurrent_streams_max;

/// Octets of coded content an encoder holds before its response sends them: the ring each slot of
/// the encoder pool carries (decision 101, the owner's ruling of 2026-09-28). h3 sends from it in
/// place until the peer acknowledges the octets, so it bounds a coded h3 response's octets in
/// flight.
pub const encoder_ring_len: usize = 65_536;

/// The encoders a pool holds unless its caller names another count, the most coded responses the
/// connections given it send at once, and the deflate level they code at: 6, the middle of the
/// three levels stdx's encoder offers (1, 6 and 9).
pub const encoders_default: usize = 4;
pub const encoder_level_default: u4 = 6;

/// Decision 110's deadlines for a connection over TCP, each the default `Config.deadlines` carries
/// and a caller may change: from the instant the connection opens to its first whole request head,
/// the TLS handshake included; between requests, after at least one response, while none is open;
/// and from the first octet of a request head to its end.
pub const first_request_timeout_ns: u64 = 10 * nanoseconds_per_second;
pub const idle_timeout_ns: u64 = 30 * nanoseconds_per_second;
pub const head_timeout_ns: u64 = 10 * nanoseconds_per_second;

/// Decision 110's body deadlines. From the end of a request's head, its body must bring
/// `body_rate_min` octets a second over each window of `rate_window_ns`, the first window taking
/// `rate_grace_ns` more, and must end within `body_timeout_ns`. In h2 each stream's body does, and
/// the bodies together do as well.
pub const body_rate_min: u32 = 1_024;
pub const rate_grace_ns: u64 = 10 * nanoseconds_per_second;
pub const rate_window_ns: u64 = 10 * nanoseconds_per_second;
pub const body_timeout_ns: u64 = 300 * nanoseconds_per_second;

/// The longest deadline a caller may set: a day. A deadline starts at an instant the caller
/// passed, and this keeps the start plus the limit inside a `u64`.
pub const timeout_ns_max: u64 = 86_400 * nanoseconds_per_second;

/// The request bodies one connection waits for at once: one in h11, and one for each stream an h2
/// peer may open.
pub const bodies_max: usize = h2.constants.concurrent_streams_max;

comptime {
    assert(encoder_ring_len > 0 and encoders_default > 0);
    assert(quic_requests_max > 0 and quic_requests_max <= h3.constants.request_streams_max);
    // A response's head, the longest field section h3 encodes behind a frame header, fits.
    assert(quic_response_kept_len >= h3.constants.frame_header_len_max + h3.constants.section_prefix_len_max);
    assert(quic_response_pieces_max > 2 and quic_read_len > 0 and quic_id_len >= 8);
    assert(quic_connections_default > 0 and quic_replies_max > 0);
    // Each request owes one `done` at most, and the ring that holds them has room for all.
    assert(done_owed_max >= quic_requests_max);
}

comptime {
    // A frame waiting for its last octets never stops the next record from opening.
    assert(plaintext_in_len >= frame_len_max + tls_provider.constants.record_ciphertext_len_max);
    // The output holds a whole flight, and a whole field block with a frame after it.
    assert(output_len >= flight_len_max);
    assert(output_len >= h2.constants.send_block_len_max + frame_len_max);
    // Every chunk the output holds leaves room for the last one.
    assert(output_len > chunk_framing_len_max + last_chunk_len);
    assert(done_owed_max > 0);
    assert(bodies_max > 0 and body_rate_min > 0);
    assert(rate_grace_ns + rate_window_ns <= body_timeout_ns and body_timeout_ns <= timeout_ns_max);
}
