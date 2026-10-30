//! The bounds colibri chose for server, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const h11 = @import("h11");
const h2 = @import("h2");
const h3 = @import("h3");
const quic = @import("quic");
const tls_provider = @import("tls_provider");
const constants = @import("constants.zig");

/// Octets of an h2 frame of the largest size colibri advertises, its header included (RFC 9113
/// §4.1, §4.2).
pub const frame_len_max: usize = h2.constants.protocol.frame_header_len + h2.constants.limits.frame_size_max;

/// Octets of the protocol's stream that records opened and `receive` has not read: the longest
/// unit that is not whole yet, and room to open one more record after it. So the next record always
/// opens while a unit waits for its last octets, as the owner ruled on 2026-10-17. A provider opens
/// a record into room for all that follows its header, and not only for its plaintext. RFC 9846
/// §5.2 bounds that room by `record_ciphertext_len_max`.
pub const plaintext_in_len: usize = partial_unit_len_max + tls_provider.constants.protocol.record_ciphertext_len_max;

/// The most octets of a unit that is not whole yet: an h11 head or an h2 frame, whichever is
/// longer, one octet short of its limit. h11 reads a head again from its first octet until the head
/// ends (RFC 9112 §2.1), and h2 takes whole frames (RFC 9113 §4.1).
const partial_unit_len_max: usize = @max(h11.constants.limits.head_len_max, frame_len_max) - 1;

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
pub const output_len: usize = @max(h2.constants.limits.send_block_len_max + frame_len_max, flight_len_max);

/// The most frames one `receive` reads past that mean nothing to the caller, such as a SETTINGS
/// acknowledgment. Each takes a frame header at least, so the plaintext a call holds bounds them.
pub const frames_per_receive_max: usize = plaintext_in_len / h2.constants.protocol.frame_header_len + 1;

/// The most DATA frames one `write_body` call writes over h2. h2 cuts a frame at the peer's
/// SETTINGS_MAX_FRAME_SIZE, which is 16,384 octets at least (RFC 9113 §4.2), so every frame but
/// the last carries that much, and all of them fit the output.
pub const data_frames_per_write_max: usize = output_len / h2.constants.protocol.max_frame_size_min + 1;

/// The most records one `send` seals. chapulin seals what the output holds in one call, and a
/// provider that seals one record a call needs one pass per record the output holds.
pub const seals_per_send_max: usize = output_len / tls_provider.constants.protocol.record_header_len + 1;

/// The `done` events one connection owes at most (decision 103): one for each request it holds
/// at once, which h2's limit on the peer's streams bounds (RFC 9113 §5.1.2), and h11 answers one
/// request at a time. `receive` reports each before it reads another request.
pub const done_owed_max: usize = h2.constants.limits.concurrent_streams_max;

/// Octets of the chunked coding around one chunk's data: a size line of at most one hex digit per
/// four bits of a `usize`, and two CRLFs (RFC 9112 §7.1).
pub const chunk_framing_len_max: usize = @sizeOf(usize) * 2 + 4;

/// Request streams a QUIC connection's client may have open at once, which the server grants as
/// `initial_max_streams_bidi` (RFC 9000 §4.6, §18.2) and which sizes each connection's table of
/// responses. It is h3's own count (`h3.constants.limits.request_streams_max`), as quinn and quic-go
/// grant: at 32, a client on a path of 50 ms reached about 2,100 requests a second over 8
/// connections (decision 130).
pub const quic_requests_max: u32 = 100;

/// Octets of the frames one h3 response keeps until the peer acknowledges them (decision 79): its
/// heads' HEADERS frames, each DATA frame's header, and its trailer section's HEADERS frame.
pub const quic_response_kept_len: usize = 8192;

/// The runs of octets one h3 response holds until the peer acknowledges them: each kept frame,
/// and each run of the caller's octets `write_body` took, which stay the caller's (decision 103).
pub const quic_response_pieces_max: usize = 16;

/// The headers and trailers one `ResponseWriter` holds until it writes them (decision 127, design
/// §8 step 25.2). Its `header` and `trailers` refuse one more.
pub const response_headers_max: usize = 32;

/// The runs of body bytes one `ResponseWriter` holds until the endpoint takes them: each run the
/// body's writer wrote before a flush, and each run of `write_kept`. An h3 response holds as many
/// (decision 103).
pub const response_pieces_max: usize = quic_response_pieces_max;

/// Octets of request content h3 copies out of the receive pool in one event (decision 80).
pub const quic_read_len: usize = 16_384;

/// Octets of the transport parameters the server sends, encoded (RFC 9000 §18): every parameter
/// RFC 9000 §18.2 defines fits.
pub const quic_transport_parameters_len_max: usize = 1024;

/// The most `Config.retry_from_percent` may be: all of an endpoint's QUIC slots.
pub const retry_from_percent_max: u8 = 100;

/// Connections `Endpoint` holds at once, the default size (decision 103). `EndpointOf` takes
/// another.
pub const quic_connections_default: usize = 16;

/// TCP connections `Endpoint` holds at once, the default size (decision 119). `EndpointOf` takes
/// another, 0 included.
pub const tcp_connections_default: usize = 16;

/// The requests a TCP slot of an endpoint holds at once: as many as an h2 connection may hold,
/// which `Limits.requests_max` reaches at most (decision 119).
pub const tcp_requests_max: usize = h2.constants.limits.concurrent_streams_max;

/// Events one poll of a TCP slot reads at most before it asks the slot again: the endings the
/// connection owes, and one event for each frame its plaintext holds.
pub const tcp_events_per_poll_max: usize = done_owed_max + bodies_max + frames_per_receive_max + 1;

/// Version Negotiation and Retry packets an endpoint owes at once. One more is dropped, and its
/// client sends again.
pub const quic_replies_max: usize = 8;

/// Events one `receive` of a QUIC connection reads past at most: one for each octet the receive
/// pool holds, and a few that consume none, such as a stream's end, for each request.
pub const quic_events_per_read_max: usize = quic.constants.limits.receive_pool_len_default + quic_requests_max * quic_events_per_request_max + 1;
/// The events of one request stream that consume nothing: its head, its end and its reset.
const quic_events_per_request_max: usize = 3;

/// The requests one TCP connection keeps coding state for (decision 101): one for each request it
/// holds at once, as `done_owed_max` counts them.
pub const coding_requests_max: usize = h2.constants.limits.concurrent_streams_max;

/// Octets of coded content an encoder holds before its response sends them: the ring each slot of
/// the encoder pool carries (decision 101, the owner's ruling of 2026-09-28). h3 sends from it in
/// place until the peer acknowledges the octets, so it bounds a coded h3 response's octets in
/// flight.
pub const encoder_ring_len: usize = 65_536;

/// The encoders a pool holds unless its caller names another count, the most coded responses the
/// connections given it send at once, and the deflate level they code at: 6, the middle of the
/// three levels stdx's encoder offers (1, 6 and 9).
pub const encoders_default: usize = 4;
/// The requests a connection holds at once by default (`Limits.requests_max`), which h2 advertises
/// (decision 110): each is a request the application works on. h2's stream table holds more, and a
/// configuration may lower it.
pub const requests_max: u32 = 100;

/// The longest deadline a caller may set: a day. A deadline starts at an instant the caller
/// passed, and this keeps the start plus the limit inside a `u64`.
pub const timeout_ns_max: u64 = 86_400 * constants.nanoseconds_per_second;

/// The request bodies one connection waits for at once: one in h11, and one for each stream an h2
/// peer may open.
pub const bodies_max: usize = h2.constants.limits.concurrent_streams_max;

/// The parameters that one pattern of a route table holds, its wildcard included (decision 122
/// ruling 10). It sizes `PathParameters`. A table that needs more does not compile, so the limit
/// never fails at run time.
pub const path_parameters_max: usize = 8;

/// The most methods that the routes of one table name (decision 128 ruling 3, which the owner set
/// on 2026-10-28): RFC 9110's eight, PATCH and one more token. Each method has a bit, and the
/// build writes the Allow value of each mask, so a table needs 2^10 = 1,024 values at most.
pub const route_methods_max: usize = 10;

/// The most octets of a path that a route table matches, its query included (decision 122 ruling
/// 13). It is the endpoint's own bound on a path: an h11 request line, or an h2 or h3 `:path`
/// field value. `match` gives `not_found` for a longer path, so the octets that one match reads
/// have a named bound (INV-8).
pub const path_len_max: usize = @max(h11.constants.limits.start_line_len_max, core.constants.limits.field_value_len_max);

comptime {
    assert(encoder_ring_len > 0 and encoders_default > 0);
    assert(quic_requests_max > 0 and quic_requests_max <= h3.constants.limits.request_streams_max);
    // A response's head, the longest field section h3 encodes behind a frame header, fits.
    assert(quic_response_kept_len >= h3.constants.protocol.frame_header_len_max + h3.constants.protocol.section_prefix_len_max);
    assert(quic_connections_default > 0 and quic_replies_max > 0);
    // Each request owes one `done` at most, and the ring that holds them has room for all.
    assert(done_owed_max >= quic_requests_max);
    // A unit that waits for its last octets never stops the next record from opening: an h11 head
    // (RFC 9112 §2.1) or an h2 frame (RFC 9113 §4.1), each one octet short of its limit, then room
    // for the most that follows a record's header (RFC 9846 §5.2).
    assert(plaintext_in_len >= h11.constants.limits.head_len_max - 1 + tls_provider.constants.protocol.record_ciphertext_len_max);
    assert(plaintext_in_len >= frame_len_max - 1 + tls_provider.constants.protocol.record_ciphertext_len_max);
    // The output holds a whole flight, and a whole field block with a frame after it.
    assert(output_len >= flight_len_max);
    assert(output_len >= h2.constants.limits.send_block_len_max + frame_len_max);
    assert(done_owed_max > 0);
    assert(tcp_connections_default > 0 and tcp_requests_max >= requests_max);
    assert(requests_max > 0 and requests_max <= h2.constants.limits.concurrent_streams_max);
    // A response can carry one header and one run of its body at least.
    assert(response_headers_max > 0 and response_pieces_max > 0);
    // A pattern can hold one parameter at least.
    assert(path_parameters_max > 0);
    // A leaf's mask of methods fits a u16.
    assert(route_methods_max > 0 and route_methods_max <= @bitSizeOf(u16));
    // Each path that the endpoint gives the program fits, in each version.
    assert(path_len_max >= h11.constants.limits.start_line_len_max and path_len_max >= core.constants.limits.field_value_len_max);
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(16393, frame_len_max);
    try expectEqual(49407, plaintext_in_len);
    try expectEqual(8192, certificate_len_max);
    try expectEqual(2, chain_certificates_max);
    try expectEqual(4096, flight_rest_len);
    try expectEqual(20480, flight_len_max);
    try expectEqual(49161, output_len);
    try expectEqual(5490, frames_per_receive_max);
    try expectEqual(4, data_frames_per_write_max);
    try expectEqual(9833, seals_per_send_max);
    try expectEqual(128, done_owed_max);
    try expectEqual(20, chunk_framing_len_max);
    try expectEqual(100, quic_requests_max);
    try expectEqual(8192, quic_response_kept_len);
    try expectEqual(16, quic_response_pieces_max);
    try expectEqual(32, response_headers_max);
    try expectEqual(16, response_pieces_max);
    try expectEqual(16384, quic_read_len);
    try expectEqual(1024, quic_transport_parameters_len_max);
    try expectEqual(100, retry_from_percent_max);
    try expectEqual(16, quic_connections_default);
    try expectEqual(16, tcp_connections_default);
    try expectEqual(128, tcp_requests_max);
    try expectEqual(5747, tcp_events_per_poll_max);
    try expectEqual(8, quic_replies_max);
    try expectEqual(1048877, quic_events_per_read_max);
    try expectEqual(128, coding_requests_max);
    try expectEqual(65536, encoder_ring_len);
    try expectEqual(4, encoders_default);
    try expectEqual(100, requests_max);
    try expectEqual(86400000000000, timeout_ns_max);
    try expectEqual(128, bodies_max);
    try expectEqual(8, path_parameters_max);
    try expectEqual(10, route_methods_max);
    try expectEqual(8192, path_len_max);
}
