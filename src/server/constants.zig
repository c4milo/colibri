//! The limits of `server` (decision 100, design §8 step 17a), each named once. A connection's
//! buffers are sized from h2's frame limits and the TLS record limits, so every size is a comptime
//! constant a caller can read (decision 35).
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
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

comptime {
    // A frame waiting for its last octets never stops the next record from opening.
    assert(plaintext_in_len >= frame_len_max + tls_provider.constants.record_ciphertext_len_max);
    // The output holds a whole flight, and a whole field block with a frame after it.
    assert(output_len >= flight_len_max);
    assert(output_len >= h2.constants.send_block_len_max + frame_len_max);
    // Every chunk the output holds leaves room for the last one.
    assert(output_len > chunk_framing_len_max + last_chunk_len);
    assert(done_owed_max > 0);
}
