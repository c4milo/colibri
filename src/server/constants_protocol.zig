//! The values the RFCs fix for server, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.
const h11 = @import("h11");
const h2 = @import("h2");
const quic = @import("quic");

/// Octets of the last chunk and the empty line after it, `0\r\n\r\n`, which end a chunked body
/// with no trailer field (RFC 9112 §7.1).
pub const last_chunk_len: usize = 5;

/// How far apart a QUIC connection's request numbers are: a stream ID's two low bits name its
/// type (RFC 9000 §2.1), so a client's request streams are 4 apart.
pub const quic_request_number_step: u64 = 1 << quic.constants.protocol.stream_id_type_bits;

/// How far apart a TCP connection's request numbers are at least: a client's h2 streams are 2
/// apart (RFC 9113 §5.1.1), and h11's requests, which count from 0, are one at a time.
pub const tcp_request_number_step: u64 = h2.constants.protocol.stream_id_step;
