//! Limits the test-only entry points of docs/design.md §9 own. Never written inline (CLAUDE.md
//! non-negotiable 4). Nothing here is packaged: `src/testing/` is excluded from the library.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const h11 = @import("h11");

/// Octets the server reads from a socket at once: one whole h2 frame, header included, so a
/// connection always makes progress on the largest frame colibri accepts (RFC 9113 §4.2).
pub const read_buffer_len: u32 = h2.constants.frame_header_len + h2.constants.frame_size_max;

/// Octets the server writes at once: a whole field block cut into frames, and the DATA frame of a
/// response body after it.
pub const write_buffer_len: u32 = h2.constants.send_block_len_max + read_buffer_len;

/// Octets a connection of the server reads from its socket at once. A cleartext connection reads
/// an h2 frame, and a TLS connection a whole record, which is what chapulin opens (RFC 9846
/// §5.1), so this is the larger of the two.
pub const wire_read_len: u32 = @max(read_buffer_len, h2.tls_provider.constants.record_write_len_min);

/// The instant one step of the server reports, in nanoseconds, and how far the next one is. The
/// server reads no clock: design §4.2 makes time a value the caller passes, and
/// `tools/lint/determinism.zig` holds `src/testing/` to it too. A fixed step keeps the rate limits
/// of RFC 9113 §10.5 advancing without a clock, and keeps one run byte-identical to the next.
pub const tick_ns: u64 = 1_000_000;

/// Decoders of the gzip and deflate transfer codings each worker's cleartext h11 connections share
/// (decision 91). The HTTP Garden sends one coded request at a time on each connection.
pub const h11_decoders_per_worker: u32 = 4;

/// Octets a worker's h11 connection decodes into per call (decision 98). The echo copies what it
/// gets at once, so a worker's connections share the buffer.
pub const h11_decoded_len: u32 = 16384;

/// Most octets of request content the server's `--echo` mode returns (`h11/h11_echo.zig`). A
/// request with more is answered with 413 (RFC 9110 §15.5.14) and no echo.
pub const echo_body_len_max: u32 = 16384;

/// Octets of the JSON one echo writes: the method and the target, each at most a request line
/// long, the field lines, each name and value base64-encoded inside `["",""],`, the content, and
/// the keys around them (`h11/h11_echo.zig`). Only modules that import h11 reach it, so its
/// comptime asserts are in `h11/h11_echo.zig`.
pub const echo_json_len_max: u32 = 2 * base64_len(h11.constants.start_line_len_max) +
    base64_len(h11.core.constants.field_section_size_max) + echo_json_line_len * h11.core.constants.field_count_max +
    base64_len(echo_body_len_max) + echo_json_keys_len;
/// The octets around one field line in the echo, `["",""],`, and around everything else.
pub const echo_json_line_len: u32 = 8;
pub const echo_json_keys_len: u32 = 128;

/// Octets of the standard base64 encoding of `len` octets, which the HTTP Garden decodes.
fn base64_len(len: u32) u32 {
    return @intCast(std.base64.standard.Encoder.calcSize(len));
}

/// The port the server listens on when the caller names none.
pub const default_port: u16 = 8080;

/// The base a port is written in on the command line.
pub const port_radix: u8 = 10;

/// Most command-line arguments the server reads, which bounds the loop that reads them.
pub const arguments_max: u32 = 16;

/// Workers the server runs, one per core up to this many. Each has its own listening socket, its
/// own connections and its own thread, and reads no other worker's memory.
pub const workers_max: u32 = 8;

/// The encoders each worker of the test-only server codes responses with in its `--coded` mode
/// (decision 101): the coded responses its connections send at once.
pub const encoders_per_worker: usize = 4;

/// Connections one worker serves at once. SO_REUSEPORT ties a connection to the worker whose
/// listener the kernel picked, and that choice is a hash rather than a balance: several peers can
/// land on one worker while another sits idle. So a worker holds far more connections than an even
/// spread would need, and a peer that arrives when its worker is full waits in that listener's
/// backlog. A slot costs one session and its buffers, which the operating system maps only when a
/// connection touches it.
pub const connections_per_worker_max: u32 = 32;

/// Connections the kernel holds for a worker before it refuses one, which is listen's backlog.
pub const kernel_backlog: u31 = 64;

/// The width of a cache line on the hosts colibri is measured on: 64 octets on x86-64 and 128 on
/// Apple silicon. A worker is padded to a multiple of it, so no two workers write one line
/// (CLAUDE.md, Performance).
pub const cache_line_bytes: u32 = 128;

/// Most responses a session owes at once, one per request that ended and has not been answered
/// whole. It is one more than the streams the connection allows, so the queue never stops the
/// reading before the stream limit does: a peer that opens one stream too many is refused by
/// SETTINGS_MAX_CONCURRENT_STREAMS and its REFUSED_STREAM (RFC 9113 §5.1.2), not a server that
/// stopped reading.
pub const responses_owed_max: u32 = h2.constants.concurrent_streams_max + 1;

/// Most steps one session takes between two reads from the socket. A step that neither consumes
/// nor writes ends the loop, so this only bounds it: one step answers at most one request, and a
/// read holds at most one frame.
pub const steps_per_read_max: u32 = 64;

/// The body every response carries. Design §9 asks for a non-empty body, which is what h2load
/// measures and what h2spec's DATA cases need.
pub const response_body = "colibri\n";

/// The `content-type` of that body (RFC 9110 §8.3).
pub const response_content_type = "text/plain; charset=utf-8";

/// The status every request is answered with (RFC 9110 §15.3.1).
pub const response_status: u16 = 200;

/// Digits of the `content-length` the server writes, which is `response_body`'s length
/// (RFC 9110 §8.6).
pub const response_content_length = "8";

/// Most exchanges one client session runs, each a request and the response to it on a stream of
/// its own. It bounds the plan the command line reads and the array the session holds.
pub const exchanges_max: u32 = 8;

/// Most octets of request content one exchange sends. It is past the 65,535-octet window a stream
/// starts with (RFC 9113 §6.9.2) several times over, so a plan can make the peer's WINDOW_UPDATE
/// frames the only way the content finishes.
pub const request_content_len_max: u32 = 1 << 24;

/// The period of the request content: octet `i` of it is `i % request_content_period`. A prime,
/// so no frame size, record size or window divides it, and content a peer reorders, drops or
/// repeats does not echo back as the same octets.
pub const request_content_period: u32 = 251;

/// Octets of a response's content the client keeps for each exchange, which `client` copies into
/// the exchange's memory: `tools/h2_interop.sh`'s `/large`, 1 MiB, whole.
pub const response_content_len_max: u32 = 1 << 20;

/// Decimal digits of the longest `content-length` a request carries (RFC 9110 §8.6), which is
/// `request_content_len_max`'s.
pub const content_length_digits_max: u32 = 8;

/// The `user-agent` every request names (RFC 9110 §10.1.5).
pub const user_agent = "colibri";

/// Connections one client run holds at once, all on one Rotor loop on one thread. Every one runs
/// the whole plan, so a run with several is the same exchanges on several connections.
pub const client_connections_max: u32 = 64;

/// Most command-line arguments the client reads: its options, and two per exchange.
pub const client_arguments_max: u32 = 16 + 2 * exchanges_max;

/// Nanoseconds the client's loop waits for any event before it gives the run up: ten seconds,
/// the most one Rotor tick waits. A peer that stops answering ends the run with a failure instead
/// of holding it forever. The waiting is the kernel's: no source file here reads a clock (design
/// §4.2).
pub const client_wait_ns: u64 = 10 * ns_per_s;

/// Nanoseconds in a second, named here because `src/testing/` reads nothing from `std.time`
/// (decision 63).
const ns_per_s: u64 = 1_000_000_000;

/// Most ticks one client run makes, which bounds its loop.
pub const client_ticks_max: u32 = 1 << 20;

comptime {
    assert(exchanges_max > 0 and client_connections_max > 0 and client_ticks_max > 0);
    assert(response_content_len_max > h2.constants.frame_size_max);
    // The digits hold the largest length a plan may name.
    assert(std.math.pow(u64, port_radix, content_length_digits_max) > request_content_len_max);
    assert(client_wait_ns > 0 and client_arguments_max > arguments_max);
}

comptime {
    assert(read_buffer_len > h2.constants.frame_size_max);
    assert(write_buffer_len > read_buffer_len);
    assert(tick_ns > 0 and default_port > 0 and port_radix > 0);
    assert(arguments_max > 0 and steps_per_read_max > 0 and responses_owed_max > 0);
    assert(workers_max > 0 and connections_per_worker_max > 0 and kernel_backlog > 0);
    assert(cache_line_bytes > 0 and cache_line_bytes % @alignOf(u64) == 0);
    assert(response_body.len > 0);
    // The declared length is the body's, or a peer would wait for octets that never come.
    assert(response_content_length.len == 1 and response_content_length[0] - '0' == response_body.len);
}

/// The largest DER the TLS checks read from one file: a certificate, a Subject Name or a
/// SubjectPublicKeyInfo. An RSA-4096 certificate runs to about 1,400 octets and an RSA-4096 SPKI
/// to about 550. The QUIC Interop Runner's amplification case pads its leaf with twenty 250-octet
/// DNS names, to 5,514 octets, so this holds 8 KiB.
pub const tls_der_len_max: usize = 8 * 1024;

/// The octets one TLS check moves over its socket in a single pass: one record at most, which
/// RFC 9846 §5.1 caps at 2^14 of plaintext plus its header and tag.
pub const tls_record_buffer_len: usize = 18 * 1024;

/// h2's byte stream one TLS connection of the server holds: a frame the session has not finished
/// reading, and one more record's plaintext after it. The record adapter asks for room for the
/// record's whole ciphertext, which its plaintext never exceeds (RFC 9846 §5.2).
pub const tls_plaintext_in_len: usize = read_buffer_len + h2.tls_provider.constants.record_ciphertext_len_max;

/// The most octets the server's handshake flight takes. chapulin writes a flight whole or fails
/// the handshake (`srv_cfg.h`), so the server's output holds this much before a handshake step
/// runs. It is the chain's two certificates, at most `tls_der_len_max` each, and the rest.
pub const tls_flight_len_max: usize = 2 * tls_der_len_max + tls_flight_rest_len;

/// The rest of the flight: ServerHello, the compatibility ChangeCipherSpec, EncryptedExtensions,
/// CertificateVerify and Finished, and a header and tag around every record. The library's object
/// seals up to 16,384 octets of plaintext per record (`TX_RECORD`, decision 97), so two 8 KiB
/// certificates take two records and their overhead; the other messages are a few hundred octets
/// more.
pub const tls_flight_rest_len: usize = 4 * 1024;

/// The label, context and length both TLS checks export under (RFC 9846 §7.5). The Go peers in
/// `tools/h2_interop/` export under the same three, and the scripts require the two values to
/// match. The label is longer than the 12 octets TLS 1.3's own labels need, so a chapulin that
/// kept its default label bound would fail the run.
pub const tls_exporter_label = "EXPORTER-colibri-check";
pub const tls_exporter_context = "colibri";
pub const tls_exporter_len: usize = 32;

/// Operations one UDP endpoint's loop holds in flight: its one multishot receive, and the sends
/// the kernel has not yet taken (decision 58).
pub const udp_operations_max: u32 = 64;

/// Buffers the kernel receives datagrams into, a power of two as rotor's groups require. The
/// endpoint gives each back once it has read it, so a few cover a burst; rotor's guide advises
/// sizing a group to the buffers in flight rather than to the memory there is.
pub const udp_receive_buffers: u32 = 16;

/// Octets of one receive buffer: rotor's prefix of 192, which holds the peer's address and the
/// control messages, and the datagram after it.
pub const udp_buffer_bytes: u32 = 2048;

/// The largest datagram an endpoint must receive whole: Ethernet's MTU, which the paths of
/// design §9's endpoints stay within.
pub const udp_payload_len_min: u32 = 1500;

/// The peer's transport parameters the QUIC provider keeps (RFC 9001 §8.2). RFC 9000 §18 sets no
/// bound, and this holds every parameter §18.2 defines with room for a peer's own.
pub const quic_peer_params_len_max: usize = 1024;

/// The NSS key log the QUIC check writes to SSLKEYLOGFILE: four lines per endpoint, each a label
/// of at most 31 octets, a 32-octet client random and a secret of at most 48 octets in hex, so
/// 194 octets.
pub const quic_keylog_len: usize = 2048;

/// The largest datagram the QUIC check moves between its two endpoints: RFC 9000 §14's 1,200
/// octets plus the room a path of Ethernet's MTU leaves.
pub const quic_datagram_len_max: usize = udp_payload_len_min;

/// Rounds the QUIC check runs before it calls the run stuck. A round moves every datagram each
/// endpoint owes, and a clean run finishes in a few dozen.
pub const quic_rounds_max: u32 = 10_000;

/// The instant the QUIC check advances by each round. It is the check's own time, never the
/// clock's (non-negotiable 3), and it is long enough that a peer's `max_ack_delay` passes.
pub const quic_round_ns: u64 = 5_000_000;

/// Certificates the QUIC server presents at most: the end-entity and every certificate above it.
/// The QUIC Interop Runner's longest chain is its amplification case's, a leaf under eight
/// intermediates.
pub const quic_chain_len_max: usize = 16;

/// The longest hq-interop request line an endpoint reads or writes: `GET `, a path and CRLF. The
/// runner's paths are a directory and a random file name, far shorter than this.
pub const hq_request_len_max: usize = 1024;
/// The frames the h3 endpoint keeps for one request stream until it closes (decision 79): a
/// response's HEADERS frame and its DATA frame's header at a server, and a request's HEADERS frame
/// at a client, whose `:authority` is the host name.
pub const h3_response_prefix_len_max: usize = 256;
pub const h3_request_prefix_len_max: usize = 1024;
/// The window each endpoint grants a peer's stream beyond the request lines hq-interop sends:
/// an h3 request's content and the peer's h3 control and QPACK streams. RFC 9114 §6.2 asks for "at
/// least 1,024 bytes" on each unidirectional stream.
pub const h3_stream_window: u64 = 65_536;

/// The QPACK settings the h3 endpoint's decoder advertises (RFC 9204 §5), so its peer's encoder
/// uses a dynamic table toward it: the most blocked streams colibri holds, and a table that size.
pub const h3_qpack_capacity: u64 = 4096;
pub const h3_qpack_blocked_streams: u64 = 16;

/// The body the h3 server answers `/` with, as design §9's h2 server answers `GET /`.
pub const h3_root_body = "colibri\n";

/// Requests the hq-interop server answers at once, which is the `initial_max_streams_bidi` it
/// grants: one slot, with its request line, per stream the client may have open.
pub const hq_requests_max: usize = 100;

/// Paths one hq-interop client run fetches. The runner's multiplexing case asks for the most.
pub const hq_paths_max: usize = 2048;

/// Octets the hq-interop client reads from a stream at once, before it writes them to the file.
pub const hq_read_len: usize = 16 * 1024;

/// The application error code of a stream the hq-interop server refuses. hq-interop defines no
/// codes, so it is 0.
pub const hq_refused_error_code: u64 = 0;

/// Datagrams one UDP endpoint may have in flight to the kernel: every operation of the loop but
/// its receive.
pub const udp_send_slots: usize = udp_operations_max - 1;

/// Operations the client's channel mode holds for its TCP connection at once: a receive, a send,
/// and the close that ends them (`client/channel_tcp.zig`). A connect is alone in flight.
pub const channel_tcp_operations_max: u32 = 3;

/// Datagrams the client's channel mode may have in flight to the kernel: every operation of the
/// loop but its receive and its TCP connection's.
pub const channel_udp_send_slots: usize = udp_operations_max - 1 - channel_tcp_operations_max;

/// How long the channel mode's QUIC handshake runs before TCP opens beside it, unless
/// `--fallback-ms` names another. A handshake on loopback completes in a few milliseconds, and a
/// run against a server with no UDP waits no longer than this for TCP.
pub const channel_fallback_delay_ns: u64 = 250 * nanoseconds_per_millisecond;

/// How long one channel mode run lasts before the client gives it up: past the idle timeout the
/// QUIC connection advertises (`client.constants.quic_idle_timeout_ms_default`), so a QUIC
/// handshake that never completes ends first.
pub const channel_run_ns_max: u64 = 60 * nanoseconds_per_second;

/// Connections one UDP QUIC server can hold at once, which sizes its static table. The server's
/// `connections=<n>` option holds fewer. The QUIC Interop Runner's handshake loss case opens 50
/// connections, and quinn's client opens all 50 at once. A connection whose close was lost also
/// lingers until its idle timeout (RFC 9000 §10.1), so the table holds more than the case opens.
pub const quic_connections_max: usize = 64;

/// Octets of one UDP QUIC connection's qlog between two turns of the loop (decision 102). A turn
/// logs the packets of at most `udp_operations_max` datagrams received and as many sent, a few
/// hundred octets each, and the next turn writes them to the connection's file.
pub const quic_qlog_len: usize = 256 * 1024;

/// How long a UDP QUIC server accepts a Retry token after minting it. RFC 9000 §8.1.4: "Servers
/// SHOULD ensure that tokens sent in Retry packets are only accepted for a short time, as they are
/// returned immediately by clients." Ten seconds covers a client that loses its first reply.
pub const quic_retry_token_lifetime_seconds: u64 = 10;

/// chapulin counts a Retry token's instants in seconds, and colibri passes nanoseconds.
pub const nanoseconds_per_second: u64 = 1_000_000_000;

/// RFC 9846 §4.3.11.1 counts a ticket's age in milliseconds, and Rotor's instant is in nanoseconds.
pub const nanoseconds_per_millisecond: u64 = 1_000_000;

/// The longest one tick of a UDP QUIC endpoint waits. A connection's next deadline is usually
/// sooner, and a wait this short keeps a lost wakeup cheap.
pub const quic_tick_wait_ns_max: u64 = 100 * 1_000_000;

/// Ticks one UDP QUIC endpoint runs before it gives up: with `quic_tick_wait_ns_max`, days.
pub const quic_run_ticks_max: u64 = 1 << 32;

/// The idle timeout each UDP QUIC endpoint advertises (RFC 9000 §10.1), in milliseconds.
pub const quic_idle_timeout_ms: u64 = 30_000;

/// Octets each connection of the UDP server's `h3` mode holds of a request's content before h3
/// reads them (decision 61). h3spec, aioquic and the QUIC Interop Runner send small requests.
pub const h3_receive_pool_len: usize = 65_536;

/// Events the `h3` mode reads from one connection in one turn at most, and from its endpoint, which
/// holds `quic_connections_max` of them, which bounds its loop.
pub const h3_serve_events_max: usize = 4096;
pub const h3_endpoint_events_max: usize = h3_serve_events_max * quic_connections_max;

comptime {
    assert(hq_paths_max >= hq_requests_max);
    assert(udp_send_slots > 0 and channel_udp_send_slots > 0);
    assert(channel_fallback_delay_ns > 0 and channel_run_ns_max > channel_fallback_delay_ns);
    assert(hq_request_len_max > "GET /\r\n".len);
    assert(quic_datagram_len_max <= udp_buffer_bytes);
    assert(quic_rounds_max > 0 and quic_round_ns > 0);
    assert(h3_receive_pool_len > 0 and h3_serve_events_max > 0);
}

comptime {
    assert(udp_operations_max > 1);
    assert(std.math.isPowerOfTwo(udp_receive_buffers));
    assert(udp_buffer_bytes > udp_payload_len_min);
}

comptime {
    assert(tls_record_buffer_len > 1 << 14);
    assert(tls_der_len_max > 0);
    // The server's output holds a whole flight, and its input a whole record.
    assert(write_buffer_len >= tls_flight_len_max);
    assert(wire_read_len >= h2.tls_provider.constants.record_write_len_min);
    assert(tls_plaintext_in_len > read_buffer_len + h2.tls_provider.constants.record_plaintext_len_max);
}
