//! Limits sim owns (docs/design.md §7). Never written inline (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;

/// The version of the trace format, written on its first line (design §6.6). colibri's own
/// formats are versioned from the first commit (CLAUDE.md non-negotiable 6); a change to what a
/// trace line holds is a new version, never a silent edit.
pub const trace_version: u32 = 1;

/// Longest trace record, in octets, its newline included. A record is built whole before it is
/// written, so this sizes the line a record is built in.
pub const trace_record_len_max: u32 = 512;

/// Longest check name a trace's first line carries.
pub const check_name_len_max: u32 = 32;

/// Longest chunk the byte pipe hands the caller at once, in octets. A chunk is 1 to this many
/// octets, so a seed produces every split of a short value.
pub const chunk_len_max: u32 = 16;

/// Longest delay between two chunks, in nanoseconds: one millisecond.
pub const chunk_delay_ns_max: u64 = 1_000_000;

/// Seeds `zig build sim -- --<check>-check` runs when no count is given, and the seeds each check's
/// test runs.
pub const check_seeds_default: u64 = 256;

/// Most values one chunk-check stream carries before its refused tail, if it has one.
pub const chunk_check_values_max: u32 = 16;

/// Longest text one chunk-check string literal carries, in octets.
pub const chunk_check_text_len_max: u32 = 16;

/// Longest encoding of one chunk-check value, in octets. `chunk_stream.zig` pins it against the
/// longest Huffman literal.
pub const chunk_check_value_len_max: u32 = 72;

/// Longest chunk-check stream: every value at its longest, and a refused tail.
pub const chunk_check_stream_len_max: u32 = (chunk_check_values_max + 1) * chunk_check_value_len_max;

/// One chunk-check seed in this many, on average, ends its stream with a refused encoding.
pub const chunk_check_refusal_one_in: u64 = 4;

/// Most octets one chunk-check trace holds: a record for every octet fed, every value, the refusal,
/// and the first and last lines, each at its longest.
pub const chunk_check_trace_len_max: u32 =
    (chunk_check_stream_len_max + chunk_check_values_max + 3) * trace_record_len_max;

/// Most frames one connection-check plan draws, before the frames of its refusal if it has one.
/// It stays below h2's `rst_stream_rate_max`, which `connection_stream.zig` pins: a plan that
/// reached that rate limit would fail for an instant the pipe chose, and chunking would decide
/// the outcome.
pub const connection_check_frames_max: u32 = 24;

/// Most streams one connection-check plan opens: one per frame it draws.
pub const connection_check_streams_max: u32 = connection_check_frames_max;

/// Most DATA payload octets one connection-check frame carries.
pub const connection_check_data_len_max: u32 = 64;

/// The fragments one connection-check field block is cut into: the HEADERS frame and the
/// CONTINUATION frames that follow it. A cut block has at least two, or no CONTINUATION frame
/// follows and it is not cut at all.
pub const connection_check_fragments_min: u32 = 2;
pub const connection_check_fragments_max: u32 = 4;

/// The SETTINGS_INITIAL_WINDOW_SIZE a connection-check plan advertises when it advertises a small
/// one: a window that holds several DATA frames and far less than the initial value.
pub const connection_check_window_size_small: u32 = 1024;

/// Largest WINDOW_UPDATE increment one connection-check frame carries. It is small so that the
/// increments of a whole plan cannot take a flow-control window near its maximum, which would end
/// the connection rather than exercise the window.
pub const connection_check_increment_max: u32 = 4096;

/// Identifiers a connection-check plan's first request may open. The lowest is the second one a
/// client may use, never the first, so the first identifier stays below the watermark and the
/// `headers_below_watermark` refusal always has one to name.
pub const connection_check_first_stream_ids: u64 = 3;

/// Most identifiers of its own parity a connection-check plan steps over between two requests. A
/// step above one leaves identifiers the peer never opened below the watermark.
pub const connection_check_stream_id_steps: u64 = 3;

/// One connection-check seed in this many, on average, ends its stream with frames the connection
/// refuses.
pub const connection_check_refusal_one_in: u64 = 4;

/// Most octets the client connection preface and the SETTINGS frame after it take.
pub const connection_check_preface_len_max: u32 = 64;

/// Most octets one drawn connection-check frame takes, the frames that continue it included.
pub const connection_check_frame_len_max: u32 = 96;

/// Most frames one connection-check refusal writes.
pub const connection_check_refusal_frames_max: u32 = 2;

/// Longest connection-check stream: the preface, every frame at its longest, and a refusal.
pub const connection_check_stream_len_max: u32 = connection_check_preface_len_max +
    (connection_check_frames_max + connection_check_refusal_frames_max) * connection_check_frame_len_max;

/// Most octets one connection-check trace holds: a record for every octet fed, every frame the
/// connection consumed, and the first and last lines, each at its longest.
pub const connection_check_trace_len_max: u32 = (connection_check_stream_len_max +
    connection_check_frames_max * connection_check_fragments_max +
    connection_check_refusal_frames_max + 3) * trace_record_len_max;

/// Octets the connection-check subject gives the connection to write the frames it owes: its own
/// SETTINGS frame and every reply its queues can hold. `connection_check.zig` pins it.
pub const connection_check_output_len_max: u32 = 1024;

/// The name the null suite computes every Retry Integrity Tag under. RFC 9001 §5.8 fixes the key
/// and the nonce of the real one for every connection, so the null one is a constant too.
pub const null_suite_retry_name: u32 = 0x5e77_1e5d;

/// How long a Retry token the null suite writes stays valid. RFC 9000 §8.1.4: "Servers SHOULD
/// ensure that tokens sent in Retry packets are only accepted for a short time, as they are
/// returned immediately by clients." One second is that short time here, measured against the
/// instant colibri passes in and never against a clock (non-negotiable 3).
pub const null_suite_retry_token_lifetime_ns: u64 = 1_000_000_000;

/// The first octet of every Retry token the null suite writes, which tells it from any other token
/// (RFC 9000 §8.1.1).
pub const null_suite_retry_token_type: u8 = 0x01;

/// The packet check of design §8 step 7 (`packet_check.zig`). Most packets one datagram holds: an
/// Initial, a Handshake and a 1-RTT packet, which is the order RFC 9000 §12.2 asks for.
pub const packet_check_packets_max: u32 = 3;

/// Most octets of one packet's payload, of an Initial packet's token, and of a datagram. The
/// datagram is past RFC 9000 §14.1's 1,200 octets, so three packets of the longest payload fit.
pub const packet_check_payload_len_max: u32 = 400;
pub const packet_check_token_len_max: u32 = 32;
pub const packet_check_datagram_len_max: u32 = 1500;

/// One in this many of the check's yes-or-no draws answers yes: whether a level is in the
/// datagram, whether anything is acknowledged, and which endpoint sends.
pub const packet_check_one_in: u64 = 2;

/// The largest packet number a seed starts from, which leaves every distance room below 2^62-1.
pub const packet_check_packet_number_base_max: u64 = 1 << 61;

/// Most key updates a seed performs before it seals, so both values of the Key Phase bit and the
/// keys of a later phase are drawn.
pub const packet_check_key_updates_max: u64 = 3;

/// The datagram network of design §8 step 8 (`network.zig`).
///
/// A schedule's drop, duplicate and congestion-marking rates are counts out of this, so a rate is
/// written as a plain fraction and no floating-point value enters a run (invariant 5).
pub const schedule_denominator: u32 = 1000;

/// Octets of the largest datagram the network carries. It is past RFC 9000 §14.1's smallest
/// allowed maximum of 1,200 octets, which every datagram carrying an Initial packet must reach.
pub const network_datagram_len_max: u32 = 1500;

/// Datagrams the network holds at once. A send with no slot left is a harness defect, not a
/// network event, so the number is far above what one run puts in flight.
pub const network_in_flight_max: u32 = 64;

/// The delay one datagram takes when a schedule names none, in nanoseconds: 5 to 45 milliseconds,
/// a spread wide enough that a datagram sent later arrives first.
pub const network_delay_min_ns: u64 = 5_000_000;
pub const network_delay_max_ns: u64 = 45_000_000;

/// The two endpoints' addresses before any rebind (`network.Address`). Only equality is ever
/// asked of them, so any distinct values serve.
pub const network_client_host: u8 = 1;
pub const network_server_host: u8 = 2;
pub const network_client_port: u16 = 50_000;
pub const network_server_port: u16 = 443;

/// The network check of design §8 step 8 (`network_check.zig`).
///
/// Packets one seed sends, the interval between them, and the longest payload. The interval is a
/// fraction of the delay range above, so several datagrams are in flight at once and they
/// overtake each other.
pub const network_check_turns: u32 = 64;
pub const network_check_turn_ns: u64 = 2_000_000;
pub const network_check_payload_len_max: u32 = 256;

/// Octets of a payload that carry the packet number the sender put in the header, so the peer
/// compares what it recovered against what was sent rather than against what is plausible.
pub const network_check_number_len: u32 = @sizeOf(u64);

/// The highest rate a seed's schedule draws for each event, out of `schedule_denominator`: one
/// datagram in ten dropped or duplicated at most, and one in four marked.
pub const network_check_drop_max: u64 = 100;
pub const network_check_duplicate_max: u64 = 100;
pub const network_check_mark_max: u64 = 250;

/// One in this many packets is sent with an ECT codepoint, which is what a node may mark.
pub const network_check_one_in: u64 = 2;

/// The draw that picks a packet's encryption level: one part Initial, one part Handshake, and the
/// rest 1-RTT, as a connection past its handshake sends.
pub const network_check_level_weights: u64 = 8;

comptime {
    assert(trace_version > 0);
    assert(chunk_len_max > 0);
    // The first line holds its fixed words, the check name and a 64-bit seed in hexadecimal.
    assert(trace_record_len_max > check_name_len_max + 64);
    assert(check_seeds_default > 0);
    assert(connection_check_frames_max > 0);
    assert(connection_check_fragments_min > 1);
    assert(connection_check_fragments_max >= connection_check_fragments_min);
    assert(connection_check_window_size_small > 0);
    assert(connection_check_first_stream_ids > 0 and connection_check_stream_id_steps > 0);
    assert(connection_check_refusal_one_in > 1);
}

test "a chunk and a trace record are never empty" {
    try std.testing.expect(chunk_len_max >= 1);
    try std.testing.expect(trace_record_len_max >= 1);
}

/// The offsets inside the record header RFC 9846 §5.1 defines, for the null provider's framing.
pub const record_content_type_offset: u32 = 0;
pub const record_version_offset: u32 = 1;
pub const record_length_offset: u32 = 3;

/// RFC 9846 §5.1: legacy_record_version is 0x0303 on every record a TLS 1.3 endpoint writes after
/// the first flight. Both octets are the same value.
pub const record_legacy_version_octet: u8 = 0x03;

/// The octets a real AEAD adds to every record (RFC 9846 §5.2). The null provider writes as many
/// zeros, so a record occupies what one would occupy on the wire.
pub const record_tag_len: u32 = 16;

/// The largest h2 byte stream the TLS check wraps in records: a preface, a SETTINGS frame and one
/// request. It is fixed, because what the check varies is where the records cut it.
pub const tls_check_stream_len_max: u32 = 512;

/// Where the TLS check's connection writes what it owes, which the check drops.
pub const tls_check_output_len_max: u32 = 1024;

/// The plaintext one `decrypt` call writes, which is one record's body.
pub const tls_check_plaintext_len_max: u32 = tls_check_stream_len_max;

/// Records one seed may cut the stream into, which bounds the check's loop (non-negotiable 4).
pub const tls_check_records_max: u32 = 64;

/// The events one run may record, which is one per frame the connection accepted.
pub const tls_check_events_max: u32 = 32;

/// The octets a record adds around its body: the header RFC 9846 §5.1 defines, whose last field is
/// the two-octet length, and the tag §5.2 sizes.
pub const record_overhead_len: u32 = record_length_offset + @sizeOf(u16) + record_tag_len;

/// The buffers the counted-cost check drives one request through. They are generous on purpose:
/// what the check measures is how many times the caller crosses colibri's boundary and how many
/// octets cross with it, not what a small buffer forces.
pub const cost_check_buffer_len: u32 = 4096;

/// The null `tls.QuicVTable` of design §8 step 9e (`null_quic_provider.zig`).
///
/// RFC 9846 §4 frames a handshake message as a one-octet HandshakeType, a uint24 length and the
/// body. The null QUIC provider frames its made-up messages the same way, so a message cut across
/// CRYPTO frames is put back together the way a real one is.
pub const null_quic_message_type_len: u32 = 1;
pub const null_quic_message_length_len: u32 = 3;
pub const null_quic_message_header_len: u32 =
    null_quic_message_type_len + null_quic_message_length_len;

/// Octets of one `quic_transport_parameters` body an endpoint holds, and it holds two: its own
/// and the peer's (RFC 9001 §8.2). RFC 9000 §18 gives the body no maximum, so the null provider
/// states its own, as the vtable's `NoSpaceLeft` says a provider must.
pub const null_quic_params_len_max: u32 = 512;

/// Octets one encryption level holds of handshake messages that have not been read yet. RFC 9001
/// §4.1.3: "TLS is responsible for buffering handshake bytes that have arrived in order." It holds
/// the longest flight one level carries: EncryptedExtensions with the parameters, and the Finished
/// after it.
pub const null_quic_pending_len_max: u32 = 1024;

/// Steps in the longest role script of `null_quic_provider.zig`, which bounds the loop that reads
/// a flight (CLAUDE.md non-negotiable 4).
pub const null_quic_steps_max: u32 = 5;

/// The QPACK check (design §8 step 11): at most this many field sections per seed, each of at
/// most `qpack_check_lines_max` lines, on at most `qpack_check_streams` request streams.
pub const qpack_check_sections_max: u32 = 24;
pub const qpack_check_lines_max: u32 = 12;
pub const qpack_check_streams: u64 = 8;

/// Request stream IDs are client-initiated bidirectional ones, which RFC 9000 §2.1 numbers in
/// steps of four.
pub const qpack_check_stream_id_step: u64 = 4;

/// The random values a seed draws, which its lines repeat so the dynamic table has something to
/// reference, and the longest of them.
pub const qpack_check_values: u32 = 6;
pub const qpack_check_value_len_max: u32 = 48;

/// Table capacities a QPACK-check seed advertises, from none to colibri's largest, 16,384
/// (`qpack.constants.dynamic_table_capacity_max`, which `sim` cannot import).
pub const qpack_check_capacities = [_]u64{ 0, 64, 128, 220, 512, 1024, 4096, 16_384 };

/// Blocked-stream counts a QPACK-check seed advertises, up to colibri's most, 100.
pub const qpack_check_blocked_counts = [_]u64{ 0, 1, 2, 8, 100 };

/// One step in this many that could cancel a stream does (RFC 9204 §2.2.2.2).
pub const qpack_check_cancel_one_in: u64 = 16;

/// One line in this many is `no_insert`, and one in this many `never_indexed`; the rest are
/// `may_insert`.
pub const qpack_check_no_insert_one_in: u64 = 10;
pub const qpack_check_never_indexed_one_in: u64 = 10;

/// Octets of one encoded field section, of the whole encoder stream, and of the whole decoder
/// stream a seed writes. Each holds the most its drawn sections can produce.
pub const qpack_check_section_len_max: u32 = 4096;
pub const qpack_check_encoder_stream_len_max: u32 = 64 * 1024;
pub const qpack_check_decoder_stream_len_max: u32 = 4096;

/// Steps one seed may take before the check calls it stuck: far more than delivering every
/// section, every encoder stream octet and every decoder stream octet one step each needs.
pub const qpack_check_steps_max: u32 = 4096;

/// The trace one seed writes: a record per step.
pub const qpack_check_trace_len_max: u32 = qpack_check_steps_max * 64;

/// The h3 check (design §8 step 12): the exchanges one seed draws, sent in rounds of
/// `h3_check_round_len`, the regular lines of one message beyond its pseudo-header fields, and its
/// longest content. A seed's lines repeat across its exchanges, drawn from `h3_check_values`
/// values of up to `h3_check_value_len_max` octets, so a table the peer allows is used, and over
/// many rounds fills and evicts, and h3's own streams outgrow their buffers (decision 78).
pub const h3_check_exchanges_max: u32 = 64;
pub const h3_check_round_len: u32 = 8;
pub const h3_check_lines_max: u32 = 6;
pub const h3_check_content_len_max: u32 = 3000;
/// The long h3 check: fewer seeds, each one connection of up to `h3_long_check_exchanges_max`
/// exchanges with short content, so QPACK's encoder stream outgrows its buffer and h3 drops the
/// octets its peer acknowledged (decision 78). A normal seed's connection never gets that far.
pub const h3_long_check_seeds: u64 = 128;
pub const h3_long_check_exchanges_max: u32 = 512;
pub const h3_long_check_content_len_max: u32 = 256;
pub const h3_check_values: u32 = 8;
pub const h3_check_value_len_max: u32 = 100;
/// The QPACK settings a seed draws each endpoint's decoder from (RFC 9204 §5).
pub const h3_check_capacities = [_]u64{ 0, 256, 1024, 4096 };
pub const h3_check_blocked_counts = [_]u64{ 0, 16 };
/// One in this many exchanges has an interim response, and one in this many messages trailers.
pub const h3_check_interim_one_in: u64 = 4;
pub const h3_check_trailers_one_in: u64 = 4;
/// The frames a caller keeps for one message: its header sections and DATA frame header before
/// the content, and its trailer section after. The content is made from its offset, as a file
/// server reads a file, and kept nowhere.
pub const h3_check_prefix_len_max: u32 = 2048;
pub const h3_check_suffix_len_max: u32 = 128;
/// The steps one run may take, the steps it may take to settle once the client read every
/// response, the datagrams one endpoint may send in a step, and the highest drop and duplicate
/// rates a seed draws, out of `schedule_denominator`.
pub const h3_check_steps_max: u32 = 100_000;
pub const h3_check_settle_steps_max: u32 = 1_000;
pub const h3_check_sends_per_step_max: u32 = 64;
pub const h3_check_drop_max: u64 = 100;
pub const h3_check_duplicate_max: u64 = 100;

/// The h3 trace run (https://github.com/c4milo/colibri/issues/58), inside the scope of
/// `spec/tla/h3_connection`: the requests one seed opens, the DATA frames each carries, the GOAWAY
/// frames the server sends, and the server decoder's blocked-stream limit and table capacity. The
/// client opens, cancels and the server shuts down within `h3_trace_act_steps` steps, and one
/// request in `h3_trace_cancel_one_in` is cancelled. Each DATA frame carries
/// `h3_trace_data_len` octets.
pub const h3_trace_requests_max: u32 = 3;
pub const h3_trace_content_max: u32 = 2;
pub const h3_trace_goaways_max: u32 = 2;
pub const h3_trace_blocked_max: u64 = 2;
pub const h3_trace_capacity: u64 = 256;
pub const h3_trace_act_steps: u64 = 16;
pub const h3_trace_cancel_one_in: u64 = 3;
pub const h3_trace_data_len: u32 = 4;
/// The frames the trace run keeps for one message, the steps one run may take, and the highest
/// drop and duplicate rates a seed draws, out of `schedule_denominator`.
pub const h3_trace_prefix_len_max: u32 = 2048;
pub const h3_trace_steps_max: u32 = 10_000;
pub const h3_trace_drop_max: u64 = 50;
pub const h3_trace_duplicate_max: u64 = 50;
/// The model's states one trace run keeps, each one differing from the last, and the octets of
/// the TLA+ module one seed's trace is written as.
pub const h3_trace_states_max: u32 = 1024;
pub const h3_trace_module_len_max: u32 = 1 << 20;
/// The seeds `sim --h3-trace-write` writes for TLC, and the model's steps TLC may take between two
/// logged states.
pub const h3_trace_written_seeds: u64 = 64;
pub const h3_trace_steps_between_max: u64 = 24;
/// The units the trace run logs from one of h3's own streams, at most. A request causes at most
/// one insert, and at most three decoder instructions: a Section Acknowledgment, a Stream
/// Cancellation and an Insert Count Increment. Four per request leaves one to spare. The last
/// term adds the control stream's SETTINGS and one more to spare.
pub const h3_trace_units_per_request_max: u32 = 4;
pub const h3_trace_units_max: u32 = h3_trace_units_per_request_max * h3_trace_requests_max +
    h3_trace_goaways_max + 2;
/// The frames the control stream may carry for each unit logged: the unit and a reserved frame
/// before it (RFC 9114 §7.2.8).
pub const h3_trace_control_frames_per_unit_max: u32 = 2;

/// The h11 split check (design §8 step 15a): the messages one seed pipelines, the field lines a
/// message carries besides Host and its framing, the longest fixed body, the chunks of a chunked
/// body and the longest chunk, the trailer fields a chunked body carries, and one seed in this many
/// planting a defect.
pub const h11_split_messages_max: u32 = 4;
pub const h11_split_extra_fields_max: u32 = 3;
pub const h11_split_body_len_max: u32 = 48;
pub const h11_split_chunks_max: u32 = 4;
pub const h11_split_chunk_len_max: u32 = 16;
pub const h11_split_trailers_max: u32 = 2;
pub const h11_split_defect_one_in: u64 = 3;
/// The longest message the plan writes, and the longest stream: every message at its longest.
pub const h11_split_message_len_max: u32 = 512;
pub const h11_split_stream_len_max: u32 = h11_split_messages_max * h11_split_message_len_max;
/// Most octets one h11 split-check trace holds: a head and an end record per message, a refusal,
/// and the first and last lines.
pub const h11_split_trace_len_max: u32 = (2 * h11_split_messages_max + 3) * trace_record_len_max;

/// The QPACK input check: inputs per seed, the most edits made to one, and the longest input.
pub const qpack_input_check_inputs: u32 = 32;
pub const qpack_input_check_edits_max: u64 = 8;
pub const qpack_input_check_input_len_max: u32 = 512;

comptime {
    assert(qpack_check_sections_max > 0 and qpack_check_lines_max > 0);
    assert(qpack_check_streams > 0);
}

comptime {
    assert(null_quic_message_header_len ==
        null_quic_message_type_len + null_quic_message_length_len);
    // One level holds the longest message the provider writes and the Finished that follows it.
    assert(null_quic_pending_len_max >=
        null_quic_params_len_max + 2 * null_quic_message_header_len);
    assert(null_quic_steps_max > 0);
}
