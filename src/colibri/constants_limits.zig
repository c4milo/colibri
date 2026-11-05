//! The bounds `colibri` chose (decision 137), which size the memory a `Server` holds. Ask the
//! owner before changing one (CLAUDE.md).
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const tls = @import("tls");
const server = @import("server");

/// The longest PEM file of a server's chain or key: an ML-DSA-87 chain's two certificates, about
/// 7,500 octets of DER each, as base64 (RFC 7468 §2).
pub const pem_file_len_max: usize = 24 * 1024;
/// The DER room that holds any chain file of `pem_file_len_max` octets: base64 carries three
/// octets in four characters (RFC 4648 §4).
pub const chain_der_len_max: usize = pem_file_len_max / 4 * 3;
/// The certificates of a chain, as many as `tls` reads.
pub const chain_certificates_max: usize = tls.constants.limits.certificate_chain_len_max;

/// The octets a TCP socket reads and holds unread: whatever a connection holds before it consumes
/// a whole record, frame or head (`server.constants.limits.plaintext_in_len`).
pub const socket_input_len: usize = server.constants.limits.plaintext_in_len;
/// The octets a TCP socket holds to send: two of what a connection writes before `send` takes it,
/// so one send is in flight while the next is written.
pub const socket_output_len: usize = 2 * server.constants.limits.output_len;
/// The connections the kernel holds for `accept` before the server takes them.
pub const listen_backlog: u31 = 1024;
/// The longest a tick waits, so a `shutdown` from another thread takes effect within it.
pub const stop_wait_ns_max: u64 = 50_000_000;
/// The datagrams the UDP socket receives into at once: the buffers of the loop's group.
pub const udp_receive_buffers: u16 = 16;
/// Each receive buffer's octets: a datagram the kernel coalesced from one peer on Linux (UDP_GRO),
/// up to 64 KiB, and on macOS, which coalesces none, one QUIC datagram of the largest size colibri
/// sends and takes (RFC 9000 §14).
pub const udp_receive_buffer_len: u32 = if (builtin.os.tag == .linux) 66 * 1024 else 2048;
/// The octets one segmented send holds: the largest UDP payload over IPv4 (RFC 768, RFC 791).
pub const udp_segmented_bytes_max: usize = 65_507;
/// The datagrams one segmented send holds, which Linux bounds (UDP_MAX_SEGMENTS).
pub const udp_segments_max: usize = 64;
/// The batches the server fills each turn, one for each peer and codepoint, each one send.
pub const udp_batches: usize = 16;
/// The longest datagram the endpoint writes in one `send_datagram`: a 1,500-octet path's payload,
/// as the test-only UDP server's `quic_datagram_len_max`.
pub const udp_datagram_len_max: usize = 1500;
/// Events one pass of a step reads at most, and passes one step makes. A step that reaches the
/// bound leaves its entry pending, so the loop comes back to it with no wait.
pub const events_per_step_max: usize = 1024;

comptime {
    assert(udp_datagram_len_max <= udp_receive_buffer_len and udp_datagram_len_max <= udp_segmented_bytes_max);
    assert(socket_input_len > 0 and socket_output_len > server.constants.limits.output_len);
    assert(listen_backlog > 0 and events_per_step_max > 0 and stop_wait_ns_max > 0);
    assert(chain_der_len_max > 0 and chain_der_len_max < pem_file_len_max);
    assert(chain_certificates_max > 0);
}

test "decision 137: the limits of colibri" {
    try std.testing.expectEqual(24 * 1024, pem_file_len_max);
    try std.testing.expectEqual(18 * 1024, chain_der_len_max);
    try std.testing.expectEqual(16, chain_certificates_max);
    try std.testing.expectEqual(1024, listen_backlog);
    try std.testing.expectEqual(1024, events_per_step_max);
    try std.testing.expectEqual(50_000_000, stop_wait_ns_max);
    try std.testing.expectEqual(16, udp_receive_buffers);
    try std.testing.expectEqual(65_507, udp_segmented_bytes_max);
    try std.testing.expectEqual(64, udp_segments_max);
    try std.testing.expectEqual(16, udp_batches);
    try std.testing.expectEqual(1500, udp_datagram_len_max);
}
