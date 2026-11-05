//! The bounds `colibri` chose (decision 137), which size the memory a `Server` holds. Ask the
//! owner before changing one (CLAUDE.md).
const std = @import("std");
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
/// Events one pass of a step reads at most, and passes one step makes. A step that reaches the
/// bound leaves its entry pending, so the loop comes back to it with no wait.
pub const events_per_step_max: usize = 1024;

comptime {
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
}
