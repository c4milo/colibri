//! The 1-RTT packets a server keeps while it waits for the Finished that completes its handshake
//! (https://github.com/c4milo/colibri/issues/153, design §8 step 71).
//!
//! RFC 9001 §5.7: "A server MUST NOT process incoming 1-RTT protected packets before the TLS
//! handshake is complete." It goes on: "Received packets protected with 1-RTT keys MAY be stored
//! and later decrypted and used once the handshake is complete." A client whose Finished was lost
//! can send its request in a 1-RTT packet that reaches the server first. A server that drops that
//! packet waits for the client to send the request again, and a client whose probes carry other
//! frames never does. So a server keeps a few such packets, still protected, and
//! `connection_datagram` opens them once the handshake completes.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const receive_module = @import("connection_receive.zig");

const Connection = connection_module.Connection;
const Ecn = receive_module.Datagram.Ecn;

/// The packets kept, and their octets, which the connection owns (decision 35).
pub const EarlyPackets = struct {
    /// The protected octets of the kept packets, one after another.
    octets: [constants.limits.early_packet_octets_max]u8,
    /// Each kept packet, in the order it arrived.
    packets: [constants.limits.early_packets_max]Kept,
    /// How many entries of `packets` hold a packet, and how many octets of `octets` they use.
    count: u8,
    octets_len: u16,
    /// Kept packets opened over the connection's life. The simulator's check reads it, and nothing
    /// here acts on it.
    opened: u32,

    /// One kept packet.
    pub const Kept = struct {
        start: u16,
        len: u16,
        /// The instant it arrived. RFC 9000 §13.2.5: "endpoints SHOULD include buffering delays
        /// caused by unavailability of decryption keys" in the ACK Delay, so it is what the space
        /// records once the packet opens.
        arrived_ns: u64,
        /// The ECN codepoint of its datagram (RFC 9000 §13.4).
        ecn: Ecn,
    };

    /// No packet kept. The octets and the entries are left unwritten, since nothing reads past
    /// `count` and `octets_len`.
    pub fn init(early: *EarlyPackets) void {
        early.count = 0;
        early.octets_len = 0;
        early.opened = 0;
    }

    /// Keeps a copy of `packet`. False when it does not fit, and the caller then drops it.
    pub fn keep(early: *EarlyPackets, packet: []const u8, arrived_ns: u64, ecn: Ecn) bool {
        assert(packet.len > 0);
        assert(early.octets_len <= early.octets.len);
        if (early.count == early.packets.len) return false;
        if (packet.len > early.octets.len - early.octets_len) return false;
        const start = early.octets_len;
        @memcpy(early.octets[start..][0..packet.len], packet);
        early.packets[early.count] = .{ .start = start, .len = @intCast(packet.len), .arrived_ns = arrived_ns, .ecn = ecn };
        early.count += 1;
        early.octets_len += @intCast(packet.len);
        return true;
    }

    /// The octets of the kept packet at `index`, which `crypto.Suite.open` unprotects in place.
    pub fn octets_of(early: *EarlyPackets, index: usize) []u8 {
        assert(index < early.count);
        const kept = early.packets[index];
        assert(kept.start + kept.len <= early.octets_len);
        return early.octets[kept.start..][0..kept.len];
    }

    /// Forgets every kept packet.
    pub fn clear(early: *EarlyPackets) void {
        early.count = 0;
        early.octets_len = 0;
    }
};

/// Whether a packet the walk discarded is one this connection keeps: a server keeps a 1-RTT
/// packet that waits for the handshake to complete (RFC 9001 §5.7). A client keeps none: §5.7
/// lets a server store such packets, and a client cannot open the server's 1-RTT packets until
/// its own handshake completes.
pub fn may_keep(connection: *const Connection, why: receive_module.Discarded) bool {
    return connection.role == .server and why == .handshake_pending;
}

test {
    _ = @import("connection_early_test.zig");
}
