//! The blocking socket the two one-connection TLS checks share: `tls-accept` and `tls-handshake`
//! (design §8 step 5). Each serves one connection and exits, so decision 46 does not govern it,
//! and a blocking read or write here waits for its peer and nothing else.
//!
//! `Input` holds what was read and not yet taken, since chapulin takes whole records and leaves a
//! partial one for the next call.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const chapulin_record = @import("chapulin_record.zig");

/// The reads a handshake may take on either side: a ClientHello, a second one after a
/// HelloRetryRequest, and the flight that answers it, each possibly split across reads.
pub const handshake_reads_max: usize = 16;

/// What the socket delivered, of which the first `len` octets are not yet taken.
pub const Input = struct {
    octets: [constants.tls_record_buffer_len]u8 = undefined,
    len: usize = 0,

    /// The octets not yet taken, which chapulin may unprotect in place.
    pub fn unread(input: *Input) []u8 {
        return input.octets[0..input.len];
    }

    /// Reads at least one octet after those not yet taken, which is what a peer that owes a record
    /// always sends.
    pub fn read_more(input: *Input, socket: std.c.fd_t) !void {
        const room = input.octets[input.len..];
        if (room.len == 0) return error.RecordTooLong;
        const read = std.c.recv(socket, room.ptr, room.len, 0);
        if (read <= 0) return error.PeerClosed;
        input.len += @intCast(read);
    }

    /// Reads until the input holds one whole record, which is what `decrypt_record` opens.
    pub fn read_record(input: *Input, socket: std.c.fd_t) ![]u8 {
        // Bounded: each pass reads at least one octet, and a record fits the buffer.
        for (0..input.octets.len) |_| {
            if (chapulin_record.whole_record_len(input.unread()) != null) break;
            try input.read_more(socket);
        }
        return input.unread();
    }

    /// Drops the `consumed` octets taken, keeping what follows at the front.
    pub fn take(input: *Input, consumed: usize) void {
        assert(consumed <= input.len);
        std.mem.copyForwards(u8, &input.octets, input.octets[consumed..input.len]);
        input.len -= consumed;
    }
};

/// Writes every octet, looping because a blocking send may still move fewer than it was asked.
pub fn write_all(socket: std.c.fd_t, octets: []const u8) !void {
    var sent: usize = 0;
    // Bounded by the slice, and every pass moves at least one octet or returns.
    while (sent < octets.len) {
        const wrote = std.c.send(socket, octets.ptr + sent, octets.len - sent, 0);
        if (wrote <= 0) return error.SendFailed;
        sent += @intCast(wrote);
    }
}
