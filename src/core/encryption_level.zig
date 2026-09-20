//! The encryption levels of RFC 9001 §4.1.4, which more than one module speaks and no module
//! owns.
//!
//! `crypto.Suite` protects a packet at a level and `tls`'s QUIC mode moves handshake octets at
//! one, and design §3 makes `tls` and `crypto` siblings with no edge between them. So the type
//! the two share lives here, where both already look.
const std = @import("std");
const assert = std.debug.assert;

/// The encryption levels colibri uses. 0-RTT is not one: [decision 20](../../docs/decisions.md)
/// refuses it, and RFC 9000 §19.6 forbids a CRYPTO frame in a 0-RTT packet anyway.
pub const Level = enum(u2) {
    initial = 0,
    handshake = 1,
    /// 1-RTT, which the application's data and every key update use.
    application = 2,
};

/// How many there are, which is how many packet number spaces a connection has (RFC 9000 §12.3)
/// and how many CRYPTO streams it reassembles (§19.6).
pub const levels_count = @typeInfo(Level).@"enum".fields.len;

comptime {
    // RFC 9001 §4.1.4 names these three, and colibri's mapping to packet types depends on the
    // order: Table 1 pairs Initial with an Initial packet, Handshake with a Handshake packet and
    // 1-RTT with a short header.
    assert(levels_count == 3);
    assert(@intFromEnum(Level.initial) == 0);
    assert(@intFromEnum(Level.handshake) == 1);
    assert(@intFromEnum(Level.application) == 2);
}
