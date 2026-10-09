//! The versions a server speaks (decision 117), and how a TCP connection in cleartext chooses
//! among them. Once design §8 step 21b builds the ALPN lists from it, `versions` is the one place a
//! program names a version. `server.zig` exports `Versions` alone.
const std = @import("std");
const testing = std.testing;
const event = @import("event.zig");

const Protocol = event.Protocol;

/// Which of h11, h2 and h3 the server speaks, each true by default (decision 117). A TCP
/// connection speaks h11 or h2, and h3 runs over QUIC alone (RFC 9114 §3.1). Over TLS the ALPN
/// list of the TLS configuration still chooses (design §8 step 21b), so `versions` governs a
/// connection in cleartext.
pub const Versions = struct {
    h11: bool = true,
    h2: bool = true,
    h3: bool = true,
};

/// How a TCP connection in cleartext chooses its version: at once when `versions` allows one of h11
/// and h2, and by its first octets when it allows both (RFC 9113 §3.3).
pub const Choice = union(enum) {
    speak: Protocol,
    read_preface,
};

/// The choice `versions` leaves a TCP connection in cleartext, or null when it allows neither h11
/// nor h2, which leaves a TCP connection no version to speak.
pub fn tcp_choice(versions: Versions) ?Choice {
    if (versions.h11 and versions.h2) return .read_preface;
    if (versions.h11) return .{ .speak = .h11 };
    if (versions.h2) return .{ .speak = .h2 };
    return null;
}

test "decision 117: both TCP versions are chosen by the preface, one alone is spoken at once" {
    try testing.expectEqual(Choice.read_preface, tcp_choice(.{}).?);
    try testing.expectEqual(Choice{ .speak = .h11 }, tcp_choice(.{ .h2 = false }).?);
    try testing.expectEqual(Choice{ .speak = .h2 }, tcp_choice(.{ .h11 = false }).?);
    // RFC 9114 §3.1: h3 alone leaves a TCP connection nothing to speak.
    try testing.expectEqual(null, tcp_choice(.{ .h11 = false, .h2 = false }));
}
