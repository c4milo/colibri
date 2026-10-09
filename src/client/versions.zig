//! The versions a client speaks (decision 117), and the one a TCP connection in cleartext speaks.
//! Once design §8 step 21c builds the ALPN lists from it, `versions` is the one place a program
//! names a version. `client.zig` exports `Versions` alone.
const std = @import("std");
const testing = std.testing;
const event = @import("event.zig");

const Protocol = event.Protocol;

/// Which of h11, h2 and h3 the client speaks, each true by default (decision 117). A TCP
/// connection speaks h11 or h2, and h3 runs over QUIC alone (RFC 9114 §3.1). Over TLS the ALPN
/// list of the TLS configuration still chooses (design §8 step 21c), so `versions` governs a
/// connection in cleartext.
pub const Versions = struct {
    h11: bool = true,
    h2: bool = true,
    h3: bool = true,
};

/// The version a TCP connection in cleartext speaks: h11 when `versions` allows it, and otherwise h2
/// with prior knowledge (RFC 9113 §3.3). Null when it allows neither, which leaves a TCP connection
/// no version to speak.
pub fn cleartext(versions: Versions) ?Protocol {
    if (versions.h11) return .h11;
    if (versions.h2) return .h2;
    return null;
}

test "decision 117: a client in cleartext speaks h11 when allowed, and h2 with prior knowledge when not" {
    try testing.expectEqual(.h11, cleartext(.{}).?);
    try testing.expectEqual(.h11, cleartext(.{ .h2 = false }).?);
    try testing.expectEqual(.h2, cleartext(.{ .h11 = false }).?);
    // RFC 9114 §3.1: h3 alone leaves a TCP connection nothing to speak.
    try testing.expectEqual(null, cleartext(.{ .h11 = false, .h2 = false }));
}
