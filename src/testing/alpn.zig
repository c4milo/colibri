//! What design §9's h11 and h2 endpoints offer through ALPN, and the protocol a finished handshake
//! runs (decision 88). The server's connections choose through colibri's `server`, which applies
//! the same rule; the client's through `client/client_session.zig`.
const std = @import("std");
const tls_provider = @import("tls_provider");

pub const Protocol = enum { h2, h11 };

/// What an endpoint offers through ALPN, most preferred first: both protocols in decision 88's
/// order, or h11 alone when the command line asks for it (RFC 7301 §3.1).
pub const alpn_both = [_][]const u8{ &tls_provider.constants.alpn_h2, tls_provider.constants.alpn_http_1_1 };
pub const alpn_h11 = [_][]const u8{tls_provider.constants.alpn_http_1_1};

/// The protocol a finished handshake runs: h2 when ALPN selected "h2" (RFC 9113 §3.2), and h11
/// when it selected "http/1.1" or nothing (decision 88). h11's `attach_tls` refuses any other
/// selection.
pub fn protocol_of(selected: ?[]const u8) Protocol {
    const name = selected orelse return .h11;
    return if (std.mem.eql(u8, name, &tls_provider.constants.alpn_h2)) .h2 else .h11;
}

test "decision 88: ALPN's h2 runs h2, and http/1.1 or no selection runs h11" {
    try std.testing.expectEqual(Protocol.h2, protocol_of(&tls_provider.constants.alpn_h2));
    try std.testing.expectEqual(Protocol.h11, protocol_of(tls_provider.constants.alpn_http_1_1));
    try std.testing.expectEqual(Protocol.h11, protocol_of(null));
}
