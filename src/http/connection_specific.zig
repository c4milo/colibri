//! The connection-specific field names: the denylist both h2 and h3 enforce (decision 15).
//!
//! RFC 9110 §7.6.1 defines the Connection field and names fields an intermediary should remove
//! before forwarding, a list it says is not complete: Proxy-Connection, Keep-Alive, TE,
//! Transfer-Encoding and Upgrade. The rule that refuses them is h2's and h3's. RFC 9113 §8.2.2
//! makes a message carrying Connection, Proxy-Connection, Keep-Alive, Transfer-Encoding or Upgrade
//! malformed, and RFC 9114 §4.2 makes a message carrying a connection-specific field malformed.
//! Both state one exception in nearly the same words: TE may appear in a request when its value is
//! "trailers".
//!
//! `te_is_trailers` compares the exact octets. RFC 9110 §10.1.4 writes "trailers" in ABNF, whose
//! quoted strings compare case-insensitively by a rule in an RFC outside docs/rfcs/, so whether to
//! accept "Trailers" is a question for the owner and not settled here.
//!
//! This file classifies; it does not decide. `classify` names which connection-specific field a
//! name is, and `te_is_trailers` answers the exception's question. Whether a TE in a response, or a
//! TE with another value, is malformed, and what error that is, is the protocol module's.
const std = @import("std");
const field = @import("field.zig");

pub const ConnectionSpecific = enum {
    connection,
    proxy_connection,
    keep_alive,
    te,
    transfer_encoding,
    upgrade,
};

/// Every connection-specific field name, as RFC 9110 §7.6.1 spells it.
const names = [_]struct { []const u8, ConnectionSpecific }{
    .{ "Connection", .connection },
    .{ "Proxy-Connection", .proxy_connection },
    .{ "Keep-Alive", .keep_alive },
    .{ "TE", .te },
    .{ "Transfer-Encoding", .transfer_encoding },
    .{ "Upgrade", .upgrade },
};

/// The only TE value RFC 9113 §8.2.2 and RFC 9114 §4.2 permit.
pub const te_trailers = "trailers";

/// Which connection-specific field `name` is, compared case-insensitively (RFC 9110 §5.1), or null
/// when it is none of them.
pub fn classify(name: []const u8) ?ConnectionSpecific {
    for (names) |entry| {
        // RFC 9113 §8.2.2, RFC 9114 §4.2: connection-specific fields make a message malformed.
        if (field.names_equal(name, entry[0])) return entry[1];
    }
    return null;
}

/// True when a TE value is exactly "trailers", the one value RFC 9113 §8.2.2 and RFC 9114 §4.2
/// permit.
pub fn te_is_trailers(value: []const u8) bool {
    // RFC 9113 §8.2.2, RFC 9114 §4.2: TE "MUST NOT contain any value other than trailers".
    return std.mem.eql(u8, value, te_trailers);
}

const testing = std.testing;

test "the five fields RFC 9110 §7.6.1 lists and Connection itself classify, in any case" {
    try testing.expectEqual(ConnectionSpecific.connection, classify("connection").?);
    try testing.expectEqual(ConnectionSpecific.proxy_connection, classify("proxy-connection").?);
    try testing.expectEqual(ConnectionSpecific.keep_alive, classify("KEEP-ALIVE").?);
    try testing.expectEqual(ConnectionSpecific.te, classify("te").?);
    try testing.expectEqual(ConnectionSpecific.transfer_encoding, classify("Transfer-Encoding").?);
    try testing.expectEqual(ConnectionSpecific.upgrade, classify("upgrade").?);
}

test "an end-to-end field is not connection-specific" {
    const end_to_end = [_][]const u8{ "content-length", "trailer", "tea", "t", "", "connections" };
    for (end_to_end) |name| try testing.expectEqual(null, classify(name));
}

test "TE is trailers only when it says exactly that" {
    try testing.expect(te_is_trailers("trailers"));
    try testing.expect(!te_is_trailers("gzip"));
    try testing.expect(!te_is_trailers("trailers, gzip"));
    try testing.expect(!te_is_trailers(" trailers"));
    try testing.expect(!te_is_trailers(""));
}
