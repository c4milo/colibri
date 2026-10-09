//! A server connection in cleartext that may speak both h11 and h2 chooses by its first octets
//! (decision 117): the connection preface chooses h2, and any other octets h11. Split off
//! `connection.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `server.zig` does not export this file, so a program reaches none of it.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const event = @import("../event.zig");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");

const Connection = connection_module.Connection;
const Error = connection_module.Error;
const Protocol = event.Protocol;
const Received = event.Received;

const preface = h2.constants.client_preface;

/// Chooses the protocol from the octets `input` holds, and then reads it from them. Until they
/// choose, nothing is consumed: the caller passes them again with what it reads next.
pub fn choose(connection: *Connection, input: []u8, now_ns: u64) Error!Received {
    assert(connection.phase == .choosing and connection.config.tls == null);
    const chosen = chosen_by(input) orelse return .{ .consumed = 0, .event = null };
    internal.open_session(connection, chosen);
    return internal.read_protocol(connection, input, now_ns);
}

/// The protocol the first octets of a connection choose, or null while they are a prefix of the
/// preface.
fn chosen_by(octets: []const u8) ?Protocol {
    const compared = @min(octets.len, preface.len);
    // RFC 9113 §3.3: "servers can identify these connections by the presence of the connection
    // preface", so an octet that differs from it is h11's.
    if (!std.mem.eql(u8, octets[0..compared], preface[0..compared])) return .h11;
    return if (compared == preface.len) .h2 else null;
}

test "RFC 9113 §3.3: the whole preface chooses h2, a differing octet h11, and a prefix nothing" {
    const testing = std.testing;
    try testing.expectEqual(.h2, chosen_by(preface).?);
    try testing.expectEqual(.h2, chosen_by(preface ++ "\x00\x00\x00\x04").?);
    try testing.expectEqual(.h11, chosen_by("GET / HTTP/1.1\r\n").?);
    try testing.expectEqual(.h11, chosen_by("POST").?);
    // Every octet of the preface counts, the last one too.
    try testing.expectEqual(.h11, chosen_by(preface[0 .. preface.len - 1] ++ "X").?);
    try testing.expectEqual(null, chosen_by(preface[0 .. preface.len - 1]));
    try testing.expectEqual(null, chosen_by("PRI * HTTP/2.0\r\n"));
    try testing.expectEqual(null, chosen_by(""));
}
