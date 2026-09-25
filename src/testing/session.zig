//! One connection of the test-only server, in whichever protocol it speaks: h2
//! (`h2/h2_session.zig`) or h11 (`h11/h11_session.zig`). `server.zig`, the socket around it, steps
//! either the same way: octets in, octets out, and whether the connection is done.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const h2_session = @import("h2/h2_session.zig");
const h11_session = @import("h11/h11_session.zig");

pub const Protocol = enum { h2, h11 };

/// What an endpoint offers through ALPN, most preferred first: both protocols in decision 88's
/// order, or h11 alone when the command line asks for it (RFC 7301 §3.1).
pub const alpn_both = [_][]const u8{ &tls.constants.alpn_h2, tls.constants.alpn_http_1_1 };
pub const alpn_h11 = [_][]const u8{tls.constants.alpn_http_1_1};

/// The protocol a finished handshake runs: h2 when ALPN selected "h2" (RFC 9113 §3.2), and h11
/// when it selected "http/1.1" or nothing (decision 88). h11's `attach_tls` refuses any other
/// selection.
pub fn protocol_of(selected: ?[]const u8) Protocol {
    const name = selected orelse return .h11;
    return if (std.mem.eql(u8, name, &tls.constants.alpn_h2)) .h2 else .h11;
}

/// What one step did, as both protocols' sessions report it.
pub const Step = h2_session.Step;

comptime {
    // The two sessions report a step with the same fields, so either converts to the other.
    assert(std.meta.fields(Step).len == std.meta.fields(h11_session.Step).len);
}

pub const Session = union(Protocol) {
    h2: h2_session.Session,
    h11: h11_session.Session,

    /// Makes a connection of `protocol` that has read nothing and written nothing.
    pub fn init(session: *Session, protocol: Protocol) void {
        switch (protocol) {
            .h2 => {
                session.* = .{ .h2 = undefined };
                session.h2.init();
            },
            .h11 => {
                session.* = .{ .h11 = undefined };
                session.h11.init();
            },
        }
        assert(std.meta.activeTag(session.*) == protocol);
    }

    /// Consumes what it can of `input` and writes what it can into `output`.
    pub fn step(session: *Session, input: []const u8, output: []u8) Step {
        return switch (session.*) {
            .h2 => |*h2| h2.step(input, output),
            .h11 => |*h11| blk: {
                const stepped = h11.step(input, output);
                break :blk .{ .consumed = stepped.consumed, .written = stepped.written, .done = stepped.done };
            },
        };
    }
};

test "decision 88: ALPN's h2 runs h2, and http/1.1 or no selection runs h11" {
    try std.testing.expectEqual(Protocol.h2, protocol_of(&tls.constants.alpn_h2));
    try std.testing.expectEqual(Protocol.h11, protocol_of(tls.constants.alpn_http_1_1));
    try std.testing.expectEqual(Protocol.h11, protocol_of(null));
}
