//! One connection of the test-only server, in whichever protocol it speaks: h2
//! (`h2/h2_session.zig`) or h11 (`h11/h11_session.zig`). `server.zig`, the socket around it, steps
//! either the same way: octets in, octets out, and whether the connection is done.
const std = @import("std");
const assert = std.debug.assert;
const h2_session = @import("h2/h2_session.zig");
const h11_session = @import("h11/h11_session.zig");

pub const Protocol = enum { h2, h11 };

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
