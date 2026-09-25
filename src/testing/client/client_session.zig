//! One connection of the test-only client, in whichever protocol it speaks: h2
//! (`h2/h2_client_session.zig`) or h11 (`h11/h11_client_session.zig`). `client_loop.zig`, the
//! socket around it, steps either the same way and reports its exchanges the same way.
const std = @import("std");
const assert = std.debug.assert;
const session = @import("../session.zig");
const client_exchange = @import("client_exchange.zig");
const h2_client_session = @import("../h2/h2_client_session.zig");
const h11_client_session = @import("../h11/h11_client_session.zig");

pub const Protocol = session.Protocol;
const Exchange = client_exchange.Exchange;
const Plan = client_exchange.Plan;

/// What one step did, as both protocols' sessions report it.
pub const Step = h2_client_session.Step;

comptime {
    // The two sessions report a step with the same fields, so either converts to the other.
    assert(std.meta.fields(Step).len == std.meta.fields(h11_client_session.Step).len);
}

pub const Session = union(Protocol) {
    h2: h2_client_session.Session,
    h11: h11_client_session.Session,

    /// Makes a client connection of `protocol` that has read nothing and written nothing. h11
    /// names no scheme in its requests: an origin-form target carries none (RFC 9112 §3.2.1).
    pub fn init(client: *Session, protocol: Protocol, scheme: []const u8, authority: []const u8, plans: []const Plan) void {
        switch (protocol) {
            .h2 => {
                client.* = .{ .h2 = undefined };
                client.h2.init(scheme, authority, plans);
            },
            .h11 => {
                client.* = .{ .h11 = undefined };
                client.h11.init(authority, plans);
            },
        }
        assert(std.meta.activeTag(client.*) == protocol);
    }

    /// Consumes what it can of `input` and writes what it can into `output`.
    pub fn step(client: *Session, input: []const u8, output: []u8) Step {
        return switch (client.*) {
            .h2 => |*h2| h2.step(input, output),
            .h11 => |*h11| blk: {
                const stepped = h11.step(input, output);
                break :blk .{ .consumed = stepped.consumed, .written = stepped.written, .done = stepped.done };
            },
        };
    }

    /// Whether every exchange ended the way a working peer ends one.
    pub fn succeeded(client: *const Session) bool {
        return switch (client.*) {
            inline else => |*protocol_session| protocol_session.succeeded(),
        };
    }

    /// Whether the protocol's connection failed.
    pub fn failed(client: *const Session) bool {
        return switch (client.*) {
            inline else => |*protocol_session| protocol_session.failed,
        };
    }

    /// The exchanges of the plan, as they stand.
    pub fn exchanges(client: *const Session) []const Exchange {
        return switch (client.*) {
            inline else => |*protocol_session| protocol_session.exchanges[0..protocol_session.exchanges_count],
        };
    }

    /// The peer closed the transport. Returns whether that is how the protocol may end a
    /// connection: in h11 a close ends a body that runs until it and leaves the exchanges to say
    /// how they ended (RFC 9112 §9.6), and in h2 a close before the client's GOAWAY is a failure.
    pub fn peer_closed(client: *Session) bool {
        switch (client.*) {
            .h2 => return false,
            .h11 => |*h11| {
                h11.transport_closed();
                return true;
            },
        }
    }
};
