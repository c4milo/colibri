//! Which end of the connection this endpoint is. RFC 9113 gives the two roles different stream
//! parities (§5.1.1), different prefaces (§3.4), different settings obligations (§6.5.2) and
//! different pseudo-header rules (§8.3), so most of h2 takes the role as a parameter.
const std = @import("std");

pub const Role = enum {
    client,
    server,

    /// The parity of the stream identifiers this role initiates: odd for a client, even for a
    /// server (RFC 9113 §5.1.1).
    pub fn initiates_odd(role: Role) bool {
        return role == .client;
    }

    /// The other end.
    pub fn peer(role: Role) Role {
        return if (role == .client) .server else .client;
    }
};

test "a client opens odd streams and a server even ones, and each is the other's peer" {
    try std.testing.expect(Role.client.initiates_odd());
    try std.testing.expect(!Role.server.initiates_odd());
    try std.testing.expectEqual(Role.server, Role.client.peer());
    try std.testing.expectEqual(Role.client, Role.server.peer());
}
