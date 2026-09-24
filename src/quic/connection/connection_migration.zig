//! RFC 9000 §9.3's answer to a peer whose address changed (decision 72). colibri refuses
//! migration (decision 21), but §9 still requires an endpoint to follow a change it did not ask
//! for, which is what NAT rebinding is.
//!
//! **The caller names the address and colibri decides.** colibri owns no socket
//! (non-negotiable 1), so each datagram arrives with the address the caller read it from. A
//! server moves its path to a new address when a datagram from it carries the highest-numbered
//! non-probing packet (§9.3). A client never moves: its server has one address (§9).
//!
//! **Two paths are held, and no more.** The active one, and the last validated one before it,
//! which §9.3.2 moves back to when a new address fails validation and §9.3.3 challenges when the
//! peer appears to have moved. A move from an unvalidated path forgets that path: it was never
//! shown to reach the peer.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const path_module = @import("../path.zig");
const PeerAddress = @import("../peer_address.zig").PeerAddress;
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;
const Path = path_module.Path;

/// What the connection remembers of the moves its peer made.
pub const State = struct {
    /// RFC 9000 §9.3.2: the last validated path other than the active one, which a failed
    /// validation moves back to, or null when there is none.
    previous: ?Path,
    /// Whether the active path came from a move and is not yet validated. Its validation is what
    /// §9.4 resets the congestion controller and the RTT estimator on, and its failure is what
    /// §9.3.2 moves back on.
    awaiting_validation: bool,
    /// Whether the last move changed the port and kept the host, which §9.4 lets an endpoint
    /// treat as NAT rebinding.
    port_only: bool,

    pub fn init(state: *State) void {
        state.* = .{ .previous = null, .awaiting_validation = false, .port_only = false };
    }
};

/// Where a datagram came from, measured against the paths the connection holds.
pub const Arrival = enum {
    /// The active path's address.
    active,
    /// The previous path's address, at a server.
    previous,
    /// An address no path holds, at a server.
    new,
    /// RFC 9000 §9: "If a client receives packets from an unknown server address, the client MUST
    /// discard these packets."
    unknown_server,
};

pub fn arrival(connection: *const Connection, from: *const PeerAddress) Arrival {
    if (from.eql(&connection.path.address)) return .active;
    // RFC 9000 §9: a server has one address, apart from a preferred address (§9.6), which
    // decision 21 has colibri's server never offer and colibri's client never use.
    if (connection.role == .client) return .unknown_server;
    if (connection.migration.previous) |*previous| {
        if (from.eql(&previous.address)) return .previous;
    }
    return .new;
}

/// Counts the datagram toward RFC 9000 §8's limit of the path it came from. One from an address
/// no path holds yet counts toward the path `move` makes for it. The previous path is always a
/// validated one, which §8's limit does not apply to, so nothing counts toward it.
pub fn on_datagram_received(connection: *Connection, arrived: Arrival, len: usize) void {
    switch (arrived) {
        .active => connection.path.on_datagram_received(len),
        .previous => assert(connection.migration.previous.?.validated),
        .new, .unknown_server => {},
    }
}

/// RFC 9000 §9.3: "An endpoint only changes the address to which it sends packets in response to
/// the highest-numbered non-probing packet." `moves` says whether the datagram carried one.
/// Returns whether the path moved, which is when the caller owes `challenge` its data.
pub fn after_datagram(connection: *Connection, from: PeerAddress, arrived: Arrival, len: usize, moves: bool) bool {
    assert(arrived != .unknown_server or connection.role == .client);
    if (!moves) return false;
    switch (arrived) {
        .active, .unknown_server => return false,
        .previous, .new => {},
    }
    move(connection, from, arrived, len);
    return true;
}

fn move(connection: *Connection, from: PeerAddress, arrived: Arrival, len: usize) void {
    const state = &connection.migration;
    const left = connection.path;
    state.port_only = from.same_host(&left.address);
    if (arrived == .previous) {
        // RFC 9000 §9.3: "An endpoint MAY skip validation of a peer address if that address has
        // been seen recently", and the previous path was validated.
        connection.path = state.previous.?;
    } else {
        // RFC 9000 §9.3.1: until the new address is validated, §8's limit applies to it.
        connection.path.init(.unvalidated);
        connection.path.address = from;
        connection.path.on_datagram_received(len);
    }
    // RFC 9000 §8.2.2: a PATH_CHALLENGE the datagram carried is answered on the path it came
    // from, which is now the active one.
    connection.path.response_owed = left.response_owed;
    // RFC 9000 §9.3.2: "an endpoint MUST revert to using the last validated peer address when
    // validation of a new peer address fails", so the path left is kept when it was validated.
    if (left.validated) {
        state.previous = left;
        state.previous.?.response_owed = null;
    } else if (arrived == .previous) {
        state.previous = null;
    }
    state.awaiting_validation = !connection.path.validated;
}

/// The data of the two PATH_CHALLENGE frames a move owes, which the caller draws because RFC 9000
/// §8.2.1 wants it unpredictable and invariant 5 forbids colibri a random number.
pub fn challenge(
    connection: *Connection,
    new_path: [constants.path_challenge_len]u8,
    previous_path: [constants.path_challenge_len]u8,
) void {
    // RFC 9000 §9.3: the endpoint "MUST initiate path validation (Section 8.2) to verify the
    // peer's ownership of the address if validation is not already underway."
    if (!connection.path.validated and connection.path.challenge == null) connection.path.owe_challenge(new_path);
    // RFC 9000 §9.3.3: "In response to an apparent migration, endpoints MUST validate the
    // previously active path using a PATH_CHALLENGE frame."
    if (connection.migration.previous) |*previous| previous.owe_challenge(previous_path);
}

/// A PATH_RESPONSE, which validates the path its challenge went out on, whichever path it arrived
/// on (RFC 9000 §8.2.3).
pub fn on_response(connection: *Connection, data: [constants.path_challenge_len]u8) void {
    if (connection.path.on_response(data)) {
        on_active_validated(connection);
        return;
    }
    if (connection.migration.previous) |*previous| _ = previous.on_response(data);
}

fn on_active_validated(connection: *Connection) void {
    const state = &connection.migration;
    if (!state.awaiting_validation) return;
    state.awaiting_validation = false;
    // RFC 9000 §9.4: "On confirming a peer's ownership of its new address, an endpoint MUST
    // immediately reset the congestion controller and round-trip time estimator for the new path
    // to initial values ... unless the only change in the peer's address is its port number."
    // colibri keeps both on a change of port alone, which §9.4 permits (decision 72).
    if (state.port_only) return;
    connection.recovery.on_path_changed();
}

/// The earlier of the two paths' §8.2.4 deadlines, or null when neither has a challenge out.
pub fn challenge_deadline_ns(connection: *const Connection) ?u64 {
    const active = connection.path.challenge_deadline_ns();
    const previous_path = connection.migration.previous orelse return active;
    const previous = previous_path.challenge_deadline_ns() orelse return active;
    return @min(active orelse previous, previous);
}

/// What `on_instant` did.
pub const Fired = struct {
    /// A challenge ran out on either path (RFC 9000 §8.2.4).
    abandoned: bool = false,
    /// The active path failed validation and the connection moved back (RFC 9000 §9.3.2).
    reverted: bool = false,
    /// The active path failed validation with no validated path to move back to, and the
    /// connection closed silently (RFC 9000 §9.3.2).
    closed: bool = false,
};

/// RFC 9000 §8.2.4 for both paths.
pub fn on_instant(connection: *Connection, now_ns: u64) Fired {
    var fired: Fired = .{};
    const active_abandoned = connection.path.on_instant(now_ns);
    if (connection.migration.previous) |*previous| {
        if (previous.on_instant(now_ns)) {
            fired.abandoned = true;
            // RFC 9000 §9.3.3: "If the path is no longer viable, the validation attempt will
            // time out and fail", and a path that failed is no longer one to move back to.
            connection.migration.previous = null;
        }
    }
    fired.abandoned = fired.abandoned or active_abandoned;
    // A connection that is no longer active sends nothing on any path, so it moves to none.
    const active = connection.termination.state == .active;
    if (active and active_abandoned and connection.migration.awaiting_validation) revert(connection, &fired);
    return fired;
}

/// RFC 9000 §9.3.2: "an endpoint MUST revert to using the last validated peer address when
/// validation of a new peer address fails." And "If an endpoint has no state about the last
/// validated peer address, it MUST close the connection silently by discarding all connection
/// state."
fn revert(connection: *Connection, fired: *Fired) void {
    const state = &connection.migration;
    state.awaiting_validation = false;
    const previous = state.previous orelse {
        connection.termination.on_path_failed();
        fired.closed = true;
        return;
    };
    connection.path = previous;
    state.previous = null;
    fired.reverted = true;
}

/// Whether the previous path has a PATH_CHALLENGE waiting to go out, which `connection_send`
/// sends in a datagram of its own.
pub fn owes_previous_probe(connection: *const Connection) bool {
    const previous = connection.migration.previous orelse return false;
    return previous.challenge_owed != null;
}

test {
    _ = @import("connection_migration_test.zig");
}
