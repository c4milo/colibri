//! When each encryption level may be sealed and opened, and when colibri tells the suite to
//! forget a level's keys (RFC 9001 §4.9). colibri holds no key, so all of this is timing.
//!
//! **Why the suite's own answer is not enough.** `crypto.Suite.keys_available` is one boolean per
//! level and direction, and it cannot tell a level that was never installed from one colibri
//! already discarded. [Invariant 21](../../../docs/invariants.md) asks for the difference in so
//! many words — "the connection holds one state per level and direction: none, available,
//! discarded" — because the two mean opposite things: a level not yet installed will arrive, and
//! a discarded one never will. RFC 9001 §4.9.1 also says "endpoints MUST NOT send Initial packets
//! after this point", which is a rule about what colibri decided rather than about what the suite
//! still holds.
//!
//! **And §5.7 forbids reading a level whose keys are there.** "Endpoints in either role MUST NOT
//! decrypt 1-RTT packets from their peer prior to completing the handshake", and its own Note
//! says a provider may hand over the 1-RTT secrets before then. So the read side of the
//! application level asks the handshake as well as the state.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const connection_module = @import("connection.zig");

const Level = core.Level;
const Direction = crypto.suite.Direction;
const Suite = crypto.Suite;
const Connection = connection_module.Connection;

/// What colibri knows about one level in one direction. RFC 9001 §4.9 moves it one way only:
/// a discarded level is never installed again.
pub const State = enum {
    /// The provider has not produced this level's secrets yet (RFC 9001 §4.1.4).
    none,
    /// Installed and not discarded, so `seal` and `open` may be called at it.
    available,
    /// RFC 9001 §4.9: colibri told the suite to forget it. Nothing is sent or opened here again.
    discarded,
};

/// One state per level and direction, which is what invariant 21 names.
pub const Keys = struct {
    state: [core.levels_count][crypto.suite.directions_count]State,

    /// A connection begins knowing no level. The Initial keys are installed by the caller's
    /// suite from the Destination Connection ID (RFC 9001 §5.2), and `mark_installed` records it.
    pub fn init(keys: *Keys) void {
        keys.state = @splat(@splat(.none));
    }

    pub fn at(keys: *const Keys, level: Level, direction: Direction) State {
        return keys.state[@intFromEnum(level)][@intFromEnum(direction)];
    }

    /// Records that the suite now holds `level` in `direction`.
    pub fn mark_installed(keys: *Keys, level: Level, direction: Direction) void {
        // RFC 9001 §4.9: a discarded level never comes back, so installing over one is colibri's
        // defect. §4.1.4 gives each level's secrets once, so installing twice is one too.
        assert(keys.at(level, direction) == .none);
        keys.state[@intFromEnum(level)][@intFromEnum(direction)] = .available;
    }

    /// Records that `level` is gone in both directions (RFC 9001 §4.9).
    pub fn mark_discarded(keys: *Keys, level: Level) void {
        for (0..crypto.suite.directions_count) |index| {
            keys.state[@intFromEnum(level)][index] = .discarded;
        }
        assert(keys.at(level, .read) == .discarded);
        assert(keys.at(level, .write) == .discarded);
    }
};

/// Whether a packet may be sealed at `level`. RFC 9001 §4.9.1: "Endpoints MUST NOT send Initial
/// packets after this point", which is what a discarded level means on the write side.
pub fn can_seal(connection: *const Connection, level: Level) bool {
    return connection.keys.at(level, .write) == .available;
}

/// Whether a packet that arrived at `level` may be opened. RFC 9001 §5.7: "Endpoints in either
/// role MUST NOT decrypt 1-RTT packets from their peer prior to completing the handshake", so the
/// application level asks the handshake too and a packet arriving early is discarded, not opened.
pub fn can_open(connection: *const Connection, level: Level, handshake_complete: bool) bool {
    if (connection.keys.at(level, .read) != .available) return false;
    // §5.7's Note: a provider may hand over the 1-RTT secrets before the handshake completes, so
    // the keys being there is not permission to use them.
    if (level == .application and !handshake_complete) return false;
    return true;
}

/// The level new data goes out at. RFC 9001 §4.9: "new data MUST be sent at the highest currently
/// available encryption level." Only ACKs and CRYPTO retransmissions go out below it.
pub fn highest_sendable(connection: *const Connection) ?Level {
    var index = core.levels_count;
    // Bounded by the three levels RFC 9001 §4.1.4 names.
    while (index > 0) {
        index -= 1;
        const level: Level = @enumFromInt(index);
        if (can_seal(connection, level)) return level;
    }
    return null;
}

/// Records that the suite installed `level` in `direction`, which the caller did because its
/// provider produced that level's secrets (RFC 9001 §4.1.4, decision 48).
pub fn on_keys_installed(connection: *Connection, level: Level, direction: Direction) void {
    connection.keys.mark_installed(level, direction);
}

/// The first Handshake packet this endpoint sent. RFC 9001 §4.9.1: "a client MUST discard Initial
/// keys when it first sends a Handshake packet". A server's Initial keys go on §4.9.1's other
/// trigger, so this does nothing for it.
pub fn on_handshake_packet_sent(connection: *Connection, suite: Suite) void {
    if (connection.role != .client) return;
    discard(connection, suite, .initial);
}

/// The first Handshake packet this endpoint opened. RFC 9001 §4.9.1: "a server MUST discard
/// Initial keys when it first successfully processes a Handshake packet". "Successfully" is why
/// the receive path calls this after the packet opened, never on one that failed (§5.5).
pub fn on_handshake_packet_processed(connection: *Connection, suite: Suite) void {
    if (connection.role != .server) return;
    discard(connection, suite, .initial);
}

/// RFC 9001 §4.9.2: "An endpoint MUST discard its Handshake keys when the TLS handshake is
/// confirmed", which §4.1.2 reaches at different moments for the two roles.
pub fn on_handshake_confirmed(connection: *Connection, suite: Suite) void {
    discard(connection, suite, .handshake);
}

/// Tells the suite to forget a level and records it, once. RFC 9001 §4.9's triggers can each be
/// reached more than once — a client sends many Handshake packets — and discarding is not
/// repeated, because `crypto.Suite.discard_keys` is the caller's state to change.
fn discard(connection: *Connection, suite: Suite, level: Level) void {
    if (connection.keys.at(level, .write) == .discarded) return;
    suite.vtable.discard_keys(suite.context, level);
    connection.keys.mark_discarded(level);
}

comptime {
    // RFC 9001 §4.9 moves a level from none to available to discarded and never back, so the
    // three states are ordered and `highest_sendable` may walk the levels by their numbers.
    assert(@intFromEnum(Level.initial) < @intFromEnum(Level.handshake));
    assert(@intFromEnum(Level.handshake) < @intFromEnum(Level.application));
}

test {
    _ = @import("connection_keys_test.zig");
}
