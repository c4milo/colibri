//! The connection IDs RFC 9000 §7.3 authenticates, which are the handshake's and not §5.1's set.
//!
//! §5.1's connection IDs are the ones NEW_CONNECTION_ID issues and RETIRE_CONNECTION_ID takes
//! back, and `connection_id.Local` and `Remote` hold those. The ones here are different: §7.3
//! fixes five values during the handshake, carries three of them in transport parameters, and
//! makes a mismatch a connection error. They are handshake values, so they live apart from the
//! set that changes over a connection's life.
//!
//! §7.3's Figure 7 names them. A client sends `Initial: DCID=S1, SCID=C1` and the server answers
//! `Initial: DCID=C1, SCID=S3`. The client chose S1, so the server echoes it back as
//! `original_destination_connection_id` and the client checks it; each side sends its own first
//! Source Connection ID as `initial_source_connection_id`. Figure 8 adds S2, a Retry's Source
//! Connection ID, which the client then addresses instead of S1.
//!
//! **colibri chooses none of them.** §5.1 requires a connection ID to be unpredictable and
//! invariant 5 forbids colibri from drawing a random number, so every value here arrives from the
//! caller or off the wire.
const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");

const ConnectionId = transport_parameters.ConnectionId;
const Role = crypto.suite.Role;

/// What the caller supplies about the handshake's connection IDs. A client knows two of these
/// before it sends anything; a server reads both of the peer's off the first Initial it accepted.
pub const Options = struct {
    /// The Source Connection ID this endpoint puts in its first Initial, which RFC 9000 §7.3
    /// sends as `initial_source_connection_id`. Figure 7's C1 for a client, S3 for a server.
    local_initial_source: []const u8,
    /// The Destination Connection ID of the client's first Initial, before any Retry (Figure 7's
    /// S1). A client chose it and a server read it; §7.3 has the server send it back as
    /// `original_destination_connection_id`.
    original_destination: []const u8,
    /// The Source Connection ID the peer put in its first Initial, when one has arrived. A server
    /// has it at once (Figure 7's C1) and a client does not hear the server's S3 until later.
    peer_initial_source: ?[]const u8 = null,
};

/// The five values of RFC 9000 §7.3, and nothing derived that could disagree with them.
pub const Identity = struct {
    local_initial_source: ConnectionId,
    original_destination: ConnectionId,
    /// Figure 8's S2, once a Retry carried one. Null while no Retry has happened, which §7.3
    /// makes the difference between `retry_source_connection_id` being required and forbidden.
    retry_source: ?ConnectionId,
    /// The peer's, which its own `initial_source_connection_id` must equal (§7.3).
    peer_initial_source: ?ConnectionId,

    pub fn init(identity: *Identity, options: Options) void {
        // RFC 9000 §17.2: in version 1 a connection ID is at most 20 octets, which `ConnectionId`
        // asserts, and a long header carries its length so a zero-length one is admitted.
        identity.local_initial_source = ConnectionId.of(options.local_initial_source);
        identity.original_destination = ConnectionId.of(options.original_destination);
        identity.retry_source = null;
        identity.peer_initial_source = if (options.peer_initial_source) |peer|
            ConnectionId.of(peer)
        else
            null;
    }

    /// What an outgoing header carries as its Destination Connection ID (RFC 9000 §7.3). It is
    /// derived rather than stored, because Figure 7 and Figure 8 are one rule read in order: a
    /// client addresses what it chose, then the Retry's Source Connection ID, then the server's.
    pub fn destination(identity: *const Identity) ConnectionId {
        if (identity.peer_initial_source) |peer| return peer;
        if (identity.retry_source) |retry| return retry;
        return identity.original_destination;
    }

    /// What an outgoing header carries as its Source Connection ID (RFC 9000 §17.2). It never
    /// changes during the handshake: §7.3 authenticates the first one each side sent.
    pub fn source(identity: *const Identity) ConnectionId {
        return identity.local_initial_source;
    }

    /// Takes the Source Connection ID off the peer's first Initial. RFC 9000 §7.3 makes it the
    /// value the peer's `initial_source_connection_id` must equal, and from here on it is what
    /// this endpoint addresses.
    pub fn on_peer_initial(identity: *Identity, scid: []const u8) void {
        // §7.3 authenticates the first one, so a later Initial carrying another is not taken.
        if (identity.peer_initial_source != null) return;
        identity.peer_initial_source = ConnectionId.of(scid);
    }

    /// Takes a Retry's Source Connection ID (RFC 9000 §17.2.5.2, Figure 8's S2). From here on a
    /// client addresses it instead of the value it chose, and §7.3 then requires the server to
    /// send it as `retry_source_connection_id`.
    /// The two roles reach it at different points and only the client's order is constrained:
    /// a client has heard nothing from the server yet, while a server read the peer's C1 off the
    /// Initial that made it send the Retry. So nothing here asserts about `peer_initial_source`,
    /// and `destination` answers C1 for the server whether or not a Retry happened.
    pub fn on_retry(identity: *Identity, scid: []const u8) void {
        // RFC 9000 §17.2.5.2: a client discards a second Retry, and a server sends one at most,
        // so this is written once. The caller refuses the repeat; this is colibri's half.
        assert(identity.retry_source == null);
        identity.retry_source = ConnectionId.of(scid);
    }

    /// How long the connection IDs this endpoint issues are (RFC 9000 §5.1). A short header
    /// carries no length, so a receiver must already know it, and §5.1 fixes it per endpoint.
    pub fn local_len(identity: *const Identity) usize {
        return identity.local_initial_source.len;
    }
};

/// Writes this endpoint's connection IDs into the parameters it will send (RFC 9000 §7.3), so
/// what goes out in the extension cannot disagree with what went out in the headers.
pub fn describe(identity: *const Identity, parameters: *transport_parameters.Parameters, role: Role) void {
    // §7.3: "Each endpoint includes the value of the Source Connection ID field from the first
    // Initial packet it sent in the initial_source_connection_id transport parameter".
    parameters.initial_source_connection_id = identity.local_initial_source;
    // §7.3: "A server includes the Destination Connection ID field from the first Initial packet
    // it received from the client in the original_destination_connection_id transport parameter".
    // A client sends neither this nor retry_source_connection_id, which §18.2 makes server-only.
    parameters.original_destination_connection_id =
        if (role == .server) identity.original_destination else null;
    // §7.3: "If it sends a Retry packet, a server also includes the Source Connection ID field
    // from the Retry packet in the retry_source_connection_id transport parameter."
    parameters.retry_source_connection_id =
        if (role == .server) identity.retry_source else null;
}

comptime {
    // A connection ID fits the octets `ConnectionId` reserves, which §17.2 bounds at 20.
    assert(constants.connection_id_len_max <= std.math.maxInt(u8));
}

test {
    _ = @import("connection_identity_test.zig");
}
