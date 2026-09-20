//! One QUIC connection: the state RFC 9000 and RFC 9002 give an endpoint, in one struct the
//! caller owns.
//!
//! Steps 9a to 9d built the pieces and this is what joins them. Every field below is a module
//! that was already tested on its own; what is new here is that they belong to one connection
//! and agree about it — three packet number spaces paired with three encryption levels, the
//! CRYPTO stream of each, the streams and both levels of flow control, the connection IDs each
//! side holds, the path, how the connection ends, and RFC 9002's recovery.
//!
//! **colibri holds no key and no socket here either.** The keys are the caller's `crypto.Suite`
//! ([decision 48](../../../docs/decisions.md)) and the handshake is the caller's
//! `tls.QuicProvider` (decision 8); a connection holds neither, and takes them as parameters
//! where it needs them. It reads no clock: every function that needs the instant takes it
//! (non-negotiable 3).
//!
//! **What a peer says it will accept arrives late.** A connection starts with colibri's own
//! transport parameters and learns the peer's during the handshake (RFC 9000 §7.4), so the
//! limits colibri may spend against start at zero and `apply_peer_parameters` raises them. That
//! is not a special case: §18.2 says of the stream limits that "if this parameter is absent or
//! zero, the peer cannot open streams until a MAX_STREAMS frame is sent", which is the same
//! state a connection begins in.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const space = @import("../space/space.zig");
const crypto_stream = @import("../crypto_stream.zig");
const stream_table = @import("../stream/stream_table.zig");
const stream_id = @import("../stream/stream_id.zig");
const flow = @import("../flow.zig");
const connection_id = @import("../connection_id.zig");
const path_module = @import("../path.zig");
const stateless_reset = @import("../stateless_reset.zig");
const termination_module = @import("../termination.zig");
const recovery_module = @import("../recovery/recovery.zig");
const transport_parameters = @import("../transport_parameters.zig");
const identity_module = @import("connection_identity.zig");
const keys_module = @import("connection_keys.zig");

const Level = core.Level;
const Parameters = transport_parameters.Parameters;

/// Which endpoint colibri is. It is the suite's, because `install_initial_keys` takes the same
/// answer and RFC 9001 §5.2 derives a different key for each side from it.
pub const Role = crypto.suite.Role;

/// What a connection is built from. Everything here is the caller's decision, including the
/// instant, which no file under `src/` may read.
pub const Options = struct {
    role: Role,
    /// The parameters colibri will send (RFC 9000 §7.4). They fix what colibri grants the peer:
    /// its flow control windows, its stream limits and its idle timeout.
    local_parameters: Parameters,
    /// The instant the connection begins, from which the idle timeout runs (RFC 9000 §10.1).
    now_ns: u64,
    /// The connection IDs the handshake uses (RFC 9000 §7.3). colibri chooses none of them:
    /// §5.1 wants them unpredictable and invariant 5 forbids colibri a random number, so a
    /// client's are the caller's and a server's come off the first Initial it accepted.
    identity: identity_module.Options,
};

pub const Connection = struct {
    /// Which endpoint colibri is (RFC 9000 §1.1).
    role: Role,
    /// The three packet number spaces of RFC 9000 §12.3, indexed by encryption level.
    spaces: [core.levels_count]space.Space,
    /// The CRYPTO stream of each level (RFC 9000 §19.6).
    crypto_streams: crypto_stream.Levels,
    /// The streams of this connection (RFC 9000 §2.1, decision 14).
    streams: stream_table.Streams,
    /// The connection-level data colibri may send, which the peer's parameters and its
    /// MAX_DATA frames raise (RFC 9000 §4.1).
    send_flow: flow.Sender,
    /// The connection-level data colibri will accept, which its own parameters fix (§4.1).
    receive_flow: flow.Receiver,
    /// The connection IDs colibri issued and the peer may use (RFC 9000 §5.1).
    local_ids: connection_id.Local,
    /// The connection IDs the peer issued and colibri may use (§5.1).
    remote_ids: connection_id.Remote,
    /// Path validation and the anti-amplification limit (RFC 9000 §8.2, §21.1.1.1).
    path: path_module.Path,
    /// The stateless reset tokens the peer gave, which §10.3 matches an unreadable packet against.
    tokens: stateless_reset.Tokens,
    /// Whether the connection is active, closing or draining (RFC 9000 §10.2).
    termination: termination_module.Termination,
    /// RFC 9002's loss recovery and congestion control.
    recovery: recovery_module.Recovery,
    /// The connection IDs RFC 9000 §7.3 authenticates, which are the handshake's and not the
    /// §5.1 set `local_ids` and `remote_ids` hold.
    identity: identity_module.Identity,
    /// Which levels may be sealed and opened (RFC 9001 §4.9, invariant 21). It holds no key:
    /// decision 48 leaves every one with the caller's `crypto.Suite`.
    keys: keys_module.Keys,
    /// The parameters colibri sent (RFC 9000 §7.4).
    local_parameters: Parameters,
    /// The peer's, once the handshake carried them, and null until then.
    peer_parameters: ?Parameters,
    /// RFC 9001 §4.1.2: a server confirms the handshake when it completes and a client when it
    /// receives a HANDSHAKE_DONE frame. It is not what `handshake_complete` answers, and RFC 9002
    /// §6.2.1 and RFC 9001 §4.9.3 both turn on the difference.
    handshake_confirmed: bool,

    /// A connection with nothing sent and nothing received.
    pub fn init(connection: *Connection, options: Options) void {
        connection.identity.init(options.identity);
        connection.keys.init();
        var parameters = options.local_parameters;
        // RFC 9000 §7.3: the connection IDs the extension carries are the ones the headers
        // carried, so the connection writes all three rather than trusting them to agree.
        identity_module.describe(&connection.identity, &parameters, options.role);
        assert(parameters.valid());
        connection.role = options.role;
        connection.local_parameters = parameters;
        connection.peer_parameters = null;
        connection.handshake_confirmed = false;
        init_spaces(connection);
        connection.crypto_streams.init();
        init_streams(connection, parameters);
        init_flow(connection, parameters);
        init_paths(connection, options);
        assert(connection.peer_parameters == null);
    }

    /// One space per encryption level, paired by index (RFC 9000 §12.3, RFC 9001 Table 1).
    fn init_spaces(connection: *Connection) void {
        connection.spaces[@intFromEnum(Level.initial)].init(.initial);
        connection.spaces[@intFromEnum(Level.handshake)].init(.handshake);
        connection.spaces[@intFromEnum(Level.application)].init(.application);
    }

    /// The stream table. What colibri may open starts at zero, because the peer has not said yet
    /// (RFC 9000 §18.2); what the peer may open is what colibri's own parameters grant.
    fn init_streams(connection: *Connection, parameters: Parameters) void {
        const none: [constants.stream_directionalities]u64 = @splat(0);
        var granted: [constants.stream_directionalities]u64 = undefined;
        granted[@intFromEnum(stream_id.Directionality.bidirectional)] = parameters.initial_max_streams_bidi;
        granted[@intFromEnum(stream_id.Directionality.unidirectional)] = parameters.initial_max_streams_uni;
        connection.streams.init(initiator_of(connection.role), none, granted);
    }

    /// Both levels of §4.1. The send side starts at zero for the same reason the stream limits do.
    fn init_flow(connection: *Connection, parameters: Parameters) void {
        connection.send_flow = flow.Sender.init(0);
        connection.receive_flow = flow.Receiver.init(parameters.initial_max_data, parameters.initial_max_data);
    }

    fn init_paths(connection: *Connection, options: Options) void {
        // RFC 9000 §5.1: an endpoint's connection IDs share one length, so whether colibri's are
        // zero-length is what its own first Source Connection ID already said.
        connection.local_ids.init(connection.identity.local_len() == 0);
        connection.remote_ids.init(false);
        // RFC 9000 §8.1: the anti-amplification limit is the server's, because a server is handed
        // an address it cannot yet believe. §21.1.1.1 exempts a client establishing a connection.
        connection.path.init(switch (options.role) {
            .client => .validated,
            .server => .unvalidated,
        });
        connection.tokens.init();
        // RFC 9000 §10.1: an idle timeout of 0 disables it, and §18.2 makes 0 the default.
        const idle = options.local_parameters.max_idle_timeout_ms;
        const idle_ns: ?u64 = if (idle == 0) null else idle * constants.nanoseconds_per_millisecond;
        connection.termination.init(idle_ns, options.now_ns);
        connection.recovery.init(constants.datagram_len_min);
    }

    /// Takes the peer's parameters once the handshake has carried them (RFC 9000 §7.4), which is
    /// what raises every limit colibri may spend against.
    pub fn apply_peer_parameters(connection: *Connection, peer: Parameters) void {
        assert(peer.valid());
        // RFC 9000 §7.4: a peer sends its parameters once, so this runs once.
        assert(connection.peer_parameters == null);
        connection.peer_parameters = peer;
        // RFC 9000 §18.2: initial_max_data is "the initial value for the maximum amount of data
        // that can be sent on the connection".
        _ = connection.send_flow.raise(peer.initial_max_data);
        // §18.2: each stream limit is "equivalent to sending a MAX_STREAMS of the corresponding
        // type with the same value", so raising is the same operation a MAX_STREAMS performs.
        _ = connection.streams.raise_local_limit(.bidirectional, peer.initial_max_streams_bidi);
        _ = connection.streams.raise_local_limit(.unidirectional, peer.initial_max_streams_uni);
        assert(connection.peer_parameters != null);
    }

    /// The packet number space a packet at `level` belongs to (RFC 9000 §12.3).
    pub fn space_at(connection: *Connection, level: Level) *space.Space {
        return &connection.spaces[@intFromEnum(level)];
    }

    /// The CRYPTO stream a packet at `level` carries handshake octets on (RFC 9000 §19.6).
    pub fn crypto_at(connection: *Connection, level: Level) *crypto_stream.CryptoStream {
        return connection.crypto_streams.at(level);
    }

    /// RFC 9001 §4.1.2's confirmed state, which a server reaches when the handshake completes and
    /// a client when a HANDSHAKE_DONE frame arrives.
    pub fn confirm_handshake(connection: *Connection) void {
        connection.handshake_confirmed = true;
    }
};

/// The connection's role as the stream table names it. RFC 9000 §2.1 calls the endpoint that
/// opened a stream its initiator, which is the same two values under a name about streams.
fn initiator_of(role: Role) stream_id.Initiator {
    return switch (role) {
        .client => .client,
        .server => .server,
    };
}

comptime {
    // One space per encryption level, which is what lets `space_at` index by level.
    assert(constants.packet_number_spaces == core.levels_count);
}

test {
    _ = @import("connection_test.zig");
    _ = @import("connection_crypto.zig");
    _ = @import("connection_identity.zig");
    _ = @import("connection_keys.zig");
}
