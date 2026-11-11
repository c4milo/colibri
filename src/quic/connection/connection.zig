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
//! `tls_provider.QuicProvider` (decision 8); a connection holds neither, and takes them as parameters
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
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const space = @import("../space/space.zig");
const crypto_stream = @import("../crypto_stream.zig");
const stream_table = @import("../stream/stream_table.zig");
const stream_id = @import("../stream/stream_id.zig");
const stream_incoming = @import("../stream/stream_incoming.zig");
const flow = @import("../flow.zig");
const connection_id = @import("../connection_id.zig");
const path_module = @import("../path.zig");
const stateless_reset = @import("../stateless_reset.zig");
const termination_module = @import("../termination.zig");
const recovery_module = @import("../recovery/recovery.zig");
const recovery_ranges = @import("../recovery/recovery_ranges.zig");
const recovery_congestion = @import("../recovery/recovery_congestion.zig");
const recovery_resume = @import("../recovery/recovery_resume.zig");
const transport_parameters = @import("../transport_parameters.zig");
const frame_control = @import("../frame/frame_control.zig");
const frame_latest = @import("../frame/frame_latest.zig");
const identity_module = @import("connection_identity.zig");
const keys_module = @import("connection_keys.zig");
const key_update = @import("connection_key_update.zig");
const retry_module = @import("connection_retry.zig");
const handshake_module = @import("connection_handshake.zig");
const migration_module = @import("connection_migration.zig");
const connection_qlog = @import("connection_qlog.zig");
const connection_version = @import("connection_version.zig");
const connection_options = @import("connection_options.zig");
const connection_datagram = @import("connection_datagram.zig");
const connection_send = @import("connection_send.zig");
const connection_timer = @import("connection_timer.zig");
const connection_resume = @import("connection_resume.zig");
const connection_idle = @import("connection_idle.zig");
const connection_close = @import("connection_close.zig");
const connection_flow = @import("connection_flow.zig");
const connection_id_frames = @import("connection_id_frames.zig");
const stream_send = @import("connection_stream/connection_stream_send.zig");
const stream_read = @import("connection_stream/connection_stream_read.zig");
const stream_acknowledged = @import("connection_stream/connection_stream_acknowledged.zig");
const stream_credit = @import("connection_stream/connection_stream_credit.zig");
const PeerAddress = @import("../peer_address.zig").PeerAddress;

const Level = core.Level;
const Parameters = transport_parameters.Parameters;

/// Which endpoint colibri is. It is the suite's, because `install_initial_keys` takes the same
/// answer and RFC 9001 §5.2 derives a different key for each side from it.
pub const Role = crypto.Role;

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
    /// The MAX_DATA and DATA_BLOCKED frames most recently sent (RFC 9000 §13.3).
    max_data: frame_latest.Latest,
    data_blocked: frame_latest.Latest,
    /// The connection IDs colibri issued and the peer may use (RFC 9000 §5.1).
    local_ids: connection_id.Local,
    /// The connection IDs the peer issued and colibri may use (§5.1).
    remote_ids: connection_id.Remote,
    /// Path validation and the anti-amplification limit (RFC 9000 §8.2, §21.1.1.1).
    path: path_module.Path,
    /// The previous path and what RFC 9000 §9.3 remembers of the peer's moves (decision 72).
    migration: migration_module.State,
    /// The stateless reset tokens the peer gave, which §10.3 matches an unreadable packet against.
    tokens: stateless_reset.Tokens,
    /// Whether the connection is active, closing or draining (RFC 9000 §10.2).
    termination: termination_module.Termination,
    /// RFC 9002's loss recovery and congestion control.
    recovery: recovery_module.Recovery,
    /// The stream ranges of each application-level packet after its first (decision 131).
    stream_ranges: recovery_ranges.Ring,
    /// The connection IDs RFC 9000 §7.3 authenticates, which are the handshake's and not the
    /// §5.1 set `local_ids` and `remote_ids` hold.
    identity: identity_module.Identity,
    /// Which levels may be sealed and opened (RFC 9001 §4.9, invariant 21). It holds no key:
    /// decision 48 leaves every one with the caller's `crypto.Suite`.
    keys: keys_module.Keys,
    /// The original and the negotiated version (RFC 9368 §2, RFC 9369 §4.1).
    versions: connection_version.Versions,
    /// The parameters colibri sent (RFC 9000 §7.4).
    local_parameters: Parameters,
    /// The peer's, once the handshake carried them, and null until then.
    peer_parameters: ?Parameters,
    /// RFC 9001 §4.1.1's completed state, which is the provider's to report and the connection's
    /// to remember: nothing here holds a provider, so `connection_crypto` writes it. §5.7 forbids
    /// opening a 1-RTT packet before it, whatever keys the suite has.
    handshake_complete: bool,
    /// RFC 9001 §4.1.2: a server confirms the handshake when it completes and a client when it
    /// receives a HANDSHAKE_DONE frame. It is not what `handshake_complete` answers, and RFC 9002
    /// §6.2.1 and RFC 9001 §4.9.3 both turn on the difference.
    handshake_confirmed: bool,
    /// The HANDSHAKE_DONE frame a server owes its client (RFC 9000 §19.20, §13.3).
    handshake_done: handshake_module.HandshakeDone,
    /// The probe packets RFC 9002 §6.2.4 owes at each level, which a PTO sets
    /// (`connection_send.owe_probes`) and each ack-eliciting packet at that level counts off.
    probes_owed: [core.levels_count]u8,
    /// A PING the caller asked for to keep the connection from its idle timeout (RFC 9000
    /// §10.1.2, `connection_idle.owe_keep_alive`), which the next ack-eliciting packet at the
    /// application level answers.
    keep_alive_pending: bool,
    /// Where the CRYPTO octets the last PTO's probes carry begin, at each handshake level, which a
    /// second probe with nothing else to carry repeats (decision 64 as amended). Null until a PTO.
    crypto_probe_from: [core.levels_count]?u64,
    /// How many times this server has sent its Initial CRYPTO octets again before the PTO, which
    /// decision 65 limits to `early_crypto_resends_max` (RFC 9002 §6.2.3).
    early_crypto_resends: u8,
    /// The instant of the last of those resends, which decision 71 spaces the next one from.
    early_crypto_resent_at_ns: u64,
    /// Packets of ACK frames alone sent at the application level since the last ack-eliciting one
    /// there, which RFC 9000 §13.2.4's PING waits for (decision 73).
    ack_only_since_eliciting: u8,
    /// Whether the congestion window bounded the last datagram `send` built, which RFC 9002 §7.8
    /// asks before an acknowledgment may grow the window.
    window_limited: bool,
    /// Whether the pacer of RFC 9002 §7.7, and not the window, held the last datagram back, which
    /// `connection_timer` turns into the instant the caller calls `send` again.
    pacing_limited: bool,
    /// Whether the last `send` planned no packet while no limit held it: the sender ran out of
    /// data, which draft-ietf-ccwg-bbr-06 §4.1.2.4 marks as an application limit.
    ran_out_of_data: bool,
    /// The pool the peer's stream octets wait in, or null when the caller reads no stream
    /// (decision 61).
    receive_storage: ?stream_incoming.Storage,
    /// `Options.ecn_reads` and `Options.ecn_marks` (decision 68).
    ecn_reads: bool,
    ecn_marks: bool,
    /// The CONNECTION_CLOSE this endpoint owes its peer (RFC 9000 §10.2), or null while it owes
    /// none. §10.2.1 keeps "only enough information to generate a packet containing a
    /// CONNECTION_CLOSE frame", and this is that information. The Reason Phrase points at the
    /// caller's octets, which the caller keeps alive until the closing period ends.
    pending_close: ?frame_control.ConnectionClose,
    /// The alert the provider raised when the handshake failed, which RFC 9001 §4.8 turns into
    /// the CRYPTO_ERROR code the close carries. Null while none was raised.
    tls_alert: ?tls_provider.Alert,
    /// Whether the TLS provider failed (RFC 9001 §4.8). From then on the suite, and not
    /// colibri's own record, says which levels still seal (decision 84, `take_lost`).
    tls_failed: bool,
    /// RFC 9001 §6's key phase, which is packet numbers and instants and no key at all. The
    /// application level alone: §6.1's Note says no other level's keys are ever updated.
    key_phase: key_update.Phase,
    /// The Retry token this endpoint repeats in every Initial it sends (RFC 9000 §8.1.2), empty
    /// until a Retry carried one.
    retry_token: retry_module.Token,
    /// The caller's qlog log, and what the last events said (decision 102).
    qlog: connection_qlog.State,

    // What `init` takes (decision 158 ruling 6), and the calls a program makes, each in the file
    // that holds it (ruling 8). A name that two files share takes its concept.
    pub const Options = connection_options.Options;
    pub const IdentityOptions = identity_module.Options;
    // A datagram the caller read is passed to `receive`, and `send` writes the next one the
    // connection owes (design §4.2).
    pub const receive = connection_datagram.receive;
    pub const Received = connection_datagram.Received;
    pub const ReceiveScratch = connection_datagram.Scratch;
    pub const ReceiveError = connection_datagram.Error;
    pub const receive_error_code = connection_datagram.connection_error_code;
    pub const send = connection_send.send;
    pub const Sent = connection_send.Sent;
    pub const SendError = connection_send.Error;
    pub const SendScratch = connection_send.Scratch;
    pub const SendScratchOptions = connection_send.ScratchOptions;
    // The instant the connection next needs `on_instant`, and what that instant is for. It is
    // the same on each call until an input changes it (ruling 12).
    pub const deadline = connection_timer.next;
    pub const on_instant = connection_timer.on_instant;
    /// RFC 9959 §3.1: the set the connection observed, which a program saves (decision 149).
    pub const resume_state = connection_resume.observe;
    pub const idle_deadline_ns = connection_idle.deadline_ns;
    pub const idle_timeout_ns = connection_idle.timeout_ns;
    pub const probe_timeout_ns = connection_idle.probe_timeout_ns;
    pub const owe_keep_alive = connection_idle.owe_keep_alive;
    pub const keep_alive_owed = connection_idle.keep_alive_owed;
    pub const owe_close = connection_close.owe;
    pub const owes_close = connection_close.close_due;
    // What a caller does with a stream: open it, supply its octets, read what arrived, and end it.
    pub const open_stream = stream_send.open;
    pub const OpenStreamError = stream_table.OpenError;
    pub const supply = stream_send.supply;
    pub const reset_stream = stream_send.reset;
    pub const stop_sending = stream_send.stop_sending;
    pub const set_stream_priority = stream_send.set_priority;
    pub const write_stream_frame = stream_send.write;
    pub const write_stream_endings = stream_send.write_endings;
    pub const StreamSendError = stream_send.Error;
    pub const read = stream_read.read;
    pub const peek = stream_read.peek;
    pub const consume = stream_read.consume;
    pub const reset_code = stream_read.reset_code;
    pub const StreamRead = stream_read.Read;
    pub const StreamReadError = stream_read.Error;
    pub const acknowledged_end = stream_acknowledged.acknowledged_end;
    pub const resets_acknowledged = stream_acknowledged.resets_acknowledged;
    pub const credit_owed = connection_flow.credit_owed;
    /// The server's `observe`, which asks `data_credit_owed` first (design §8 step 29d.7).
    pub const count_credit_owed = connection_flow.count_credit_owed;
    /// The server's body meters, which wait on data credit alone (decision 130).
    pub const data_credit_owed = connection_flow.data_credit_owed;
    pub const send_credit = stream_credit.send_credit;
    // What an endpoint does beside a connection's datagrams: the version it chooses, a new
    // connection ID, a path challenge, a key update and the log.
    pub const version_chooser = connection_version.chooser;
    pub const issue_connection_ids = connection_id_frames.issue;
    pub const challenge_path = migration_module.challenge;
    pub const ChallengeData = migration_module.ChallengeData;
    pub const initiate_key_update = key_update.initiate;
    /// Starts the qlog of a connection that `init` already made (ruling 12).
    pub const attach_log = connection_qlog.init;

    /// A connection with nothing sent and nothing received.
    pub fn init(connection: *Connection, options: Options) void {
        connection.identity.init(options.identity);
        connection.keys.init();
        var parameters = options.local_parameters;
        // RFC 9000 §7.3: the connection IDs the extension carries are the ones the headers
        // carried, so the connection writes all three rather than trusting them to agree.
        identity_module.describe(&connection.identity, &parameters, options.role);
        // RFC 9368 §3: the connection states the version it chose and the versions it lists.
        parameters.version_information = connection_version.information_of(options.role, options.version);
        assert(parameters.valid());
        connection.role = options.role;
        connection.versions = .init(options.role, options.version, options.switch_to);
        connection.local_parameters = parameters;
        connection.peer_parameters = null;
        connection.handshake_complete = false;
        connection.handshake_confirmed = false;
        connection.handshake_done = .{};
        connection.probes_owed = @splat(0);
        connection.keep_alive_pending = false;
        connection.crypto_probe_from = @splat(null);
        connection.early_crypto_resends = 0;
        connection.early_crypto_resent_at_ns = 0;
        connection.ack_only_since_eliciting = 0;
        connection.window_limited = false;
        connection.pacing_limited = false;
        connection.ran_out_of_data = false;
        connection.max_data = .{};
        connection.data_blocked = .{};
        connection.key_phase.init();
        connection.retry_token.init();
        connection.pending_close = null;
        connection.tls_alert = null;
        connection.tls_failed = false;
        connection.receive_storage = options.receive;
        if (options.receive) |storage| storage.reset();
        connection.ecn_reads = options.ecn_reads;
        connection.ecn_marks = options.ecn_marks;
        init_spaces(connection, options.packet_number_skips);
        connection.crypto_streams.init();
        init_streams(connection, parameters);
        init_flow(connection, parameters);
        init_paths(connection, options);
        connection_qlog.init(connection, options.qlog, options.now_ns);
        assert(connection.peer_parameters == null);
    }

    /// One space per encryption level, paired by index (RFC 9000 §12.3, RFC 9001 Table 1).
    fn init_spaces(connection: *Connection, skips: ?u64) void {
        connection.spaces[@intFromEnum(Level.initial)].init(.initial);
        connection.spaces[@intFromEnum(Level.handshake)].init(.handshake);
        connection.spaces[@intFromEnum(Level.application)].init(.application);
        // RFC 9000 §21.4: only the 1-RTT space carries enough packets for a skip to matter.
        if (skips) |intervals| connection.spaces[@intFromEnum(Level.application)].skips = .init(intervals);
    }

    /// The stream table. What colibri may open starts at zero, because the peer has not said yet
    /// (RFC 9000 §18.2); what the peer may open is what colibri's own parameters grant.
    fn init_streams(connection: *Connection, parameters: Parameters) void {
        const none: [constants.protocol.stream_directionalities]u64 = @splat(0);
        var granted: [constants.protocol.stream_directionalities]u64 = undefined;
        granted[@intFromEnum(stream_id.Directionality.bidirectional)] = parameters.initial_max_streams_bidi;
        granted[@intFromEnum(stream_id.Directionality.unidirectional)] = parameters.initial_max_streams_uni;
        connection.streams.init(initiator_of(connection.role), none, granted);
        connection.stream_ranges.init();
    }

    /// Both levels of §4.1. The send side starts at zero for the same reason the stream limits do.
    fn init_flow(connection: *Connection, parameters: Parameters) void {
        connection.send_flow = flow.Sender.init(0);
        connection.receive_flow = flow.Receiver.init(parameters.initial_max_data, receive_window_max(connection, parameters.initial_max_data));
    }

    fn init_paths(connection: *Connection, options: Options) void {
        // RFC 9000 §5.1: an endpoint's connection IDs share one length, so whether colibri's are
        // zero-length is what its own first Source Connection ID already said.
        connection.local_ids.init(connection.identity.local_len() == 0);
        // RFC 9000 §5.1.1: "The initial connection ID issued by an endpoint is sent in the Source
        // Connection ID field of the long packet header during the handshake. The sequence number
        // of the initial connection ID is 0." So the identity's own is entry 0 of this set, and
        // §19.16 can ask which connection ID a packet was addressed to from the first packet on.
        const issued = connection.local_ids.issue(connection.identity.source().slice(), null);
        assert(issued != null and issued.? == 0);
        connection.remote_ids.init(false);
        // RFC 9000 §5.1.1: the peer's first Source Connection ID is its sequence number 0, which a
        // server read off the client's first Initial and a client learns from the server's.
        if (connection.identity.peer_initial_source) |peer| connection.remote_ids.hold_initial(peer.slice());
        // RFC 9000 §8.1: the anti-amplification limit is the server's, because a server is handed
        // an address it cannot yet believe. §21.1.1.1 exempts a client establishing a connection.
        connection.path.init(switch (options.role) {
            .client => .validated,
            .server => .unvalidated,
        });
        connection.path.address = options.peer_address;
        connection.migration.init();
        connection.tokens.init();
        // RFC 9000 §10.1: an idle timeout of 0 disables it, and §18.2 makes 0 the default.
        const idle = options.local_parameters.max_idle_timeout_ms;
        const idle_ns: ?u64 = if (idle == 0) null else idle * constants.nanoseconds_per_millisecond;
        connection.termination.init(idle_ns, options.now_ns);
        connection.recovery.init(constants.protocol.datagram_len_min);
        connection.recovery.congestion.select(.{
            .controller = options.congestion_controller,
            .bandwidth_probe_waits = options.bandwidth_probe_waits,
        }, options.now_ns);
        connection.recovery.careful_resume.init(options.resumed_from, options.resume_bounds, options.now_ns);
    }

    /// Whether a packet whose Destination Connection ID is `dcid` belongs to this connection.
    /// RFC 9000 §5.2 has the caller decide that before it hands the datagram over, and the
    /// connection holds the IDs it is decided by.
    pub fn addressed_by(connection: *const Connection, dcid: []const u8) bool {
        // RFC 9000 §5.2: "a non-zero-length Destination Connection ID corresponding to an
        // existing connection", which is one this endpoint issued (§5.1).
        if (connection.local_ids.sequence_number_of(dcid) != null) return true;
        // RFC 9000 §7.2: until a client hears from the server it addresses the value it chose,
        // so a server also answers to that one. A client never chose its own address.
        if (connection.role != .server) return false;
        // RFC 9000 §17.2.5.2: after a Retry, the client addresses the Retry's Source Connection
        // ID instead, until the server's first Initial arrives.
        if (connection.identity.retry_source) |retry| return std.mem.eql(u8, retry.slice(), dcid);
        return std.mem.eql(u8, connection.identity.original_destination.slice(), dcid);
    }
};

/// The packet number space a packet at `level` belongs to (RFC 9000 §12.3).
pub fn space_at(connection: *Connection, level: Level) *space.Space {
    return &connection.spaces[@intFromEnum(level)];
}

/// The CRYPTO stream a packet at `level` carries handshake octets on (RFC 9000 §19.6).
pub fn crypto_at(connection: *Connection, level: Level) *crypto_stream.CryptoStream {
    return connection.crypto_streams.at(level);
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
    // RFC 9000 §10.1: "the effective value at an endpoint is computed as the minimum of the two
    // advertised values (or the sole advertised value, if only one endpoint advertises a
    // non-zero value)".
    connection.termination.idle_timeout_ns = termination_module.Termination.advertised_idle_timeout_ns(
        connection.local_parameters.max_idle_timeout_ms,
        peer.max_idle_timeout_ms,
    );
    // RFC 9002 §6.2.1: the Probe Timeout adds the peer's max_ack_delay, which RFC 9000 §18.2
    // gives "in milliseconds".
    connection.recovery.rtt.peer_max_ack_delay_ns = peer.max_ack_delay_ms *| constants.nanoseconds_per_millisecond;
    assert(connection.peer_parameters != null);
}

/// RFC 9000 §18.2: the maximum delay this endpoint advertised before it acknowledges an
/// ack-eliciting packet, in the unit RFC 9002 counts in. §13.2.1 calls it "an explicit
/// contract", so it is this endpoint's own parameter and never the peer's.
pub fn max_ack_delay_ns(connection: *const Connection) u64 {
    return connection.local_parameters.max_ack_delay_ms *| constants.nanoseconds_per_millisecond;
}

// The receive windows the pool caps (decision 61), in `connection_flow.zig` for length.
pub const receive_window_max = connection_flow.receive_window_max;
pub const stream_receive_window_max = connection_flow.stream_receive_window_max;
pub const receive_credit_floor = connection_flow.receive_credit_floor;

/// RFC 9001 §4.1.2's confirmed state, which a server reaches when the handshake completes and
/// a client when a HANDSHAKE_DONE frame arrives.
pub fn confirm_handshake(connection: *Connection) void {
    connection.handshake_confirmed = true;
}

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
    assert(constants.protocol.packet_number_spaces == core.levels_count);
}

test "decision 115: the connection's public functions are the calls a program makes" {
    // What the module's own files call on a connection is a function of their file, and the root
    // exports only the ones the simulator and the corpus call. Decision 158 rulings 6 and 8 add
    // the options and each call a program makes.
    try core.public_names.expect(Connection, &.{
        "Options",              "IdentityOptions",      "receive",             "Received",
        "ReceiveScratch",       "ReceiveError",         "receive_error_code",  "send",
        "Sent",                 "SendError",            "SendScratch",         "SendScratchOptions",
        "deadline",             "on_instant",           "resume_state",        "idle_deadline_ns",
        "idle_timeout_ns",      "probe_timeout_ns",     "owe_keep_alive",      "keep_alive_owed",
        "owe_close",            "owes_close",           "open_stream",         "OpenStreamError",
        "supply",               "reset_stream",         "stop_sending",        "set_stream_priority",
        "write_stream_frame",   "write_stream_endings", "StreamSendError",     "read",
        "peek",                 "consume",              "reset_code",          "StreamRead",
        "StreamReadError",      "acknowledged_end",     "resets_acknowledged", "credit_owed",
        "count_credit_owed",    "data_credit_owed",     "send_credit",         "version_chooser",
        "issue_connection_ids", "challenge_path",       "ChallengeData",       "initiate_key_update",
        "attach_log",           "init",                 "addressed_by",
    });
}

test "decision 158 ruling 16: a connection's options name the server role by default" {
    const role_field = std.meta.fieldInfo(Connection.Options, .role);
    try std.testing.expectEqual(Role.server, role_field.defaultValue().?);
}

test {
    _ = @import("connection_test.zig");
    _ = @import("connection_crypto.zig");
    _ = @import("connection_identity.zig");
    _ = @import("connection_keys.zig");
    _ = @import("connection_key_update.zig");
    _ = @import("connection_retry.zig");
    _ = @import("connection_timer.zig");
    _ = @import("connection_receive.zig");
    _ = @import("connection_frames.zig");
    _ = @import("connection_stream/connection_stream_frames.zig");
    _ = @import("connection_path_frames.zig");
    _ = @import("packet_build/packet_build.zig");
    _ = @import("connection_send.zig");
    _ = @import("connection_datagram.zig");
    _ = @import("connection_stream/connection_stream_read.zig");
    _ = @import("connection_stream/connection_stream_close.zig");
    _ = @import("connection_qlog.zig");
}
