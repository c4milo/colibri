//! What a quic connection is built from, `Connection.Options` (decision 158 ruling 6). Split off
//! `connection.zig` for length.
const crypto = @import("crypto");
const transport_parameters = @import("../transport_parameters.zig");
const recovery_congestion = @import("../recovery/recovery_congestion.zig");
const recovery_resume = @import("../recovery/recovery_resume.zig");
const stream_incoming = @import("../stream/stream_incoming.zig");
const identity_module = @import("connection_identity.zig");
const connection_qlog = @import("connection_qlog.zig");
const PeerAddress = @import("../peer_address.zig").PeerAddress;

const Role = crypto.Role;
const Parameters = transport_parameters.Parameters;

/// What a connection is built from. Everything here is the caller's decision, including the
/// instant, which no file under `src/` may read. Each field has a default except
/// `local_parameters`, `now_ns` and `identity`, which only the caller knows (decision 158 ruling
/// 16).
pub const Options = struct {
    /// The end of the connection this side is. A server is the default, as in h11, h2 and h3
    /// (decision 158 ruling 16).
    role: Role = .server,
    /// The version the connection starts in (RFC 9368 §2): a client's choice, which its TLS session
    /// starts in too, or the version of the first flight a server accepted.
    version: crypto.suite.Version = .v1,
    /// The version a server switches a client to when the client lists it (RFC 9368 §2.3,
    /// decision 111), or null to keep every client in its original version. A client ignores it.
    switch_to: ?crypto.suite.Version = .v2,
    /// The parameters colibri will send (RFC 9000 §7.4). They fix what colibri grants the peer:
    /// its flow control windows, its stream limits and its idle timeout.
    local_parameters: Parameters,
    /// The instant the connection begins, from which the idle timeout runs (RFC 9000 §10.1).
    now_ns: u64,
    /// The connection IDs the handshake uses (RFC 9000 §7.3). colibri chooses none of them:
    /// §5.1 wants them unpredictable and invariant 5 forbids colibri a random number, so a
    /// client's are the caller's and a server's come off the first Initial it accepted.
    identity: identity_module.Options,
    /// RFC 9000 §21.4: one value the caller drew from its source, whose eight octets space out
    /// the 1-RTT packet numbers the connection skips to catch a peer that acknowledges what it
    /// never received (invariant 5), or null to skip none.
    packet_number_skips: ?u64 = null,
    /// The congestion controller (decisions 133, 136 and 143): BBRv3, the default, CUBIC, or
    /// RFC 9002's NewReno.
    congestion_controller: recovery_congestion.Controller = .bbr,
    /// Decision 136: one value the caller drew from its source, from which BBRv3 draws each of
    /// its bandwidth probe waits (draft-ietf-ccwg-bbr-06 §5.3.3.8.2). CUBIC and NewReno read none.
    bandwidth_probe_waits: u64 = 0,
    /// RFC 9959's saved set to start from (decision 149), which a program kept from an earlier
    /// connection to the same remote endpoint, or null for normal congestion control. A set past
    /// `resume_bounds.lifetime_ns`, or of another layout, is not used.
    resumed_from: ?recovery_resume.ResumeState = null,
    /// RFC 9959 §5's bounds on a resumed connection: max_jump and the Lifetime.
    resume_bounds: recovery_resume.ResumeBounds = .{},
    /// The pool the peer's stream octets wait in until the application reads them, which the
    /// caller places (decision 61). Its capacity caps every receive window. A connection given
    /// none reads no stream: it checks STREAM frames and keeps nothing.
    receive: ?stream_incoming.Storage = null,
    /// Decision 68: whether the caller reads each received datagram's ECN codepoint and passes it
    /// in `Datagram.ecn`. RFC 9000 §13.4.1: an endpoint that "does not have access to received
    /// ECN codepoints ... does not process or report ECN", so without it no ACK carries counts.
    ecn_reads: bool = false,
    /// Decision 68: whether the caller sets on each datagram the codepoint `Sent.ecn` names,
    /// which lets this endpoint mark ECT(0) and validate the path (§13.4.2).
    ecn_marks: bool = false,
    /// The peer's address as the caller names it (decision 72): the server a client sends to, or
    /// the client whose first Initial a server accepted. A caller that names no addresses leaves
    /// it empty and passes none with its datagrams, and the path never moves.
    peer_address: PeerAddress = .{},
    /// The log the connection writes qlog events into (decision 102), whose header the caller
    /// wrote with `Log.start` at or before `now_ns`. Null, the default, logs nothing.
    qlog: ?*connection_qlog.Log = null,
};
