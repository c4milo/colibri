//! The transport of RFC 8999, 9000, 9001 and 9002. Knows nothing about HTTP (decision 5,
//! invariant 26), which build/modules.zig enforces and tools/graph_check.zig proves.
//!
//! The root exports the names code outside the module uses, each under the namespace of the file
//! that declares it (decision 115 as amended). It exports no file but `constants` and
//! `error_code`, so a function only the module's own files call is not reachable from outside.
//! A caller that needs another name adds it here, and to the list in the test below.
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const crypto = @import("crypto");
pub const tls_provider = @import("tls_provider");
/// The log a connection writes qlog events into (decision 102), so a caller of `quic` names its
/// types without importing the module itself.
pub const qlog = @import("qlog");
/// The module's named limits and sizes (decision 35), and the error codes RFC 9000 §20.1
/// registers. These two files are exported whole.
pub const constants = @import("constants.zig");
pub const error_code = @import("error_code.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const packet = @import("packet/packet.zig");
    pub const frame = @import("frame/frame.zig");
    pub const frame_ack = @import("frame/frame_ack.zig");
    pub const space = @import("space/space.zig");
    pub const termination = @import("termination.zig");
    pub const flow = @import("flow.zig");
    pub const connection_id = @import("connection_id.zig");
    pub const path = @import("path.zig");
    pub const peer_address = @import("peer_address.zig");
    pub const stateless_reset = @import("stateless_reset.zig");
    pub const rtt = @import("rtt.zig");
    pub const recovery_sent = @import("recovery/recovery_sent.zig");
    pub const recovery_loss = @import("recovery/recovery_loss.zig");
    pub const recovery_congestion = @import("recovery/recovery_congestion.zig");
    pub const recovery_timer = @import("recovery/recovery_timer.zig");
    pub const recovery_pacing = @import("recovery/recovery_pacing.zig");
    pub const recovery = @import("recovery/recovery.zig");
    pub const recovery_ack = @import("recovery/recovery_ack.zig");
    pub const recovery_ecn = @import("recovery/recovery_ecn.zig");
    pub const stream = @import("stream/stream.zig");
    pub const connection = @import("connection/connection.zig");
    pub const connection_identity = @import("connection/connection_identity.zig");
    pub const connection_keys = @import("connection/connection_keys.zig");
    pub const connection_key_update = @import("connection/connection_key_update.zig");
    pub const connection_retry = @import("connection/connection_retry.zig");
    pub const connection_timer = @import("connection/connection_timer.zig");
    pub const connection_idle = @import("connection/connection_idle.zig");
    pub const connection_receive = @import("connection/connection_receive.zig");
    pub const connection_frames = @import("connection/connection_frames.zig");
    pub const connection_stream_frames = @import("connection/connection_stream/connection_stream_frames.zig");
    pub const connection_stream_send = @import("connection/connection_stream/connection_stream_send.zig");
    pub const connection_stream_recovery = @import("connection/connection_stream/connection_stream_recovery.zig");
    pub const connection_stream_read = @import("connection/connection_stream/connection_stream_read.zig");
    pub const connection_stream_acknowledged = @import("connection/connection_stream/connection_stream_acknowledged.zig");
    pub const connection_stream_credit = @import("connection/connection_stream/connection_stream_credit.zig");
    pub const connection_path_frames = @import("connection/connection_path_frames.zig");
    pub const connection_migration = @import("connection/connection_migration.zig");
    pub const packet_build = @import("connection/packet_build/packet_build.zig");
    pub const connection_send = @import("connection/connection_send.zig");
    pub const connection_version = @import("connection/connection_version.zig");
    pub const connection_close = @import("connection/connection_close.zig");
    pub const connection_handshake = @import("connection/connection_handshake.zig");
    pub const connection_flow = @import("connection/connection_flow.zig");
    pub const connection_id_frames = @import("connection/connection_id_frames.zig");
    pub const connection_recovery = @import("connection/connection_recovery.zig");
    pub const connection_datagram = @import("connection/connection_datagram.zig");
    pub const connection_qlog = @import("connection/connection_qlog.zig");
    pub const crypto_stream = @import("crypto_stream.zig");
    pub const transport_parameters = @import("transport_parameters.zig");
    pub const transport_parameters_read = @import("transport_parameters_read.zig");
};

/// One QUIC connection, in storage the caller owns.
pub const Connection = files.connection.Connection;
/// A peer's address as the caller names it (decision 72).
pub const PeerAddress = files.peer_address.PeerAddress;
/// A packet number space, and the loss recovery of a connection, which the simulator drives by
/// themselves. A program names neither.
pub const Space = files.space.Space;
pub const Recovery = files.recovery.Recovery;

/// A datagram the caller read is passed to `receive`, and `send` writes the next one the
/// connection owes (design §4.2).
pub const connection_datagram = struct {
    pub const Error = files.connection_datagram.Error;
    pub const Received = files.connection_datagram.Received;
    pub const Scratch = files.connection_datagram.Scratch;
    pub const connection_error_code = files.connection_datagram.connection_error_code;
    pub const receive = files.connection_datagram.receive;
};

pub const connection_send = struct {
    pub const DefaultScratch = files.connection_send.DefaultScratch;
    pub const Ecn = files.connection_send.Ecn;
    pub const Error = files.connection_send.Error;
    pub const Sent = files.connection_send.Sent;
    pub const send = files.connection_send.send;
};

/// The instant the connection next needs `on_instant`, and what that instant is for.
pub const connection_timer = struct {
    pub const next = files.connection_timer.next;
    pub const on_instant = files.connection_timer.on_instant;
};

pub const connection_idle = struct {
    pub const deadline_ns = files.connection_idle.deadline_ns;
    pub const keep_alive_owed = files.connection_idle.keep_alive_owed;
    pub const owe_keep_alive = files.connection_idle.owe_keep_alive;
    pub const probe_timeout_ns = files.connection_idle.probe_timeout_ns;
    pub const timeout_ns = files.connection_idle.timeout_ns;
};

pub const connection_close = struct {
    pub const owe = files.connection_close.owe;
    pub const owes = files.connection_close.owes;
    pub const transport = files.connection_close.transport;
};

/// What a caller does with a stream: open it, supply its octets, read what arrived, and end it.
pub const connection_stream_send = struct {
    pub const Error = files.connection_stream_send.Error;
    pub const open = files.connection_stream_send.open;
    pub const reset = files.connection_stream_send.reset;
    pub const set_priority = files.connection_stream_send.set_priority;
    pub const stop_sending = files.connection_stream_send.stop_sending;
    pub const supply = files.connection_stream_send.supply;
    pub const write = files.connection_stream_send.write;
    pub const write_endings = files.connection_stream_send.write_endings;
};

pub const connection_stream_read = struct {
    pub const Error = files.connection_stream_read.Error;
    pub const Read = files.connection_stream_read.Read;
    pub const consume = files.connection_stream_read.consume;
    pub const peek = files.connection_stream_read.peek;
    pub const read = files.connection_stream_read.read;
    pub const reset_code = files.connection_stream_read.reset_code;
};

pub const connection_stream_acknowledged = struct {
    pub const acknowledged_end = files.connection_stream_acknowledged.acknowledged_end;
    pub const resets_acknowledged = files.connection_stream_acknowledged.resets_acknowledged;
};

pub const connection_flow = struct {
    pub const credit_owed = files.connection_flow.credit_owed;
};

pub const connection_stream_credit = struct {
    pub const send_credit = files.connection_stream_credit.send_credit;
};

/// What an endpoint does beside a connection's datagrams: the versions it speaks, a Retry, a new
/// connection ID, a path challenge, a key update and the log.
pub const connection_version = struct {
    pub const chooser = files.connection_version.chooser;
    pub const speaks = files.connection_version.speaks;
    pub const supported_versions = files.connection_version.supported_versions;
};

pub const connection_retry = struct {
    pub const answer = files.connection_retry.answer;
    pub const verify_token = files.connection_retry.verify_token;
};

pub const connection_id_frames = struct {
    pub const issue = files.connection_id_frames.issue;
};

pub const connection_migration = struct {
    pub const ChallengeData = files.connection_migration.ChallengeData;
    pub const challenge = files.connection_migration.challenge;
};

pub const connection_key_update = struct {
    pub const initiate = files.connection_key_update.initiate;
};

pub const connection_qlog = struct {
    pub const init = files.connection_qlog.init;
};

/// What the simulator, the corpus and the test endpoints call to drive one part of a connection
/// by itself. A program calls none of these.
pub const connection = struct {
    pub const Role = files.connection.Role;
    pub const apply_peer_parameters = files.connection.apply_peer_parameters;
    pub const space_at = files.connection.space_at;
};

pub const connection_receive = struct {
    pub const Datagram = files.connection_receive.Datagram;
    pub const Discarded = files.connection_receive.Discarded;
    pub const Error = files.connection_receive.Error;
    pub const Walk = files.connection_receive.Walk;
    pub const next = files.connection_receive.next;
};

pub const connection_recovery = struct {
    pub const Error = files.connection_recovery.Error;
};

pub const connection_frames = struct {
    pub const member_of = files.connection_frames.member_of;
};

pub const connection_keys = struct {
    pub const on_keys_installed = files.connection_keys.on_keys_installed;
};

pub const connection_stream_frames = struct {
    pub const apply = files.connection_stream_frames.apply;
};

pub const connection_stream_recovery = struct {
    pub const on_packets_acknowledged = files.connection_stream_recovery.on_packets_acknowledged;
};

pub const recovery_ack = struct {
    pub const on_ack_received = files.recovery_ack.on_ack_received;
};

pub const recovery_sent = struct {
    pub const Record = files.recovery_sent.Record;
};

/// The wire formats a caller reads and writes itself: a packet's header before any connection
/// has it (RFC 9000 §5.2), a frame, and the transport parameters (§18).
pub const packet = struct {
    pub const header = struct {
        pub const Error = files.packet.header.Error;
        pub const Long = files.packet.header.Long;
        pub const LongType = files.packet.header.LongType;
        pub const Packet = files.packet.header.Packet;
        pub const Version = files.packet.header.Version;
        pub const read = files.packet.header.read;
        pub const unprotected_long = files.packet.header.unprotected_long;
        pub const unprotected_short = files.packet.header.unprotected_short;
    };
    pub const header_write = struct {
        pub const write_long = files.packet.header_write.write_long;
        pub const write_retry = files.packet.header_write.write_retry;
        pub const write_short = files.packet.header_write.write_short;
    };
    pub const invariant = struct {
        pub const Long = files.packet.invariant.Long;
        pub const connection_id_length_len = files.packet.invariant.connection_id_length_len;
        pub const first_octet_len = files.packet.invariant.first_octet_len;
        pub const form_of = files.packet.invariant.form_of;
        pub const read_long = files.packet.invariant.read_long;
        pub const read_short = files.packet.invariant.read_short;
        pub const read_supported_versions = files.packet.invariant.read_supported_versions;
        pub const version_len = files.packet.invariant.version_len;
        pub const write_version_negotiation = files.packet.invariant.write_version_negotiation;
    };
    pub const packet_number = struct {
        pub const Truncated = files.packet.packet_number.Truncated;
        pub const encode = files.packet.packet_number.encode;
    };
};

pub const frame = struct {
    pub const Ack = files.frame.Ack;
    pub const AckRanges = files.frame.AckRanges;
    pub const Crypto = files.frame.Crypto;
    pub const Directionality = files.frame.Directionality;
    pub const EcnCounts = files.frame.EcnCounts;
    pub const Frame = files.frame.Frame;
    pub const Stream = files.frame.Stream;
    pub const read = files.frame.read;
    pub const write = files.frame.write;
    pub const frame_ack = struct {
        pub const Range = files.frame.frame_ack.Range;
    };
    pub const frame_control = struct {
        pub const ConnectionClose = files.frame.frame_control.ConnectionClose;
        pub const NewConnectionId = files.frame.frame_control.NewConnectionId;
    };
};

pub const transport_parameters = struct {
    pub const ConnectionId = files.transport_parameters.ConnectionId;
    pub const Parameters = files.transport_parameters.Parameters;
    pub const Role = files.transport_parameters.Role;
    pub const ack_delay_exponent_max = files.transport_parameters.ack_delay_exponent_max;
    pub const active_connection_id_limit_min = files.transport_parameters.active_connection_id_limit_min;
    pub const max_ack_delay_ms_max = files.transport_parameters.max_ack_delay_ms_max;
    pub const max_udp_payload_size_min = files.transport_parameters.max_udp_payload_size_min;
    pub const stateless_reset_token_len = files.transport_parameters.stateless_reset_token_len;
    pub const write = files.transport_parameters.write;
};

pub const transport_parameters_read = struct {
    pub const read = files.transport_parameters_read.read;
};

/// A stream's ID, the provider a caller supplies its octets through (decision 57), and the pool
/// a connection holds its unread octets in (decision 61).
pub const stream = struct {
    pub const Directionality = files.stream.Directionality;
    pub const Initiator = files.stream.Initiator;
    pub const Stream = files.stream.Stream;
    pub const StreamId = files.stream.StreamId;
    pub const StreamProvider = files.stream.StreamProvider;
    pub const stream_incoming = struct {
        pub const DefaultPool = files.stream.stream_incoming.DefaultPool;
        pub const Pool = files.stream.stream_incoming.Pool;
        pub const Storage = files.stream.stream_incoming.Storage;
        pub const block_len = files.stream.stream_incoming.block_len;
    };
    pub const stream_provider = struct {
        pub const VTable = files.stream.stream_provider.VTable;
    };
    pub const stream_table = struct {
        pub const OpenError = files.stream.stream_table.OpenError;
    };
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",                           "wire",                   "crypto",
        "tls_provider",                   "qlog",                   "constants",
        "error_code",                     "Connection",             "PeerAddress",
        "Space",                          "Recovery",               "connection_datagram",
        "connection_send",                "connection_timer",       "connection_idle",
        "connection_close",               "connection_stream_send", "connection_stream_read",
        "connection_stream_acknowledged", "connection_flow",        "connection_stream_credit",
        "connection_version",             "connection_retry",       "connection_id_frames",
        "connection_migration",           "connection_key_update",  "connection_qlog",
        "connection",                     "connection_receive",     "connection_recovery",
        "connection_frames",              "connection_keys",        "connection_stream_frames",
        "connection_stream_recovery",     "recovery_ack",           "recovery_sent",
        "packet",                         "frame",                  "transport_parameters",
        "transport_parameters_read",      "stream",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{ "core", "wire", "crypto", "tls_provider", "qlog" });
}
