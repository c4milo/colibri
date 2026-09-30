//! Why colibri closed a server connection on its own (decision 110, design §8 step 20b), which
//! `Connection.close_reason` names: the deadline that passed, or the limit the peer passed. An
//! operator reads it to tell an attack from a limit set too tight. A connection that ended any
//! other way has no close reason: the peer closed it or broke the protocol, TLS failed, or the
//! caller ended it.
const deadline = @import("deadline.zig");

pub const CloseReason = union(enum) {
    /// The deadline that passed.
    deadline: deadline.Deadline,
    /// The limit the peer passed.
    limit: Limit,
};

/// A limit on how much of a feature a peer may use. RFC 9113 §10.5 asks an h2 endpoint to set
/// such limits, and to end a connection whose peer passes one with ENHANCE_YOUR_CALM.
pub const Limit = enum {
    /// h2: more CONTINUATION frames in one field block than `continuation_count_max`.
    continuation_frames,
    /// h11 or h2 over TLS: more records in a row that carried no data than
    /// `records_without_data_max`.
    records_without_data,
    /// h2: more streams refused with RST_STREAM in one period than `rst_stream_rate_max`.
    resets_sent,
    /// h2: more streams the peer opened and reset in one period than `peer_reset_rate_max`: Rapid
    /// Reset, CVE-2023-44487.
    peer_resets,
};
