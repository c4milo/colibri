//! Why colibri closed a server connection on its own (decision 110, design §8 steps 20b and
//! 20c), which `Ended.reason` carries: the deadline that passed, or the limit the peer passed. An
//! operator reads it to tell an attack from a limit set too tight. A connection that ended any
//! other way has no close reason. Either the peer closed it or broke the protocol, TLS failed, or
//! the caller ended it. The one TLS failure with a close reason is `key_updates`.
const deadline = @import("deadline.zig");

pub const CloseReason = union(enum) {
    /// The deadline that passed.
    timeout: deadline.Timeout,
    /// The limit the peer passed.
    limit: Limit,
};

/// A limit on how much of a feature a peer may use. RFC 9113 §10.5 asks an h2 endpoint to set
/// such limits, and to end a connection whose peer passes one with ENHANCE_YOUR_CALM. RFC 9114
/// §10.5 asks the same of h3, with H3_EXCESSIVE_LOAD. `key_updates` is the TLS provider's limit,
/// and its alert ends the connection (RFC 9846 §6).
pub const Limit = enum {
    /// h2: more CONTINUATION frames in one field block than `continuation_count_max`.
    continuation_frames,
    /// h11 or h2 over TLS: more records in a row that carried no data than
    /// `records_without_data_max`.
    records_without_data,
    /// h2: more streams refused with RST_STREAM in one second than `Limits.resets_sent_max`. h3:
    /// more request streams refused in one second, each because the client broke it, than the
    /// same limit.
    resets_sent,
    /// h2: more streams the peer opened and reset in one second than `Limits.peer_resets_max`:
    /// Rapid Reset, CVE-2023-44487. h3: more request streams the client opened and cancelled in
    /// one second than the same limit.
    peer_resets,
    /// h11 or h2 over TLS: more KeyUpdates in a row than the provider reads (chapulin: 16).
    key_updates,
};
