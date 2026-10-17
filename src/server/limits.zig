//! The bounds of a server's connections, named by what they bound (decision 117). `server.zig`
//! exports `Limits`.
const constants = @import("constants.zig");

/// The bounds a configuration holds (decision 117). A bound that applies to one version alone says
/// so.
pub const Limits = struct {
    /// The requests a connection holds at once, from 1 to h2's `concurrent_streams_max`. h2
    /// advertises it as SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 §6.5.2, decision 110). Through an
    /// endpoint it bounds an h3 connection's request streams too, up to `quic_requests_max`
    /// (decision 119).
    requests_max: u32 = constants.requests_max,
    /// The shortest DATA frame h2 sends when a window, not the content, decides its length
    /// (decision 110), up to h2's initial maximum frame size.
    data_frame_len_min: u32 = constants.data_frame_len_min,
    /// The requests a client may cancel in one second, at least 1: h2's RST_STREAM on a stream
    /// the client opened, and h3's RESET_STREAM or STOP_SENDING on a request stream. One more
    /// ends the connection, which `CloseReason` names `peer_resets` (decision 110 as amended).
    peer_resets_max: u32 = constants.peer_resets_max,
    /// The streams the server may reset in one second, at least 1, each for a stream the client
    /// broke. One more ends the connection, which `CloseReason` names `resets_sent` (decision 110
    /// as amended).
    resets_sent_max: u32 = constants.resets_sent_max,
};
