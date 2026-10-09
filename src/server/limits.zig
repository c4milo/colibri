//! The bounds of a server's connections, named by what they bound (decision 117). `server.zig`
//! exports `Limits`.
const constants = @import("constants.zig");

/// The bounds a configuration holds (decision 117). A bound that applies to one version alone says
/// so.
pub const Limits = struct {
    /// The requests a connection holds at once, from 1 to h2's `concurrent_streams_max`. h2
    /// advertises it as SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 §6.5.2, decision 110). An h3
    /// connection holds `quic_requests_max`.
    requests_max: u32 = constants.requests_max,
    /// The shortest DATA frame h2 sends when a window, not the content, decides its length
    /// (decision 110), up to h2's initial maximum frame size.
    data_frame_len_min: u32 = constants.data_frame_len_min,
};
