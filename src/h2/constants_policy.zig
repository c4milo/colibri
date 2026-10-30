//! The values colibri chose for h2 within what the RFCs allow, which size nothing.
//! Decision 137 groups them, and `constants.zig` exports this file as `policy`.
const std = @import("std");
const assert = std.debug.assert;
const hpack = @import("hpack");
const protocol = @import("constants_protocol.zig");

/// The SETTINGS_INITIAL_WINDOW_SIZE colibri advertises, and the window every stream starts with:
/// the RFC's initial value (§6.9.2).
pub const window_initial: u32 = protocol.initial_window_size_initial;

/// The SETTINGS_HEADER_TABLE_SIZE colibri advertises: the RFC's initial value, kept small
/// (design §6.1). The decoder's storage is `hpack.constants.limits.dynamic_table_capacity_max`.
pub const header_table_size_advertised: u32 = protocol.header_table_size_initial;

/// Most RST_STREAM frames colibri sends in one `rst_stream_rate_period_ns`, after which invalid
/// requests are a connection error of ENHANCE_YOUR_CALM (§10.5: track the use of these features
/// and set limits). It is what `Connection.init` sets in `resets_sent_max`.
pub const rst_stream_rate_max: u32 = 100;
pub const rst_stream_rate_period_ns: u64 = 1_000_000_000;

/// Most streams the peer opens and then resets in one `peer_reset_rate_period_ns`, after which the
/// connection ends with ENHANCE_YOUR_CALM (§10.5). Each such stream costs the application a
/// request's work for nothing, which CVE-2023-44487 did at line rate (decision 110). It is what
/// `Connection.init` sets in `peer_resets_max`.
pub const peer_reset_rate_max: u32 = 100;
pub const peer_reset_rate_period_ns: u64 = 1_000_000_000;

/// How long colibri waits for a SETTINGS acknowledgment before a connection error of
/// SETTINGS_TIMEOUT (§6.5.3 leaves "a reasonable amount of time" to the implementation).
pub const settings_timeout_ns: u64 = 10_000_000_000;

/// The receive window colibri lets a peer consume before it sends a WINDOW_UPDATE: half the
/// initial window, so the update is neither per frame nor too late (§6.9.1 advises against tiny
/// increments).
pub const window_update_threshold: u32 = window_initial / 2;

comptime {
    assert(window_update_threshold > 0 and window_update_threshold <= window_initial);
    assert(header_table_size_advertised <= hpack.constants.limits.dynamic_table_capacity_max);
    assert(rst_stream_rate_max > 0 and rst_stream_rate_period_ns > 0 and settings_timeout_ns > 0);
    assert(peer_reset_rate_max > 0 and peer_reset_rate_period_ns > 0);
}
