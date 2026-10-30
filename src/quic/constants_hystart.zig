//! HyStart++'s constants (RFC 9406, decision 135), which `constants.zig` exports as `hystart`.
//! Each is RFC 9406 §4.3's recommended value. Its L is infinity, because colibri paces (RFC 9002
//! §7.7), so no constant limits the octets one ACK adds to the window.
const std = @import("std");
const assert = std.debug.assert;
const nanoseconds_per_millisecond = @import("constants.zig").nanoseconds_per_millisecond;

/// §4.3: MIN_RTT_THRESH, the smallest increase of a round's minimum round trip that ends slow
/// start.
pub const rtt_threshold_min_ns: u64 = 4_000_000;

/// §4.3: MAX_RTT_THRESH, the largest such increase.
pub const rtt_threshold_max_ns: u64 = 16_000_000;

/// §4.3: MIN_RTT_DIVISOR. Between the two bounds the threshold is the last round's minimum
/// round trip divided by it.
pub const rtt_divisor: u64 = 8;

/// §4.3: N_RTT_SAMPLE, the round trip samples a round takes before its minimum is compared.
pub const rtt_samples: u8 = 8;

/// §4.3: CSS_GROWTH_DIVISOR. In Conservative Slow Start (CSS) the window grows by the octets
/// acknowledged divided by it.
pub const css_growth_divisor: u64 = 4;

/// §4.3: CSS_ROUNDS, the most rounds CSS lasts before congestion avoidance.
pub const css_rounds: u8 = 5;

comptime {
    assert(rtt_threshold_min_ns == 4 * nanoseconds_per_millisecond);
    assert(rtt_threshold_max_ns == 16 * nanoseconds_per_millisecond);
    // §4.3: "The minimum value of CSS_GROWTH_DIVISOR MUST be at least 2."
    assert(css_growth_divisor >= 2);
    assert(rtt_samples > 0 and css_rounds > 0);
}
