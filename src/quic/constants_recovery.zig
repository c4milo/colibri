//! The parameters of RFC 9002's loss detection, congestion control and pacing, as it
//! recommends them, with CUBIC's (RFC 9438) and HyStart++'s (RFC 9406).
//! Decision 137 groups them, and `constants.zig` exports this file as `recovery`.
const constants = @import("constants.zig");

/// The round trip estimator and loss detection of RFC 9002, whose Appendix A.2 names each one.
///
/// `kInitialRtt`: the estimate before any sample, which §6.2.2 recommends at 333 milliseconds.
/// The variation starts at half of it (§5.3).
pub const rtt_initial_ns: u64 = 333 * constants.nanoseconds_per_millisecond;
pub const rtt_initial_variation_divisor: u64 = 2;

/// The weights of RFC 9002 §5.3's moving averages, as divisors: the smoothed estimate keeps
/// seven eighths of itself and the variation three quarters.
pub const rtt_smoothed_weight: u64 = 8;
pub const rtt_variation_weight: u64 = 4;

/// RFC 9002 §6.2.1: the Probe Timeout carries four times the variation.
pub const rtt_variation_factor: u64 = 4;

/// `kGranularity`: the timer granularity, which §6.1.2 recommends at 1 millisecond. A timeout
/// is never shorter, so a timer cannot expire the instant it is armed.
pub const rtt_granularity_ns: u64 = constants.nanoseconds_per_millisecond;

/// `kTimeThreshold`: how far past an estimate a packet is declared lost by time, which §6.1.2
/// recommends at nine eighths.
pub const loss_time_threshold_numerator: u64 = 9;
pub const loss_time_threshold_denominator: u64 = 8;

/// `kPacketThreshold`: how many packets may arrive after one before it is declared lost, which
/// §6.1.1 recommends at 3.
pub const loss_packet_threshold: u64 = 3;

/// The congestion window of RFC 9002 §7.2, whose Appendix B.1 names each one.
///
/// `kInitialWindow`: ten maximum datagrams, held to the larger of 14,720 octets and two of them.
/// §7.2 takes the figure from the analysis it cites, raised for UDP's smaller header.
pub const congestion_window_initial_datagrams: u64 = 10;
pub const congestion_window_initial_len_max: u64 = 14_720;

/// `kMinimumWindow`: the smallest the window falls to on loss, on an increase in the peer's
/// ECN-CE count, or on persistent congestion, which §7.2 recommends at two maximum datagrams.
pub const congestion_window_minimum_datagrams: u64 = 2;

/// The constants of CUBIC (RFC 9438, decision 133) and of HyStart++ (RFC 9406, decision 135).
pub const cubic = @import("constants_cubic.zig");
pub const hystart = @import("constants_hystart.zig");

/// RFC 9002 Appendix A.9: a Probe Timeout sends one or two ack-eliciting packets, and two is
/// what recovers a tail of exactly one lost packet in one round trip rather than two.
pub const probe_packets: u8 = 2;

/// RFC 9002 §7.7's `N`, as a fraction: the pacing rate is `N * congestion_window / smoothed_rtt`,
/// and §7.7 asks for an `N` that is small but at least 1, giving 1.25 as its example. Above 1 the
/// window is not left underused when the round trip moves.
pub const pacing_rate_numerator: u64 = 5;
pub const pacing_rate_denominator: u64 = 4;

/// `kPersistentCongestionThreshold`: how many Probe Timeouts a span of loss must cover before it
/// counts as persistent congestion, which §7.6.1 recommends at 3.
pub const persistent_congestion_threshold: u64 = 3;
