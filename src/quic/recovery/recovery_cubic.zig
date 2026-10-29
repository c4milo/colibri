//! The arithmetic of CUBIC (RFC 9438 §4.2 to §4.7, decision 133), in octets and microseconds, which
//! `recovery_congestion.zig` calls. Part of design §8 step 27.
//!
//! RFC 9438 counts the window in segments and time in seconds, and §4.1 lets an implementation
//! count octets, scaling by the maximum segment, which here is the maximum datagram. colibri reads
//! no floating point on a protocol path, so each fraction is a pair of integers, time is in
//! microseconds, and §4.2's cube root is an integer one (non-negotiable 5).
const std = @import("std");
const assert = std.debug.assert;
const cubic = @import("../constants.zig").cubic;

/// What the cubic increase is shaped by in one congestion avoidance stage: W_max, the window the
/// stage aims back at (§4.1.2), and K, the microseconds it takes to get there (§4.2, Figure 2).
pub const Curve = struct {
    w_max: u64,
    k_us: u64,
    datagram_len: u64,

    /// The curve of a stage that starts at `window`. A W_max at or below the window, which §4.8
    /// and §4.10 make the case after a timeout or a slow start that ended without a loss, gives
    /// K = 0 and W_max = the window.
    pub fn of(w_max: u64, window: u64, datagram_len: u64) Curve {
        assert(datagram_len > 0);
        if (w_max <= window) return .{ .w_max = window, .k_us = 0, .datagram_len = datagram_len };
        // Figure 2: K = cbrt((W_max − cwnd_epoch) / C), in seconds and segments. In microseconds
        // and octets: cbrt((W_max − cwnd_epoch) × 10^18 / (C × datagram)).
        const shortfall: u128 = w_max - window;
        const scaled = shortfall * cubic.c_denominator * cubic.microseconds_per_second * cubic.microseconds_per_second *
            cubic.microseconds_per_second / (cubic.c_numerator * datagram_len);
        return .{ .w_max = w_max, .k_us = cube_root(scaled), .datagram_len = datagram_len };
    }

    /// §4.2, Figure 1: W_cubic(t) = C × (t − K)^3 + W_max, in octets, for `t_us` microseconds into
    /// the stage. It is 0 rather than negative before the curve rises past nothing.
    pub fn window_at(curve: Curve, t_us: u64) u64 {
        const elapsed: i128 = @as(i128, @min(t_us, cubic.elapsed_us_max)) - @min(curve.k_us, cubic.elapsed_us_max);
        const cube = elapsed * elapsed * elapsed;
        const second_cubed: i128 = cubic.microseconds_per_second * cubic.microseconds_per_second * cubic.microseconds_per_second;
        const rise = @divTrunc(cube * cubic.c_numerator * curve.datagram_len, cubic.c_denominator * second_cubed);
        const window = rise + curve.w_max;
        if (window <= 0) return 0;
        return @intCast(@min(window, std.math.maxInt(u64)));
    }

    /// §4.2: the target after the next round trip, W_cubic(t + RTT), held between the window and
    /// 1.5 times it, so the increase never slows and never passes slow start's.
    pub fn target(curve: Curve, t_us: u64, rtt_us: u64, window: u64) u64 {
        const ahead = curve.window_at(t_us +| rtt_us);
        const ceiling = window / cubic.target_denominator * cubic.target_numerator;
        return std.math.clamp(ahead, window, @max(window, ceiling));
    }
};

/// §4.3, Figure 4: what W_est gains from `acknowledged_len` octets acknowledged at `window`, with
/// α_cubic until W_est reaches cwnd_prior and 1 from there.
pub fn estimate_gain(acknowledged_len: u64, window: u64, datagram_len: u64, reached_prior: bool) u64 {
    assert(window > 0);
    const gain: u128 = @as(u128, acknowledged_len) * datagram_len / window;
    if (reached_prior) return @intCast(gain);
    return @intCast(gain * cubic.alpha_numerator / cubic.alpha_denominator);
}

/// §4.7: W_max after a congestion event at `window`, lowered further with fast convergence when
/// the window fell short of the W_max before it.
pub fn w_max_after(window: u64, w_max_before: u64) u64 {
    if (window < w_max_before) return window / cubic.convergence_denominator * cubic.convergence_numerator;
    return window;
}

/// §4.6, Figure 5: the slow start threshold after a congestion event at `window`, β_cubic of it.
pub fn reduced(window: u64) u64 {
    return window / cubic.beta_denominator * cubic.beta_numerator;
}

/// The largest integer whose cube is at most `value`, by bisection over `cube_root_bits` bits.
pub fn cube_root(value: u128) u64 {
    var root: u64 = 0;
    var bit: u7 = cubic.cube_root_bits;
    // Bounded by `cube_root_bits`: each pass decides one bit of the root, from the highest.
    while (bit > 0) {
        bit -= 1;
        const candidate = root | (@as(u64, 1) << @intCast(bit));
        const square: u128 = @as(u128, candidate) * candidate;
        // For integers, square ≤ ⌊value / candidate⌋ exactly when square × candidate ≤ value, and
        // the division cannot overflow where the product could.
        if (square <= value / candidate) root = candidate;
    }
    assert(@as(u128, root) * root * root <= value);
    return root;
}

const testing = std.testing;

/// RFC 9000 §14.1's smallest datagram, the segment these tests count in. Test-only.
const datagram: u64 = 1200;

test "decision 133: an integer cube root is exact on cubes and rounds down between them" {
    try testing.expectEqual(0, cube_root(0));
    try testing.expectEqual(1, cube_root(7));
    try testing.expectEqual(2, cube_root(8));
    try testing.expectEqual(1_000_000, cube_root(1_000_000_000_000_000_000));
    try testing.expectEqual(999_999, cube_root(1_000_000_000_000_000_000 - 1));
    try testing.expect(cube_root(std.math.maxInt(u128)) < @as(u64, 1) << cubic.cube_root_bits);
}

test "RFC 9438 §4.2: the curve starts at the window, reaches W_max at K, and rises past it" {
    // Ten segments short of W_max: K = cbrt(10 / 0.4) = cbrt(25) seconds, about 2.924 seconds.
    const w_max = 30 * datagram;
    const curve = Curve.of(w_max, 20 * datagram, datagram);
    try testing.expectEqual(2_924_017, curve.k_us);
    // At t = 0 the curve is back at the window. K rounds down, so it lands an octet above it.
    try testing.expectEqual(20 * datagram + 1, curve.window_at(0));
    try testing.expectEqual(w_max, curve.window_at(curve.k_us));
    // One second past K: W_max + C × 1^3 segments, 0.4 of a datagram.
    try testing.expectEqual(w_max + datagram * cubic.c_numerator / cubic.c_denominator, curve.window_at(curve.k_us + cubic.microseconds_per_second));
}

test "RFC 9438 §4.8, §4.10: a W_max at or below the window gives K = 0 and W_max = the window" {
    const curve = Curve.of(10 * datagram, 20 * datagram, datagram);
    try testing.expectEqual(0, curve.k_us);
    try testing.expectEqual(20 * datagram, curve.w_max);
}

test "RFC 9438 §4.2: the target holds between the window and 1.5 times it" {
    const window = 20 * datagram;
    const curve = Curve.of(30 * datagram, window, datagram);
    // At the stage's start the target is the window, an octet above it for K's rounding.
    try testing.expectEqual(window + 1, curve.target(0, 0, window));
    // A W_max below the window starts the curve at it, and the target cannot fall below it.
    try testing.expectEqual(window, Curve.of(0, window, datagram).target(0, 0, window));
    // Far past K the curve outruns slow start, and the target stops at 1.5 times the window.
    try testing.expectEqual(window / 2 * 3, curve.target(cubic.elapsed_us_max, 0, window));
}

test "RFC 9438 §4.3, §4.6, §4.7: the Reno-friendly gain, the decrease and fast convergence" {
    // A window of octets acknowledged at that window gains α = 9/17 of a datagram, then 1.
    try testing.expectEqual(datagram * 9 / 17, estimate_gain(10 * datagram, 10 * datagram, datagram, false));
    try testing.expectEqual(datagram, estimate_gain(10 * datagram, 10 * datagram, datagram, true));
    try testing.expectEqual(7 * datagram, reduced(10 * datagram));
    // A window short of the W_max before lowers W_max to (1 + β) / 2 of it; one at or past it keeps it.
    try testing.expectEqual(17 * datagram, w_max_after(20 * datagram, 30 * datagram));
    try testing.expectEqual(20 * datagram, w_max_after(20 * datagram, 20 * datagram));
}

/// The base the vector file writes its numbers in. Test-only.
const decimal: u8 = 10;

/// Reads the next field of a vector line as an integer. Test-only.
fn field(comptime T: type, fields: *std.mem.TokenIterator(u8, .scalar)) !T {
    return std.fmt.parseUnsigned(T, fields.next() orelse return error.TestVectorShort, decimal);
}

test "decision 77: the arithmetic gives what spec/lean/Colibri/Quic/Cubic.lean proves it gives" {
    var lines = std.mem.splitScalar(u8, @embedFile("cubic_vectors.txt"), '\n');
    var counts: [6]usize = @splat(0);
    // Bounded by the file, which spec/lean/Vectors.lean writes.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = fields.next().?;
        if (std.mem.eql(u8, kind, "root")) {
            const value = try field(u128, &fields);
            try testing.expectEqual(try field(u64, &fields), cube_root(value));
            counts[0] += 1;
        } else if (std.mem.eql(u8, kind, "curve")) {
            const curve = Curve.of(try field(u64, &fields), try field(u64, &fields), try field(u64, &fields));
            try testing.expectEqual(try field(u64, &fields), curve.w_max);
            try testing.expectEqual(try field(u64, &fields), curve.k_us);
            counts[1] += 1;
        } else if (std.mem.eql(u8, kind, "at")) {
            const curve: Curve = .{ .w_max = try field(u64, &fields), .k_us = try field(u64, &fields), .datagram_len = try field(u64, &fields) };
            const t_us = try field(u64, &fields);
            try testing.expectEqual(try field(u64, &fields), curve.window_at(t_us));
            counts[2] += 1;
        } else if (std.mem.eql(u8, kind, "target")) {
            const curve: Curve = .{ .w_max = try field(u64, &fields), .k_us = try field(u64, &fields), .datagram_len = try field(u64, &fields) };
            const t_us = try field(u64, &fields);
            const rtt_us = try field(u64, &fields);
            const window = try field(u64, &fields);
            try testing.expectEqual(try field(u64, &fields), curve.target(t_us, rtt_us, window));
            counts[3] += 1;
        } else if (std.mem.eql(u8, kind, "reduced")) {
            const window = try field(u64, &fields);
            try testing.expectEqual(try field(u64, &fields), reduced(window));
            counts[4] += 1;
        } else {
            try testing.expectEqualStrings("w_max_after", kind);
            const window = try field(u64, &fields);
            const before = try field(u64, &fields);
            try testing.expectEqual(try field(u64, &fields), w_max_after(window, before));
            counts[5] += 1;
        }
    }
    // Every kind of line the file holds was read.
    for (counts) |count| try testing.expect(count > 0);
}
