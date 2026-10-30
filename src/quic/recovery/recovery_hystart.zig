//! HyStart++ (RFC 9406), the slow start of CUBIC's first stage (decision 135). Part of design §8
//! step 28.
//!
//! Slow start doubles the window each round trip until a loss stops it. HyStart++ watches the
//! smallest round trip of each round instead: when it grows by a threshold, a queue fills, and
//! the window moves to Conservative Slow Start (CSS), which grows it by a quarter as fast. When
//! the round trip falls back below the one that started CSS, the exit was spurious and slow start
//! resumes. After CSS_ROUNDS rounds of CSS the window enters congestion avoidance.
//!
//! A round ends when an acknowledged packet went out at or after the round's start: §4.2's
//! windowEnd in send instants rather than sequence numbers (decision 135). It reads no clock:
//! every instant is a parameter (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const hystart = @import("../constants.zig").recovery.hystart;

/// Where slow start stands. `done` is every slow start after the first, which §4.3 leaves to the
/// standard algorithm.
pub const Stage = enum { slow_start, conservative, done };

/// What one acknowledgment does to the window.
pub const Growth = enum {
    /// The octets acknowledged, as in standard slow start (§4.2's `cwnd + min(N, L * SMSS)` with
    /// L infinity).
    full,
    /// The octets acknowledged divided by CSS_GROWTH_DIVISOR (§4.2).
    conservative,
    /// None in slow start: the window enters congestion avoidance with `ssthresh = cwnd` (§4.2).
    avoidance,
};

pub const HyStart = struct {
    stage: Stage,
    /// When the current round started, or null before the first acknowledgment.
    round_started_at_ns: ?u64,
    /// §4.2's lastRoundMinRTT and currentRoundMinRTT. Null is infinity.
    last_round_min_ns: ?u64,
    round_min_ns: ?u64,
    /// §4.2's rttSampleCount, held at N_RTT_SAMPLE once it gets there.
    samples: u8,
    /// §4.2's cssBaselineMinRtt, the round trip that started CSS. Null is infinity.
    css_baseline_ns: ?u64,
    /// The rounds of CSS so far, the partial round that started it included (§4.2).
    css_rounds: u8,

    pub fn init(held: *HyStart) void {
        held.* = .{
            .stage = .slow_start,
            .round_started_at_ns = null,
            .last_round_min_ns = null,
            .round_min_ns = null,
            .samples = 0,
            .css_baseline_ns = null,
            .css_rounds = 0,
        };
    }

    /// One ACK frame that arrived in slow start. `largest_sent_at_ns` is when the largest packet it
    /// newly acknowledged went out, and `rtt_ns` the round trip sample it gave, if any (RFC 9002
    /// §5.1). The answer is how the window takes the octets the frame acknowledged.
    pub fn on_ack(held: *HyStart, largest_sent_at_ns: u64, rtt_ns: ?u64, now_ns: u64) Growth {
        if (held.stage == .done) return .full;
        // §4.2: "When windowEnd is ACKed, the current round ends".
        const started_at_ns = held.round_started_at_ns orelse 0;
        if (held.round_started_at_ns == null or largest_sent_at_ns >= started_at_ns) {
            if (held.start_round(now_ns) == .avoidance) return .avoidance;
        }
        // §4.2 updates the window before it takes the sample, so the stage before is the growth.
        const growth: Growth = if (held.stage == .conservative) .conservative else .full;
        const sampled_ns = rtt_ns orelse return growth;
        held.round_min_ns = @min(held.round_min_ns orelse sampled_ns, sampled_ns);
        if (held.samples < hystart.rtt_samples) held.samples += 1;
        if (held.samples >= hystart.rtt_samples) held.judge_round();
        assert(held.stage != .done);
        return growth;
    }

    /// Ends HyStart++ for the rest of the connection (§4.2: "If loss or ... ECN marking is observed
    /// at any time during standard slow start or CSS, enter congestion avoidance").
    pub fn finish(held: *HyStart) void {
        held.stage = .done;
        held.css_baseline_ns = null;
        assert(held.stage == .done);
    }

    /// §4.2: "At the start of each round ... lastRoundMinRTT = currentRoundMinRTT". A round of CSS
    /// that ends the last of CSS_ROUNDS ends slow start.
    fn start_round(held: *HyStart, now_ns: u64) Growth {
        held.round_started_at_ns = now_ns;
        held.last_round_min_ns = held.round_min_ns;
        held.round_min_ns = null;
        held.samples = 0;
        if (held.stage != .conservative) return .full;
        // §4.2: "If CSS_ROUNDS rounds are complete, enter congestion avoidance".
        if (held.css_rounds >= hystart.css_rounds) {
            held.finish();
            return .avoidance;
        }
        held.css_rounds += 1;
        return .conservative;
    }

    /// §4.2's two comparisons, once the round holds N_RTT_SAMPLE samples.
    fn judge_round(held: *HyStart) void {
        const round_min_ns = held.round_min_ns.?;
        switch (held.stage) {
            .slow_start => {
                const last_ns = held.last_round_min_ns orelse return;
                // §4.2: the delay increase that "triggers slow start exit".
                if (round_min_ns < last_ns +| threshold_ns(last_ns)) return;
                held.css_baseline_ns = round_min_ns;
                held.stage = .conservative;
                // §4.2: "If the transition into CSS happens in the middle of a round, that partial
                // round counts towards the limit."
                held.css_rounds = 1;
            },
            .conservative => {
                // §4.2: a round trip below the baseline means "slow start exit was spurious".
                if (round_min_ns >= held.css_baseline_ns.?) return;
                held.css_baseline_ns = null;
                held.stage = .slow_start;
            },
            .done => unreachable,
        }
    }
};

/// §4.2's RttThresh: the last round's minimum divided by MIN_RTT_DIVISOR, held between
/// MIN_RTT_THRESH and MAX_RTT_THRESH.
pub fn threshold_ns(last_round_min_ns: u64) u64 {
    const scaled_ns = last_round_min_ns / hystart.rtt_divisor;
    return @max(hystart.rtt_threshold_min_ns, @min(scaled_ns, hystart.rtt_threshold_max_ns));
}

const testing = std.testing;
const ms: u64 = 1_000_000;

/// Feeds one round: an acknowledgment of a packet sent after the round began, then the samples.
fn round(held: *HyStart, at_ns: u64, rtt_ns: u64, samples: u8) Growth {
    var first = held.on_ack(at_ns, rtt_ns, at_ns);
    var sample: u8 = 1;
    // Bounded by `samples`.
    while (sample < samples) : (sample += 1) {
        const growth = held.on_ack(at_ns - 1, rtt_ns, at_ns);
        if (first != .avoidance) first = growth;
    }
    return first;
}

test "RFC 9406 §4.2: RttThresh is the last minimum over 8, between 4 and 16 ms" {
    try testing.expectEqual(4 * ms, threshold_ns(10 * ms));
    try testing.expectEqual(10 * ms, threshold_ns(80 * ms));
    try testing.expectEqual(16 * ms, threshold_ns(200 * ms));
}

test "RFC 9406 §4.2: a round trip that grows by the threshold moves slow start to CSS" {
    var held: HyStart = undefined;
    held.init();
    try testing.expectEqual(Growth.full, round(&held, 1 * ms, 100 * ms, 8));
    // 100 ms over 8 is 12.5 ms: 112 ms is below the threshold.
    _ = round(&held, 200 * ms, 112 * ms, 8);
    try testing.expectEqual(Stage.slow_start, held.stage);
    // 112 ms over 8 is 14 ms, and 126 ms is at it.
    _ = round(&held, 400 * ms, 126 * ms, 8);
    try testing.expectEqual(Stage.conservative, held.stage);
    try testing.expectEqual(126 * ms, held.css_baseline_ns.?);
    try testing.expectEqual(1, held.css_rounds);
    // Seven samples are not enough to judge a round.
    held.init();
    _ = round(&held, 1 * ms, 100 * ms, 8);
    _ = round(&held, 200 * ms, 200 * ms, 7);
    try testing.expectEqual(Stage.slow_start, held.stage);
}

test "RFC 9406 §4.2: CSS grows by a quarter, and a round trip below its baseline resumes slow start" {
    var held: HyStart = undefined;
    held.init();
    _ = round(&held, 1 * ms, 100 * ms, 8);
    _ = round(&held, 200 * ms, 130 * ms, 8);
    try testing.expectEqual(Growth.conservative, held.on_ack(1 * ms, 130 * ms, 201 * ms));
    // At the baseline, CSS holds; one nanosecond below it, the exit was spurious.
    _ = round(&held, 400 * ms, 130 * ms, 8);
    try testing.expectEqual(Stage.conservative, held.stage);
    _ = round(&held, 600 * ms, 130 * ms - 1, 8);
    try testing.expectEqual(Stage.slow_start, held.stage);
    try testing.expectEqual(null, held.css_baseline_ns);
}

test "RFC 9406 §4.2: after CSS_ROUNDS rounds of CSS the window enters congestion avoidance" {
    var held: HyStart = undefined;
    held.init();
    _ = round(&held, 1 * ms, 100 * ms, 8);
    _ = round(&held, 200 * ms, 130 * ms, 8);
    // The partial round that started CSS is its first; four more follow it.
    var at_ns: u64 = 400 * ms;
    for (1..hystart.css_rounds) |_| {
        try testing.expectEqual(Growth.conservative, round(&held, at_ns, 140 * ms, 8));
        at_ns += 200 * ms;
    }
    try testing.expectEqual(Growth.avoidance, held.on_ack(at_ns, 140 * ms, at_ns));
    try testing.expectEqual(Stage.done, held.stage);
    try testing.expectEqual(Growth.full, held.on_ack(at_ns + 1, 140 * ms, at_ns + 1));
}

test "RFC 9406 §4.2: an ACK with no sample moves neither the minimum nor the count" {
    var held: HyStart = undefined;
    held.init();
    _ = held.on_ack(1 * ms, null, 1 * ms);
    try testing.expectEqual(null, held.round_min_ns);
    try testing.expectEqual(0, held.samples);
    // An acknowledgment of a packet sent before the round began does not end it.
    _ = held.on_ack(1 * ms - 1, 50 * ms, 2 * ms);
    try testing.expectEqual(1 * ms, held.round_started_at_ns.?);
    try testing.expectEqual(1, held.samples);
    // One sent at the instant the round began is the first of the round, and ends it.
    _ = held.on_ack(1 * ms, null, 3 * ms);
    try testing.expectEqual(3 * ms, held.round_started_at_ns.?);
}

test "RFC 9406 §4.3: after a loss, slow start is the standard one" {
    var held: HyStart = undefined;
    held.init();
    _ = round(&held, 1 * ms, 100 * ms, 8);
    held.finish();
    // A round trip that would start CSS changes nothing.
    try testing.expectEqual(Growth.full, round(&held, 200 * ms, 300 * ms, 8));
    try testing.expectEqual(Stage.done, held.stage);
}

const Tokens = std.mem.TokenIterator(u8, .scalar);
const decimal: u8 = 10;

fn field(fields: *Tokens) !u64 {
    return std.fmt.parseUnsigned(u64, fields.next() orelse return error.TestVectorShort, decimal);
}

/// A value the vectors write as `-` when it is null.
fn optional(fields: *Tokens) !?u64 {
    const text = fields.next() orelse return error.TestVectorShort;
    if (std.mem.eql(u8, text, "-")) return null;
    return try std.fmt.parseUnsigned(u64, text, decimal);
}

/// The state the vectors write after each step, in `stateText`'s order.
fn expect_state(held: *const HyStart, fields: *Tokens) !void {
    const stage = std.meta.stringToEnum(Stage, fields.next() orelse return error.TestVectorShort).?;
    try testing.expectEqual(stage, held.stage);
    try testing.expectEqual(try optional(fields), held.round_started_at_ns);
    try testing.expectEqual(try optional(fields), held.last_round_min_ns);
    try testing.expectEqual(try optional(fields), held.round_min_ns);
    try testing.expectEqual(try field(fields), held.samples);
    try testing.expectEqual(try optional(fields), held.css_baseline_ns);
    try testing.expectEqual(try field(fields), held.css_rounds);
}

test "decision 77: HyStart++ steps as spec/lean/Colibri/Quic/HyStart.lean proves it steps" {
    var lines = std.mem.splitScalar(u8, @embedFile("hystart_vectors.txt"), '\n');
    var held: HyStart = undefined;
    held.init();
    var counts: [4]usize = @splat(0);
    // Bounded by the file, which spec/lean/Vectors.lean writes.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = fields.next().?;
        if (std.mem.eql(u8, kind, "threshold")) {
            const last_ns = try field(&fields);
            try testing.expectEqual(try field(&fields), threshold_ns(last_ns));
            counts[0] += 1;
        } else if (std.mem.eql(u8, kind, "init")) {
            held.init();
            counts[1] += 1;
        } else if (std.mem.eql(u8, kind, "finish")) {
            held.finish();
            try expect_state(&held, &fields);
            counts[2] += 1;
        } else {
            try testing.expectEqualStrings("ack", kind);
            const sent_at_ns = try field(&fields);
            const rtt_ns = try optional(&fields);
            const now_ns = try field(&fields);
            const growth = std.meta.stringToEnum(Growth, fields.next() orelse return error.TestVectorShort).?;
            try testing.expectEqual(growth, held.on_ack(sent_at_ns, rtt_ns, now_ns));
            try expect_state(&held, &fields);
            counts[3] += 1;
        }
    }
    // Every kind of line the file holds was read.
    for (counts) |count| try testing.expect(count > 0);
}
