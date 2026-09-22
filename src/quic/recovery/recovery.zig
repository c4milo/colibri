//! Loss recovery and congestion control (RFC 9002), tied together. Part of design §8 step 10.
//!
//! Five entry points, which are the five RFC 9002's pseudocode reaches `now()` from and which
//! design §4.2 names: `on_packet_sent`, `on_datagram_received`, `on_ack_received`, `next_timer`
//! and `on_timeout`. Each takes the instant it works at, because colibri reads no clock
//! (non-negotiable 3).
//!
//! **colibri never sets a timer.** `next_timer` returns the instant it next wants to be called
//! at and the caller arranges it, which is design §4.2's rule for every deadline colibri
//! computes.
//!
//! What it holds: one sent-packet table per space (RFC 9000 §12.3), the round trip estimator of
//! `rtt.zig`, the congestion window of `recovery_congestion.zig`, the pacer of
//! `recovery_pacing.zig`, and the per-space facts `recovery_timer.zig` chooses from. The octets
//! in flight are the sum over the three tables and are held nowhere else.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const rtt_estimator = @import("../rtt.zig");
const space = @import("../space/space.zig");
const recovery_congestion = @import("recovery_congestion.zig");
const recovery_loss = @import("recovery_loss.zig");
const recovery_pacing = @import("recovery_pacing.zig");
const recovery_sent = @import("recovery_sent.zig");
const recovery_timer = @import("recovery_timer.zig");
const recovery_ecn = @import("recovery_ecn.zig");

const Congestion = recovery_congestion.Congestion;
const Kind = space.Kind;
const Pacer = recovery_pacing.Pacer;
const Rate = recovery_pacing.Rate;
const Record = recovery_sent.Record;
const Rtt = rtt_estimator.Rtt;
const Timer = recovery_timer.Timer;

pub const Error = recovery_sent.Error;

/// One space's outstanding packets, sized by the one named limit. Every space gets the same
/// table because RFC 9000 §12.3 gives them the same shape; `constants.sent_packets_max` records
/// why they are not sized apart.
pub const Table = recovery_sent.Sent(constants.sent_packets_max);

/// What a timeout asks the caller to do (RFC 9002 Appendix A.9).
pub const Action = union(enum) {
    /// The timer fired with nothing to do, which a caller that armed a stale timer can see.
    none,
    /// Packets were declared lost. Their frames are the caller's to resend.
    lost: recovery_loss.Detected,
    /// Send `count` ack-eliciting packets in `space`, which RFC 9002 Appendix A.9 fills with new
    /// data if there is any, else data already sent, else a PING frame.
    probe: struct { space: Kind, count: u8 },
};

pub const Recovery = struct {
    rtt: Rtt,
    congestion: Congestion,
    pacer: Pacer,
    /// What `recovery_timer.zig` chooses the one timer from.
    timer: recovery_timer.State,
    tables: [constants.packet_number_spaces]Table,
    /// RFC 9002 Appendix A.3's `largest_acked_packet[space]`, or null where the peer has
    /// acknowledged nothing in that space yet.
    largest_acknowledged: [constants.packet_number_spaces]?u64,
    /// RFC 9000 §13.4.2.1's counts, per packet number space: what the peer last reported and what
    /// this endpoint sent under each ECT codepoint. RFC 9002 Appendix B.2's `ecn_ce_counters` is
    /// `reported.ecn_ce`.
    ecn: [constants.packet_number_spaces]recovery_ecn.State,
    /// RFC 9000 §13.4.2.2: false once validation failed, after which this endpoint "stops setting
    /// the ECT codepoint in IP packets that it sends". §13.4.2 validates "for each network path",
    /// and a connection holds one path here, so one answer covers the three spaces.
    ecn_enabled: bool,

    pub fn init(recovery: *Recovery, max_datagram_len: u64) void {
        recovery.rtt.init();
        recovery.congestion.init(max_datagram_len);
        recovery.pacer.init(recovery.rate());
        recovery.timer = .{ .spaces = @splat(.{}) };
        for (&recovery.tables) |*table| table.init();
        recovery.largest_acknowledged = @splat(null);
        for (&recovery.ecn) |*state| state.init();
        recovery.ecn_enabled = true;
    }

    pub fn table_of(recovery: *Recovery, kind: Kind) *Table {
        return &recovery.tables[@intFromEnum(kind)];
    }

    /// RFC 9002 Appendix B.2's `bytes_in_flight`, which is the sum over the three spaces.
    pub fn in_flight_len(recovery: *const Recovery) u64 {
        var total: u64 = 0;
        // Bounded by the three spaces of RFC 9000 §12.3.
        for (recovery.tables) |table| total +|= table.in_flight_len();
        return total;
    }

    /// What `recovery_pacing.zig` spreads over a round trip.
    pub fn rate(recovery: *const Recovery) Rate {
        return .{
            .window_len = recovery.congestion.window,
            .smoothed_rtt_ns = if (recovery.rtt.has_sample()) recovery.rtt.smoothed_ns else 0,
            .burst_len = recovery_congestion.initial_window(recovery.congestion.max_datagram_len),
        };
    }

    /// How many octets may go out now: what the congestion window leaves, held to what the pacer
    /// has earned. RFC 9002 §7.7 exempts a packet carrying only ACK frames from the second,
    /// which the caller applies by sending it without asking.
    pub fn available_len(recovery: *const Recovery) u64 {
        return @min(recovery.congestion.available_len(recovery.in_flight_len()), recovery.pacer.credit_len);
    }

    /// RFC 9000 §13.4.2.2: whether this endpoint may still set an ECT codepoint. The caller
    /// writes the IP header, so it asks before it marks.
    pub fn ecn_permitted(recovery: *const Recovery) bool {
        return recovery.ecn_enabled;
    }

    /// RFC 9002 Appendix A.5's `OnPacketSent`.
    pub fn on_packet_sent(recovery: *Recovery, kind: Kind, sent: Record, now_ns: u64) Error!void {
        try recovery.table_of(kind).record(sent);
        // RFC 9000 §13.4.2.1 compares what the peer reports against what this endpoint marked.
        recovery.ecn[@intFromEnum(kind)].on_packet_sent(sent.ecn);
        if (!sent.in_flight) return;
        const held = &recovery.timer.spaces[@intFromEnum(kind)];
        if (sent.ack_eliciting) held.last_ack_eliciting_sent_at_ns = now_ns;
        held.ack_eliciting_in_flight = recovery.table_of(kind).ack_eliciting_count() > 0;
        recovery.pacer.refill(now_ns, recovery.rate());
        recovery.pacer.on_sent(sent.sent_len);
    }

    /// RFC 9002 Appendix A.6's `OnDatagramReceived`. A server that was at the anti-amplification
    /// limit may send again, so the caller clears the limit and asks for the timer afresh; a
    /// timer already in the past fires at once, which Appendix A.8 says of every timer it sets.
    pub fn on_datagram_received(recovery: *Recovery) void {
        recovery.timer.at_anti_amplification_limit = false;
    }

    /// RFC 9002 Appendix A.8's `SetLossDetectionTimer`: the instant colibri next wants to be
    /// called at, or null when it wants nothing.
    pub fn next_timer(recovery: *const Recovery, now_ns: u64) ?Timer {
        return recovery_timer.next(recovery.timer, recovery.rtt, now_ns);
    }

    /// RFC 9002 Appendix A.9's `OnLossDetectionTimeout`.
    pub fn on_timeout(recovery: *Recovery, now_ns: u64, lost: []Record) Action {
        const timer = recovery.next_timer(now_ns) orelse return .none;
        if (timer.mode == .loss) return .{ .lost = recovery.detect(timer.space, now_ns, lost) };
        // RFC 9002 Appendix A.9: with nothing outstanding this is the anti-deadlock packet, and
        // the space `recovery_timer.zig` chose is the one it goes in.
        const count: u8 = if (recovery.timer.spaces[@intFromEnum(timer.space)].ack_eliciting_in_flight)
            constants.probe_packets
        else
            1;
        recovery.timer.pto_count +|= 1;
        return .{ .probe = .{ .space = timer.space, .count = count } };
    }

    /// Runs RFC 9002 Appendix A.10 over one space and acts on what it found.
    pub fn detect(recovery: *Recovery, kind: Kind, now_ns: u64, lost: []Record) recovery_loss.Detected {
        const largest = recovery.largest_acknowledged[@intFromEnum(kind)] orelse return recovery_loss.Detected.none();
        const found = recovery_loss.detect(
            recovery.table_of(kind),
            largest,
            now_ns,
            recovery.rtt.loss_delay_ns(),
            recovery.rtt.first_sample_at_ns,
            lost,
        );
        recovery.after_loss(kind, found, now_ns);
        return found;
    }

    /// RFC 9002 Appendix B.8's `OnPacketsLost`.
    fn after_loss(recovery: *Recovery, kind: Kind, found: recovery_loss.Detected, now_ns: u64) void {
        const held = &recovery.timer.spaces[@intFromEnum(kind)];
        held.loss_time_ns = found.loss_time_ns;
        held.ack_eliciting_in_flight = recovery.table_of(kind).ack_eliciting_count() > 0;
        // RFC 9002 Appendix B.8: losing packets that were in flight is a congestion event.
        const sent_at_ns = found.latest_sent_at_ns orelse return;
        recovery.congestion.on_congestion_event(sent_at_ns, now_ns);
        // RFC 9002 §7.6: and a long enough span of it is persistent congestion, which puts the
        // window back to the minimum.
        if (found.is_persistent_congestion(recovery.rtt.persistent_congestion_ns())) {
            recovery.congestion.on_persistent_congestion();
        }
    }

    /// RFC 9002 Appendix A.11: dropping a space's keys gives up its packets, which are neither
    /// acknowledged nor lost, and clears what it contributed to the timer.
    pub fn discard_space(recovery: *Recovery, kind: Kind) void {
        _ = recovery.table_of(kind).discard();
        recovery.timer.spaces[@intFromEnum(kind)] = .{};
        recovery.largest_acknowledged[@intFromEnum(kind)] = null;
        // RFC 9002 Appendix A.11: the handshake is over for that space, so a probe waiting on it
        // is no longer owed and the backoff starts again.
        recovery.timer.pto_count = 0;
    }
};

test {
    _ = @import("recovery_test.zig");
}
