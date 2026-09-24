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
    /// Packets in `space` were declared lost. Their frames are the caller's to resend, and the
    /// space is what says whose: RFC 9000 §12.3 gives each space its own packet numbers.
    lost: struct { space: Kind, found: recovery_loss.Detected },
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
    /// RFC 9000 Appendix A.4's state of the path, which says whether this endpoint marks ECT(0)
    /// (decision 69). §13.4.2 validates "for each network path", and a connection holds one path
    /// here, so one answer covers the three spaces.
    ecn_path: recovery_ecn.Path,

    pub fn init(recovery: *Recovery, max_datagram_len: u64) void {
        recovery.rtt.init();
        recovery.congestion.init(max_datagram_len);
        recovery.pacer.init(recovery.rate());
        recovery.timer = .{ .spaces = @splat(.{}) };
        for (&recovery.tables) |*table| table.init();
        recovery.largest_acknowledged = @splat(null);
        for (&recovery.ecn) |*state| state.init();
        recovery.ecn_path.init();
    }

    /// RFC 9000 §9.4: the peer's new address is validated, so the congestion controller and the
    /// RTT estimator start again "for the new path to initial values (see Appendices A.3 and B.3
    /// of [QUIC-RECOVERY])". What the peer advertised is kept (`Rtt.reset`).
    pub fn on_path_changed(recovery: *Recovery) void {
        recovery.rtt.reset();
        recovery.congestion.init(recovery.congestion.max_datagram_len);
        recovery.pacer.init(recovery.rate());
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

    /// RFC 9000 §13.4.2.2: whether validation failed, after which this endpoint "stops setting
    /// the ECT codepoint in IP packets that it sends" for the rest of the connection.
    pub fn ecn_failed(recovery: *const Recovery) bool {
        return recovery.ecn_path.state == .failed;
    }

    /// The codepoint the next datagram carries at `now_ns`: ECT(0) while the path is testing or
    /// capable, and Not-ECT otherwise (RFC 9000 Appendix A.4, decision 69). The caller writes the
    /// IP header, so it asks before it marks.
    pub fn ecn_codepoint(recovery: *Recovery, now_ns: u64) recovery_sent.Ecn {
        const probe_timeout_ns = recovery.rtt.probe_timeout_ns(true);
        return if (recovery.ecn_path.marks(now_ns, probe_timeout_ns)) .ect_0 else .not_ect;
    }

    /// A packet sent under `ecn` that no record keeps, such as one of ACK frames alone. RFC 9000
    /// §13.4.2.1 fails validation when a reported count "exceeds the total number of packets sent
    /// with each corresponding ECT codepoint", and the peer counts this packet too (§13.4.1).
    pub fn on_packet_sent_unrecorded(recovery: *Recovery, kind: Kind, ecn: recovery_sent.Ecn, now_ns: u64) void {
        recovery.count_marked(kind, ecn, now_ns);
    }

    /// RFC 9000 §13.4.2.1 compares what the peer reports against what this endpoint marked, and
    /// decision 69's test counts the marked packets of the path.
    fn count_marked(recovery: *Recovery, kind: Kind, ecn: recovery_sent.Ecn, now_ns: u64) void {
        recovery.ecn[@intFromEnum(kind)].on_packet_sent(ecn);
        if (ecn == .ect_0 or ecn == .ect_1) recovery.ecn_path.on_marked_sent(now_ns);
    }

    /// RFC 9002 Appendix A.5's `OnPacketSent`.
    pub fn on_packet_sent(recovery: *Recovery, kind: Kind, sent: Record, now_ns: u64) Error!void {
        try recovery.table_of(kind).record(sent);
        recovery.count_marked(kind, sent.ecn, now_ns);
        if (!sent.in_flight) return;
        // RFC 9002 Appendix A.5: a packet in flight sets the timer again.
        recovery.timer.armed_at_ns = now_ns;
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
    pub fn next_timer(recovery: *const Recovery) ?Timer {
        return recovery_timer.next(recovery.timer, recovery.rtt);
    }

    /// RFC 9002 Appendix A.9's `OnLossDetectionTimeout`.
    pub fn on_timeout(recovery: *Recovery, now_ns: u64, lost: []Record) Action {
        const timer = recovery.next_timer() orelse return .none;
        // RFC 9002 Appendix A.9 ends every branch with `SetLossDetectionTimer`.
        recovery.timer.armed_at_ns = now_ns;
        if (timer.mode == .loss) {
            return .{ .lost = .{ .space = timer.space, .found = recovery.detect(timer.space, now_ns, lost) } };
        }
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

    /// Takes every packet `kind` has in flight out of its table as lost, and writes as many of the
    /// records as fit into `lost`. RFC 9002 §6.2.4: "instead of sending an ack-eliciting packet,
    /// the sender MAY mark any packets still in flight as lost". Decision 64 does so when a PTO
    /// fires at a handshake level, so the probes carry the CRYPTO octets those packets held.
    ///
    /// It is no congestion event: the packets are declared lost to move their octets, and §6.2.4
    /// names "an unnecessary rate reduction by the congestion controller" as this choice's risk.
    pub fn declare_in_flight_lost(recovery: *Recovery, kind: Kind, lost: []Record) recovery_sent.Removed {
        assert(kind != .application);
        const removed = recovery.table_of(kind).remove_range_into(0, constants.packet_number_max, lost);
        recovery.timer.spaces[@intFromEnum(kind)].ack_eliciting_in_flight = false;
        assert(recovery.table_of(kind).count() == 0);
        return removed;
    }

    /// Takes the `count` oldest ack-eliciting packets `kind` has in flight out of its table as
    /// lost, writes their records into `lost`, and returns how many it took. Decision 66 does so
    /// when a PTO fires at the application level: RFC 9002 §6.2.4 lets a sender "mark any packets
    /// still in flight as lost", and marking the oldest alone gives each probe their frames
    /// without sending the whole window again. As in decision 64, it is no congestion event.
    pub fn declare_oldest_lost(recovery: *Recovery, kind: Kind, count: u8, lost: []Record) usize {
        assert(count > 0 and count <= lost.len);
        const table = recovery.table_of(kind);
        var found: usize = 0;
        var records = table.iterator();
        // Bounded by the table, and ends once `count` are found. The walk runs from the oldest.
        while (records.next()) |record| {
            if (found == count) break;
            if (!record.ack_eliciting) continue;
            lost[found] = record;
            found += 1;
        }
        // Taken after the walk, which reads the table as it was.
        for (lost[0..found]) |record| {
            const taken = table.remove(record.number);
            assert(taken != null);
        }
        recovery.timer.spaces[@intFromEnum(kind)].ack_eliciting_in_flight = table.ack_eliciting_count() > 0;
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
