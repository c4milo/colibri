//! The driver of the step 10 check: one seed's run of `recovery_check.zig`. It is a file of its
//! own because a hand-written source file stays at or under 500 lines (CLAUDE.md), and the check
//! keeps the name while the turn-by-turn driving lives here.
//!
//! What it does each turn: give the receiver what has arrived, write the acknowledgment RFC 9000
//! §13.2.1 owes, give the sender what came back, fire the one loss detection timer where it is
//! due, send while the window and the pacer allow, and step time to the next instant anything is
//! due at.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const constants = sim.constants;
const recovery_check = @import("recovery_check.zig");

const Random = sim.random.Random;
const Reader = quic.core.Reader;
const Writer = quic.core.Writer;
const Record = quic.recovery_sent.Record;
const Space = quic.space.Space;
const Result = recovery_check.Result;
const Scenario = recovery_check.Scenario;
const Storage = recovery_check.Storage;
const Violation = recovery_check.Violation;
const datagram_len = recovery_check.datagram_len;
const packets_per_seed = recovery_check.packets_per_seed;
const numbers_max = recovery_check.numbers_max;
const kind_data = recovery_check.kind_data;
const kind_ack = recovery_check.kind_ack;
const blackhole_from_ns = recovery_check.blackhole_from_ns;
const blackhole_until_ns = recovery_check.blackhole_until_ns;
const start_ns = recovery_check.start_ns;
const idle_step_ns = recovery_check.idle_step_ns;
const ack_delay_exponent = recovery_check.ack_delay_exponent;
const steps_max = recovery_check.steps_max;
const scenario_count = recovery_check.scenario_count;

/// Runs one seed and returns its counts.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    var random = Random.init(seed);
    const scenario: Scenario = @enumFromInt(random.below(scenario_count));
    var run = Run.start(storage, seed, scenario);
    // Bounded by `steps_max`, which is a named limit.
    for (0..steps_max) |_| {
        if (try run.step()) return run.finish();
    }
    return Violation.StepsExhausted;
}

/// One seed's driver.
const Run = struct {
    storage: *Storage,
    scenario: Scenario,
    now_ns: u64,
    /// The next number the sender will use, and how many it has put on the path.
    next_number: u64,
    result: Result,
    digest: std.hash.Crc32,

    fn start(storage: *Storage, seed: u64, scenario: Scenario) Run {
        storage.sender.init(datagram_len);
        storage.sender.timer.handshake_confirmed = true;
        storage.sender.timer.peer_completed_address_validation = true;
        storage.receiver.init(.application);
        storage.network.init(seed, scenario.schedule());
        storage.outstanding = @splat(false);
        storage.settled = @splat(false);
        return .{
            .storage = storage,
            .scenario = scenario,
            .now_ns = start_ns,
            .next_number = 0,
            .result = .{
                .scenario = scenario,
                .window = storage.sender.congestion.window,
                .window_min = storage.sender.congestion.window,
            },
            .digest = std.hash.Crc32.init(),
        };
    }

    /// One turn of the driver. Returns whether the run is over.
    fn step(run: *Run) Violation!bool {
        try run.deliver();
        try run.fire_timer();
        try run.send_while_allowed();
        try run.check_invariants();
        if (run.is_drained()) return true;
        run.now_ns = run.next_instant();
        return false;
    }

    /// Whether everything sent has been accounted for and nothing is on the path.
    fn is_drained(run: *const Run) bool {
        if (run.next_number < packets_per_seed) return false;
        if (run.storage.sender.in_flight_len() != 0) return false;
        return run.storage.network.in_flight_count() == 0;
    }

    /// The next instant anything is due at: a datagram arriving, the one loss detection timer,
    /// or the pacer earning enough for another packet. Never behind the current instant.
    fn next_instant(run: *const Run) u64 {
        var at_ns: u64 = run.now_ns +| idle_step_ns;
        if (run.storage.network.next_arrival_ns()) |arrival_ns| at_ns = @min(at_ns, arrival_ns);
        if (run.storage.sender.next_timer(run.now_ns)) |timer| at_ns = @min(at_ns, timer.at_ns);
        return @max(at_ns, run.now_ns +| 1);
    }

    /// Gives the receiver everything that has arrived, and the sender every acknowledgment.
    fn deliver(run: *Run) Violation!void {
        // Bounded by the network's own slot count, which is a named limit.
        for (0..constants.network_in_flight_max) |_| {
            const delivery = run.storage.network.receive(run.now_ns, .server) orelse break;
            try run.receive_data(delivery.octets, delivery.ecn);
        }
        for (0..constants.network_in_flight_max) |_| {
            const delivery = run.storage.network.receive(run.now_ns, .client) orelse break;
            try run.receive_ack(delivery.octets);
        }
        try run.answer();
    }

    /// The receiver takes one data datagram.
    fn receive_data(run: *Run, octets: []const u8, ecn: sim.network.Ecn) Violation!void {
        var reader = Reader.init(octets);
        const kind = reader.read_byte() catch return Violation.DatagramNotRead;
        if (kind != kind_data) return Violation.DatagramNotRead;
        const number = reader.read_int(u64) catch return Violation.DatagramNotRead;
        _ = run.storage.receiver.receive(number, run.now_ns, true, space_ecn(ecn));
    }

    /// The receiver writes an ACK frame where RFC 9000 §13.2.1 says one is owed.
    fn answer(run: *Run) Violation!void {
        if (!run.storage.receiver.owes_ack()) return;
        var writer = Writer.init(&run.storage.datagram);
        writer.write_byte(kind_ack) catch return Violation.DatagramNotRead;
        const written = run.storage.receiver.write_ack(&writer, run.now_ns, ack_delay_exponent, true) catch
            return Violation.DatagramNotRead;
        if (!written) return;
        try run.put(.server, writer.written());
    }

    /// The sender takes one acknowledgment (RFC 9002 Appendix A.7).
    fn receive_ack(run: *Run, octets: []const u8) Violation!void {
        var reader = Reader.init(octets);
        const kind = reader.read_byte() catch return Violation.DatagramNotRead;
        if (kind != kind_ack) return Violation.DatagramNotRead;
        const read = quic.frame.read(&reader) catch return Violation.DatagramNotRead;
        const ack = switch (read) {
            .ack => |held| held,
            else => return Violation.DatagramNotRead,
        };
        const outcome = quic.recovery_ack.on_ack_received(
            &run.storage.sender,
            .application,
            .{ .ranges = ack.ranges, .delay_ns = ack.delay * delay_unit_ns(), .ecn = ack.ecn },
            .full,
            run.now_ns,
            &run.storage.lost,
        );
        try run.settle_acknowledged(ack);
        try run.settle_lost(outcome.lost.written);
        run.result.acknowledged += outcome.acknowledged;
    }

    /// Fires the one loss detection timer where it is due (RFC 9002 Appendix A.9).
    fn fire_timer(run: *Run) Violation!void {
        const timer = run.storage.sender.next_timer(run.now_ns) orelse return;
        if (timer.at_ns > run.now_ns) return;
        const action = run.storage.sender.on_timeout(run.now_ns, &run.storage.lost);
        switch (action) {
            .none => {},
            .lost => |found| try run.settle_lost(found.written),
            .probe => |probe| try run.send_probes(probe.count),
        }
    }

    /// RFC 9002 Appendix A.9 sends one or two ack-eliciting packets when the Probe Timeout
    /// fires. This harness has no new data left by then, so each is the PING frame A.9 names as
    /// the last resort: a packet the peer must acknowledge and nothing more.
    fn send_probes(run: *Run, count: u8) Violation!void {
        // Bounded by the count, which is at most `probe_packets`.
        for (0..count) |_| {
            if (run.next_number >= numbers_max) return;
            try run.send_one(.probe);
            run.result.probes += 1;
        }
    }

    /// Sends while the window, the pacer and the table all allow it.
    fn send_while_allowed(run: *Run) Violation!void {
        run.storage.sender.pacer.refill(run.now_ns, run.storage.sender.rate());
        // Bounded by how many packets a seed sends.
        for (0..packets_per_seed) |_| {
            if (run.next_number >= packets_per_seed) return;
            if (run.storage.sender.available_len() < datagram_len) return;
            try run.send_one(.data);
        }
    }

    /// Whether a packet carries data or is a Probe Timeout's probe, which RFC 9002 §7.5 exempts
    /// from the congestion window.
    const Purpose = enum { data, probe };

    /// Puts one ack-eliciting packet on the path.
    fn send_one(run: *Run, purpose: Purpose) Violation!void {
        const number = run.next_number;
        var writer = Writer.init(&run.storage.datagram);
        writer.write_byte(kind_data) catch return Violation.DatagramNotRead;
        writer.write_int(u64, number) catch return Violation.DatagramNotRead;
        // RFC 9000 §14.1: an ack-eliciting packet fills a datagram of at least 1200 octets.
        // Bounded by the datagram, which is a named limit.
        while (writer.written().len < datagram_len) {
            writer.write_byte(0) catch return Violation.DatagramNotRead;
        }
        // RFC 9002 §7.5: a probe MUST NOT be blocked by the congestion controller, and §7.5 says
        // in the same paragraph that sending one may put the octets in flight past the window.
        const congestion = &run.storage.sender.congestion;
        const over = run.storage.sender.in_flight_len() +| datagram_len > congestion.window;
        if (purpose == .data and over) return Violation.WindowExceeded;
        const record: Record = .{
            .number = number,
            .sent_at_ns = run.now_ns,
            .sent_len = datagram_len,
            .ack_eliciting = true,
            .in_flight = true,
        };
        run.storage.sender.on_packet_sent(.application, record, run.now_ns) catch return;
        run.storage.outstanding[number] = true;
        run.next_number += 1;
        run.result.sent += 1;
        try run.put(.client, writer.written());
    }

    /// Hands a datagram to the network, unless the path is swallowing them.
    fn put(run: *Run, from: sim.network.Endpoint, octets: []const u8) Violation!void {
        run.digest.update(octets);
        if (run.is_blackholed()) return;
        const sent = run.storage.network.send(run.now_ns, from, octets, .not_ect);
        if (sent == .no_slot) return Violation.NetworkFull;
    }

    fn is_blackholed(run: *const Run) bool {
        if (run.scenario != .blackhole) return false;
        return run.now_ns >= start_ns + blackhole_from_ns and run.now_ns < start_ns + blackhole_until_ns;
    }

    /// Records that the packets an ACK newly named are accounted for. RFC 9000 §13.2.1 has an
    /// endpoint repeat ranges it has already sent, so a number the harness no longer holds
    /// outstanding is a repeat and not a second account.
    fn settle_acknowledged(run: *Run, ack: quic.frame_ack.Ack) Violation!void {
        var walk = ack.ranges.iterator();
        // Bounded by the frame's own ACK Range Count.
        while (walk.next()) |range| {
            var number = range.smallest;
            // Bounded by how many packets a seed sends.
            while (number <= range.largest and number < numbers_max) : (number += 1) {
                if (run.storage.outstanding[number]) try run.settle(number);
            }
        }
    }

    /// The same for the packets one detection pass declared lost.
    fn settle_lost(run: *Run, written: usize) Violation!void {
        // Bounded by the caller's slice, which is the table's own named capacity.
        for (run.storage.lost[0..written]) |held| {
            try run.settle(held.number);
            run.result.lost += 1;
        }
    }

    /// RFC 9002 §6.1: a packet leaves `sent_packets` once, so it is accounted for once. A second
    /// account means it was declared lost after being acknowledged, or declared lost twice.
    fn settle(run: *Run, number: u64) Violation!void {
        assert(number < numbers_max);
        if (run.storage.settled[number]) return Violation.PacketCountedTwice;
        run.storage.settled[number] = true;
        run.storage.outstanding[number] = false;
    }

    fn check_invariants(run: *Run) Violation!void {
        const congestion = &run.storage.sender.congestion;
        // RFC 9002 §7.2: the window never falls under two maximum datagrams, whatever the path
        // does, so a sender always has something to probe with.
        if (congestion.window < congestion.minimum_window()) return Violation.WindowUnderMinimum;
        run.result.window_min = @min(run.result.window_min, congestion.window);
    }

    fn finish(run: *Run) Violation!Result {
        if (run.storage.sender.in_flight_len() != 0) return Violation.NotDrained;
        var result = run.result;
        result.window = run.storage.sender.congestion.window;
        result.smoothed_rtt_ns = if (run.storage.sender.rtt.has_sample()) run.storage.sender.rtt.smoothed_ns else 0;
        result.octets_crc32 = run.digest.final();
        return result;
    }
};

/// RFC 9000 §18.2: the ACK Delay field is in microseconds scaled by the exponent.
fn delay_unit_ns() u64 {
    return quic.constants.nanoseconds_per_microsecond * (@as(u64, 1) << ack_delay_exponent);
}

/// The network's codepoint as the space names it (RFC 9000 §13.4).
fn space_ecn(ecn: sim.network.Ecn) Space.Ecn {
    return switch (ecn) {
        .not_ect => .not_ect,
        .ect_0 => .ect_0,
        .ect_1 => .ect_1,
        .ecn_ce => .ecn_ce,
    };
}
