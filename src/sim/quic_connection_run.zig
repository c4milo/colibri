//! The driver of the QUIC connection check: one seed's run of `quic_connection_check.zig`. It is a
//! file of its own because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//!
//! What it does each step: give each endpoint what the network delivered, fire whichever of its
//! deadlines have come, have it send until colibri owes nothing more, read invariants 17 to 21 off
//! both, and move time to the next instant anything is due at.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const constants = sim.constants;
const quic_endpoint = @import("quic_endpoint.zig");
const quic_invariants = @import("quic_invariants.zig");
const check = @import("quic_connection_check.zig");

const Random = sim.random.Random;
const Schedule = sim.network.Schedule;
const Side = sim.network.Endpoint;
const Result = check.Result;
const Storage = check.Storage;
const Violation = check.Violation;

/// Runs one seed and returns its counts.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    var random = Random.init(seed);
    storage.network.init(seed, draw_schedule(&random));
    storage.failure = null;
    // Bounded by the two sides of the network.
    for (std.enums.values(Side)) |side| {
        const at = @intFromEnum(side);
        storage.endpoints[at].init(role_of(side), check.start_ns);
        storage.histories[at].init(&storage.endpoints[at]);
    }
    apply_fault(storage);
    var run: Run = .{ .storage = storage, .now_ns = check.start_ns, .result = .{}, .digest = std.hash.Crc32.init() };
    // Bounded by `steps_max`, which is a named limit.
    for (0..check.steps_max) |_| {
        if (try run.step()) return run.finish();
    }
    return Violation.StepsExhausted;
}

/// Puts the defect a fault test asked for into the run (`check.Fault`).
fn apply_fault(storage: *Storage) void {
    const server = &storage.endpoints[@intFromEnum(Side.server)];
    switch (storage.fault) {
        .none => {},
        .server_alert => server.provider.fails_with = .handshake_failure,
        .keys_refused => server.suite.keys_unavailable = 1,
        .number_reused => storage.histories[@intFromEnum(Side.client)].largest_sent[@intFromEnum(quic.core.Level.initial)] = 0,
        .wrong_octet => storage.endpoints[@intFromEnum(Side.client)].supplies_wrong_octet = true,
    }
}

/// A seed's network: up to `drop_max` datagrams dropped and up to `duplicate_max` duplicated, out
/// of `schedule_denominator`, over the default delays, which reorder on their own.
fn draw_schedule(random: *Random) Schedule {
    return .{
        .drop = @intCast(random.below(check.drop_max + 1)),
        .duplicate = @intCast(random.below(check.duplicate_max + 1)),
    };
}

fn role_of(side: Side) quic.connection.Role {
    return switch (side) {
        .client => .client,
        .server => .server,
    };
}

/// One seed's driver.
const Run = struct {
    storage: *Storage,
    now_ns: u64,
    result: Result,
    digest: std.hash.Crc32,

    /// One step. Returns whether the run is over.
    fn step(run: *Run) Violation!bool {
        // Bounded by the two sides.
        for (std.enums.values(Side)) |side| try run.deliver(side);
        for (std.enums.values(Side)) |side| try run.fire(side);
        for (std.enums.values(Side)) |side| try run.send_owed(side);
        for (std.enums.values(Side)) |side| try run.storage.histories[@intFromEnum(side)].check(&run.storage.endpoints[@intFromEnum(side)]);
        run.result.steps += 1;
        if (run.is_done()) return true;
        run.now_ns = run.next_instant();
        return false;
    }

    /// Gives `side` every datagram the network has for it now.
    fn deliver(run: *Run, side: Side) Violation!void {
        const endpoint = &run.storage.endpoints[@intFromEnum(side)];
        // Bounded by the network's own slot count, which is a named limit.
        for (0..constants.network_in_flight_max) |_| {
            const delivery = run.storage.network.receive(run.now_ns, side) orelse return;
            run.storage.histories[@intFromEnum(side)].on_received(delivery.octets.len);
            endpoint.receive(delivery.octets, delivery.ecn, run.now_ns) catch |failure| return run.fail(failure);
        }
    }

    /// Fires `side`'s deadlines that have come (design §4.2).
    fn fire(run: *Run, side: Side) Violation!void {
        const endpoint = &run.storage.endpoints[@intFromEnum(side)];
        endpoint.on_instant(run.now_ns) catch |failure| return run.fail(failure);
    }

    /// Has `side` send until colibri owes nothing more now, and puts each datagram on the path.
    fn send_owed(run: *Run, side: Side) Violation!void {
        const at = @intFromEnum(side);
        const endpoint = &run.storage.endpoints[at];
        // Bounded by a named limit: the congestion window stops a sender long before it.
        for (0..check.sends_per_step_max) |_| {
            const sent = (endpoint.send(run.now_ns) catch |failure| return run.fail(failure)) orelse return;
            const octets = endpoint.output[0..sent.len];
            try run.storage.histories[at].on_sent(endpoint, sent, octets);
            run.digest.update(octets);
            run.result.datagrams += 1;
            run.result.packets += sent.count;
            // The endpoint marks no ECN codepoint (`connection_send` records every packet so).
            if (run.storage.network.send(run.now_ns, side, octets, .not_ect) == .no_slot) return Violation.NetworkFull;
        }
        return Violation.SendsExhausted;
    }

    /// The run is over once both endpoints have confirmed the handshake, the client's stream has
    /// been acknowledged whole and read whole, and nothing is left on the path.
    fn is_done(run: *const Run) bool {
        const client = &run.storage.endpoints[@intFromEnum(Side.client)];
        const server = &run.storage.endpoints[@intFromEnum(Side.server)];
        if (!client.connection.handshake_confirmed or !server.connection.handshake_confirmed) return false;
        if (!client.transfer_done or !server.transfer_read) return false;
        return run.storage.network.in_flight_count() == 0;
    }

    /// The next instant anything is due at: a datagram arriving or either endpoint's deadline.
    /// Never behind the current instant, and never more than `idle_step_ns` past it.
    fn next_instant(run: *Run) u64 {
        var at_ns: u64 = run.now_ns +| check.idle_step_ns;
        if (run.storage.network.next_arrival_ns()) |arrival_ns| at_ns = @min(at_ns, arrival_ns);
        // Bounded by the two sides.
        for (&run.storage.endpoints) |*endpoint| {
            if (endpoint.next_deadline_ns()) |deadline_ns| at_ns = @min(at_ns, deadline_ns);
        }
        return @max(at_ns, run.now_ns +| 1);
    }

    /// Keeps the error an endpoint stopped with, for the trace, and ends the run.
    fn fail(run: *Run, failure: quic_endpoint.Error) Violation {
        run.storage.failure = failure;
        return Violation.ConnectionError;
    }

    fn finish(run: *Run) Result {
        var result = run.result;
        result.finished_ns = run.now_ns - check.start_ns;
        result.octets_crc32 = run.digest.final();
        const client = &run.storage.endpoints[@intFromEnum(Side.client)];
        result.round_trip_ns = client.connection.recovery.rtt.smoothed_ns;
        return result;
    }
};
