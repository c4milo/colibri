//! The h3 check of design §8 step 12: a colibri client and a colibri server exchange a seed's
//! requests and responses over the datagram network of step 8, which drops, duplicates and
//! reorders by seed.
//!
//! Each endpoint is `h3_endpoint.zig`'s: step 9e's QUIC endpoint with the null provider and suite,
//! and an h3 connection over it. Each seed draws both endpoints' QPACK settings and grease values
//! and up to `h3_check_exchanges_max` exchanges (`h3_plan.zig`). The run passes when the client
//! has read every response to its end, each field section and content octet as the plan has it,
//! and the connection then settles within `h3_check_settle_steps_max` steps:
//! - every request stream's slot is free again on both sides;
//! - no field section waits on the QPACK dynamic table (RFC 9204 §2.2.1);
//! - neither decoder owes an instruction, and each encoder's Known Received Count has reached its
//!   insert count (RFC 9204 §2.1.4), which colibri's decoder reports in full (decision 74).
//!
//! Each seed runs twice and must send the same datagrams, which is invariant 5.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const h3_plan = @import("h3_plan.zig");
const h3_endpoint = @import("h3_endpoint.zig");
const quic_endpoint = @import("quic_endpoint.zig");

const Random = sim.random.Random;
pub const Shape = h3_plan.Shape;
const Side = sim.network.Endpoint;
const constants = sim.constants;

/// The digest of every seed's run, committed after both build modes agree on it.
pub const census_crc32_expected: u32 = 0xdacf68d7;
pub const long_census_crc32_expected: u32 = 0xb2ba117a;

pub const Violation = h3_endpoint.Error || error{
    /// The network was asked to carry a datagram and had no slot, which is a harness defect.
    NetworkFull,
    /// An endpoint was still sending at the bound on one step's sends.
    SendsExhausted,
    /// The run hit its step bound before the client read every response.
    StepsExhausted,
    /// The connection did not settle after the client read every response: a slot, a blocked
    /// section or an owed instruction was left, or an insert was never acknowledged.
    Unsettled,
    /// The seed's second run sent different datagrams from its first (invariant 5).
    ReplayDiverged,
};

/// The storage one seed runs in, placed outside any stack frame (decision 35).
pub const Storage = struct {
    /// Whether the seeds are the normal check's or the long check's.
    shape: h3_plan.Shape,
    plan: h3_plan.Plan,
    network: sim.Network,
    endpoints: [Side.count]h3_endpoint.Endpoint,
};

/// One seed's counts.
pub const Result = struct {
    datagrams: u64 = 0,
    octets_crc32: u32 = 0,
    exchanges: u64 = 0,
    content_len: u64 = 0,
    /// Entries each endpoint's QPACK encoder inserted (RFC 9204 §3.2).
    inserts: u64 = 0,
    /// Octets of h3's own streams dropped once the peer acknowledged them (decision 78).
    acknowledged_dropped: u64 = 0,
};

pub const Census = struct {
    seeds: u64 = 0,
    datagrams: u64 = 0,
    exchanges: u64 = 0,
    content_len: u64 = 0,
    inserts: u64 = 0,
    acknowledged_dropped: u64 = 0,
    dropped: u64 = 0,
    crc32: std.hash.Crc32 = .init(),

    fn count(census: *Census, storage: *const Storage, result: Result) void {
        census.seeds += 1;
        census.datagrams += result.datagrams;
        census.exchanges += result.exchanges;
        census.content_len += result.content_len;
        census.inserts += result.inserts;
        census.acknowledged_dropped += result.acknowledged_dropped;
        census.dropped += storage.network.census.dropped;
        var octets: [@sizeOf(u32)]u8 = undefined;
        std.mem.writeInt(u32, &octets, result.octets_crc32, .big);
        census.crc32.update(&octets);
    }
};

/// The instant a run starts, and the longest step it takes when nothing is due sooner.
const start_ns: u64 = 1_000_000;
const idle_step_ns: u64 = 10_000_000;

/// Runs one seed twice and returns the first run's counts.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    const first = try run_once(storage, seed);
    const second = try run_once(storage, seed);
    if (first.octets_crc32 != second.octets_crc32 or first.datagrams != second.datagrams) return error.ReplayDiverged;
    return first;
}

fn run_once(storage: *Storage, seed: u64) Violation!Result {
    var random = Random.init(seed);
    storage.plan.draw(&random, storage.shape);
    storage.network.init(seed, .{
        .drop = @intCast(random.below(constants.h3_check_drop_max + 1)),
        .duplicate = @intCast(random.below(constants.h3_check_duplicate_max + 1)),
    });
    for (std.enums.values(Side)) |side| {
        const role: quic.connection.Role = if (side == .client) .client else .server;
        storage.endpoints[@intFromEnum(side)].init(role, &storage.plan, start_ns);
    }
    var run: Run = .{ .storage = storage, .now_ns = start_ns, .digest = .init() };
    // Bounded by a named limit.
    for (0..constants.h3_check_steps_max) |_| {
        try run.step();
        if (run.endpoint(.client).finished()) break;
    } else return error.StepsExhausted;
    // Bounded by a named limit.
    for (0..constants.h3_check_settle_steps_max) |_| {
        if (settled(storage)) return run.finish();
        try run.step();
    }
    return error.Unsettled;
}

const Run = struct {
    storage: *Storage,
    now_ns: u64,
    digest: std.hash.Crc32,
    datagrams: u64 = 0,

    fn endpoint(run: *Run, side: Side) *h3_endpoint.Endpoint {
        return &run.storage.endpoints[@intFromEnum(side)];
    }

    /// One step: deliver, fire deadlines, let each caller act, send, and move time on.
    fn step(run: *Run) Violation!void {
        for (std.enums.values(Side)) |side| try run.deliver(side);
        for (std.enums.values(Side)) |side| try run.endpoint(side).transport.on_instant(run.now_ns);
        for (std.enums.values(Side)) |side| try run.endpoint(side).step();
        for (std.enums.values(Side)) |side| try run.send_owed(side);
        run.now_ns = run.next_instant();
    }

    fn deliver(run: *Run, side: Side) Violation!void {
        const held = run.endpoint(side);
        // Bounded by the network's own slot count, which is a named limit.
        for (0..constants.network_in_flight_max) |_| {
            const delivery = run.storage.network.receive(run.now_ns, side) orelse return;
            try held.transport.receive(delivery.octets, delivery.ecn, delivery.from_address, run.now_ns);
        }
    }

    fn send_owed(run: *Run, side: Side) Violation!void {
        const held = run.endpoint(side);
        // Bounded by a named limit: the congestion window stops a sender long before it.
        for (0..constants.h3_check_sends_per_step_max) |_| {
            const sent = try held.transport.send(run.now_ns) orelse return;
            const octets = held.transport.output[0..sent.len];
            run.digest.update(octets);
            run.datagrams += 1;
            const to = quic_endpoint.network_address(sent.to);
            if (run.storage.network.send_to(run.now_ns, side, octets, quic_endpoint.network_ecn(sent.ecn), to) == .no_slot) return error.NetworkFull;
        }
        return error.SendsExhausted;
    }

    fn next_instant(run: *Run) u64 {
        var at_ns: u64 = run.now_ns +| idle_step_ns;
        if (run.storage.network.next_arrival_ns()) |arrival_ns| at_ns = @min(at_ns, arrival_ns);
        for (&run.storage.endpoints) |*held| {
            if (held.transport.next_deadline_ns()) |deadline_ns| at_ns = @min(at_ns, deadline_ns);
        }
        return @max(at_ns, run.now_ns +| 1);
    }

    fn finish(run: *Run) Violation!Result {
        var result: Result = .{ .datagrams = run.datagrams, .octets_crc32 = run.digest.final(), .exchanges = run.storage.plan.len };
        for (&run.storage.endpoints) |*held| {
            const local = &held.h3.local;
            result.inserts += held.h3.encoder.table.insert_count();
            result.acknowledged_dropped += local.control.start_offset + local.encoder.start_offset + local.decoder.start_offset;
        }
        for (run.storage.plan.exchanges[0..run.storage.plan.len]) |exchange| {
            result.content_len += exchange.request.content_len + exchange.response.content_len;
        }
        return result;
    }
};

/// Whether both endpoints have settled: no request stream holds a slot, no field section waits
/// on the dynamic table, no decoder owes an instruction, and every insert is acknowledged.
fn settled(storage: *const Storage) bool {
    for (&storage.endpoints) |*held| {
        const connection = &held.h3;
        for (connection.requests.slots) |slot| {
            if (slot != null) return false;
        }
        if (connection.decoder.blocked_len != 0 or connection.decoder.owes()) return false;
        if (connection.encoder.state.known_received != connection.encoder.table.insert_count()) return false;
    }
    return true;
}

/// Runs seeds `[0, seeds)` in order. On a violation, `failed_seed` names the seed.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        census.count(storage, try run_seed(storage, seed));
    }
    failed_seed.* = null;
    assert(census.seeds == seeds);
}

const testing = std.testing;

/// The storage the check test runs in, placed outside any stack frame.
var test_storage: Storage = undefined;

test "h3 check: every seed's exchanges arrive as planned over a lossy network, and replay" {
    test_storage.shape = .normal;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("h3 check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // The seeds used the dynamic table and lost datagrams, so the check proved both.
    try testing.expect(census.inserts > 0);
    try testing.expect(census.dropped > 0);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}

test "h3 long check: long connections outgrow h3's own buffers, which drop what was acknowledged" {
    test_storage.shape = .long;
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.h3_long_check_seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h3 long check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // Decision 78 ran: h3 dropped octets of its own streams once the peer acknowledged them.
    try testing.expect(census.acknowledged_dropped > 0);
    try testing.expect(census.dropped > 0);
    try testing.expectEqual(long_census_crc32_expected, census.crc32.final());
}
