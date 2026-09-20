//! The datagram network of design §8 step 8: what a QUIC endpoint's caller would hand it, made
//! deterministic. A run's delays, drops, reorderings, duplications and ECN markings are a pure
//! function of its seed, so a failure on one seed is a failure anyone can replay (invariant 5).
//!
//! It carries datagrams between two endpoints over the clock of step 2. A datagram sent at one
//! instant arrives at another, and the network decides which by drawing from a `Schedule` the
//! caller fixes before the run. Nothing here reads a clock: the instant is a parameter, as it is
//! everywhere else (design §4.2).
//!
//! Reordering is not a separate draw. Each datagram gets its own delay, so one sent later and
//! delayed less overtakes one sent earlier, which is what a network does; `Census` counts how
//! often it happened, and the check requires that it happened. Two datagrams that arrive at the
//! same instant are delivered in the order they were sent, which is what makes one seed replay:
//! without that tie-break the delivery order would follow the array's layout.
//!
//! What it does not model is as important as what it does. There is no bandwidth, no queue
//! length, no path MTU and no congestion, so a datagram is never dropped for being too large or
//! too frequent. RFC 9002's congestion control is step 10's, and it is driven by acknowledgments
//! and loss, both of which this network produces. A network that also modelled a bottleneck would
//! decide the answers step 10 must compute.
//!
//! It allocates nothing: the datagrams in flight are a fixed array the caller places
//! (decision 35), and a send with no free slot is refused rather than queued.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Random = @import("random.zig").Random;

/// Which endpoint of the network a datagram came from or goes to. The network carries datagrams
/// between exactly two, because a QUIC connection has two ends; connection migration is
/// step 9's and moves a path, not an endpoint.
pub const Endpoint = enum(u1) {
    client,
    server,

    /// How many there are, which sizes the arrays a network and a check hold one of per endpoint.
    pub const count = @typeInfo(Endpoint).@"enum".fields.len;

    pub fn peer(endpoint: Endpoint) Endpoint {
        return if (endpoint == .client) .server else .client;
    }
};

/// The ECN field of the IP header a datagram travelled in (RFC 9000 §13.4). The names are the
/// ones §13.4 uses; the two bits each stands for are RFC 3168's, which colibri never writes,
/// because the field belongs to the IP header its caller owns and not to any QUIC packet.
pub const Ecn = enum {
    not_ect,
    ect_0,
    ect_1,
    /// RFC 9000 §13.4: a network node indicates congestion by setting this codepoint instead of
    /// dropping the datagram.
    ecn_ce,

    /// Whether the sender asked for ECN treatment, which is what a node may answer with
    /// congestion (RFC 9000 §13.4).
    pub fn is_ect(ecn: Ecn) bool {
        return ecn == .ect_0 or ecn == .ect_1;
    }
};

/// How the network treats a run's datagrams. Every field is a count out of
/// `schedule_denominator`, so a schedule of all zeros is a perfect network and the delays alone
/// remain. The caller fixes it before the run and the network never changes it.
pub const Schedule = struct {
    /// Datagrams dropped, out of `schedule_denominator`.
    drop: u32 = 0,
    /// Datagrams delivered a second time, each copy with a delay of its own (RFC 9000 §13.3 has
    /// an endpoint prepared for a packet it has already received).
    duplicate: u32 = 0,
    /// Datagrams whose ECT codepoint a node changes to ECN-CE (RFC 9000 §13.4). A datagram sent
    /// Not-ECT is never marked: a node that did so would be breaking the field's meaning, and
    /// RFC 9000 §13.4.2's validation exists for networks that do.
    mark_congestion: u32 = 0,
    /// The delay one datagram takes, in nanoseconds, drawn from `[delay_min_ns, delay_max_ns]`.
    /// A range wider than one endpoint's sending interval is what produces reordering.
    delay_min_ns: u64 = constants.network_delay_min_ns,
    delay_max_ns: u64 = constants.network_delay_max_ns,

    /// Asserts the schedule is one the network can draw from.
    pub fn validate(schedule: Schedule) void {
        assert(schedule.drop <= constants.schedule_denominator);
        assert(schedule.duplicate <= constants.schedule_denominator);
        assert(schedule.mark_congestion <= constants.schedule_denominator);
        assert(schedule.delay_min_ns <= schedule.delay_max_ns);
    }
};

/// One datagram the network holds until its arrival instant.
const InFlight = struct {
    /// Whether this slot holds a datagram.
    live: bool = false,
    to: Endpoint = .client,
    /// The instant the receiver may take it (design §4.2).
    arrival_ns: u64 = 0,
    /// The order it was sent in. It breaks a tie between two datagrams arriving at one instant,
    /// so delivery is a total order and not the array's layout.
    sequence: u64 = 0,
    ecn: Ecn = .not_ect,
    len: usize = 0,
    octets: [constants.network_datagram_len_max]u8 = @splat(0),
};

/// A datagram the network gave to an endpoint.
pub const Delivery = struct {
    from: Endpoint,
    /// Valid until the next call on the network.
    octets: []const u8,
    ecn: Ecn,
    arrival_ns: u64,
    sequence: u64,
};

/// What one send did.
pub const Sent = enum {
    /// The datagram is in flight, and `Census` says whether a copy is too.
    queued,
    /// The network dropped it, which a sender cannot tell from one lost later.
    dropped,
    /// Every slot is full. It is not a network event: the caller is sending faster than the run
    /// gives the receiver a chance to read, and a check treats it as a harness defect.
    no_slot,
};

/// What the network counted, which a check compares across build modes and hosts.
pub const Census = struct {
    sent: u64 = 0,
    delivered: u64 = 0,
    dropped: u64 = 0,
    duplicated: u64 = 0,
    marked_congestion: u64 = 0,
    /// Deliveries that arrived after a datagram sent later than they were.
    reordered: u64 = 0,
    octets: u64 = 0,
};

/// The network, in storage the caller places (decision 35).
pub const Network = struct {
    schedule: Schedule,
    random: Random,
    in_flight: [constants.network_in_flight_max]InFlight,
    /// The order the next datagram is sent in.
    next_sequence: u64,
    /// The highest sequence delivered to each endpoint, which says when one is reordered.
    highest_delivered: [Endpoint.count]u64,
    census: Census,

    /// A network that holds nothing, drawing from `seed`. Every field is written, so no read of
    /// this struct sees a value the caller did not choose (invariant 6).
    pub fn init(network: *Network, seed: u64, schedule: Schedule) void {
        schedule.validate();
        network.schedule = schedule;
        network.random = Random.init(seed);
        network.in_flight = @splat(.{});
        network.next_sequence = 0;
        network.highest_delivered = @splat(0);
        network.census = .{};
    }

    /// Hands a datagram to the network. `now_ns` is the instant it left the sender, and every
    /// draw for it is made here, so a datagram's fate does not depend on when it is collected.
    pub fn send(network: *Network, now_ns: u64, from: Endpoint, octets: []const u8, ecn: Ecn) Sent {
        assert(octets.len > 0 and octets.len <= constants.network_datagram_len_max);
        network.census.sent += 1;
        network.census.octets += octets.len;
        // RFC 9000 §13.4: a node that drops a datagram and one that marks it are the same node,
        // so the draw that drops comes first and a dropped datagram is never marked.
        if (network.draws(network.schedule.drop)) {
            network.census.dropped += 1;
            return .dropped;
        }
        if (!network.queue(now_ns, from.peer(), octets, network.mark(ecn))) return .no_slot;
        // A duplicate is a second datagram with its own delay, so it may arrive before the first.
        if (network.draws(network.schedule.duplicate)) {
            if (network.queue(now_ns, from.peer(), octets, network.mark(ecn))) {
                network.census.duplicated += 1;
            }
        }
        return .queued;
    }

    /// The next datagram due for `to` at or before `now_ns`, or null when none is. A caller reads
    /// until it answers null, which is what a socket that has nothing to give answers.
    pub fn receive(network: *Network, now_ns: u64, to: Endpoint) ?Delivery {
        const index = network.next_due(to, now_ns) orelse return null;
        const held = &network.in_flight[index];
        const sequence = held.sequence;
        // A datagram sent after one already delivered, but delivered before it, is a reordering.
        const highest = &network.highest_delivered[@intFromEnum(to)];
        if (sequence < highest.*) network.census.reordered += 1;
        highest.* = @max(highest.*, sequence);
        held.live = false;
        network.census.delivered += 1;
        return .{
            .from = to.peer(),
            .octets = held.octets[0..held.len],
            .ecn = held.ecn,
            .arrival_ns = held.arrival_ns,
            .sequence = sequence,
        };
    }

    /// The instant the next datagram in flight arrives, or null when none is. A driver advances
    /// its clock to this when neither endpoint has anything else to do, which is what makes a run
    /// finish rather than idle (design §4.2).
    pub fn next_arrival_ns(network: *const Network) ?u64 {
        var earliest: ?u64 = null;
        for (&network.in_flight) |*held| {
            if (!held.live) continue;
            if (earliest == null or held.arrival_ns < earliest.?) earliest = held.arrival_ns;
        }
        return earliest;
    }

    /// How many datagrams are in flight, which a check asserts is zero once a run has drained.
    pub fn in_flight_count(network: *const Network) usize {
        var count: usize = 0;
        for (&network.in_flight) |*held| {
            if (held.live) count += 1;
        }
        return count;
    }

    /// Whether a draw of `count` out of `schedule_denominator` came up.
    fn draws(network: *Network, count: u32) bool {
        return network.random.below(constants.schedule_denominator) < count;
    }

    /// The codepoint a datagram arrives with. RFC 9000 §13.4: a node indicates congestion by
    /// setting ECN-CE, and only a datagram the sender marked ECT is eligible.
    fn mark(network: *Network, ecn: Ecn) Ecn {
        if (!ecn.is_ect()) return ecn;
        if (!network.draws(network.schedule.mark_congestion)) return ecn;
        network.census.marked_congestion += 1;
        return .ecn_ce;
    }

    /// Puts one datagram in flight. False when every slot is full.
    fn queue(network: *Network, now_ns: u64, to: Endpoint, octets: []const u8, ecn: Ecn) bool {
        const delay_ns = network.random.between(network.schedule.delay_min_ns, network.schedule.delay_max_ns);
        const held = network.free_slot() orelse return false;
        held.* = .{
            .live = true,
            .to = to,
            .arrival_ns = now_ns + delay_ns,
            .sequence = network.next_sequence,
            .ecn = ecn,
            .len = octets.len,
        };
        @memcpy(held.octets[0..octets.len], octets);
        network.next_sequence += 1;
        return true;
    }

    fn free_slot(network: *Network) ?*InFlight {
        for (&network.in_flight) |*held| {
            if (!held.live) return held;
        }
        return null;
    }

    /// The slot holding the datagram `to` takes next: the earliest arrival, and among those the
    /// lowest sequence, so the order is total and the same on every host.
    fn next_due(network: *const Network, to: Endpoint, now_ns: u64) ?usize {
        var due: ?usize = null;
        for (&network.in_flight, 0..) |*held, index| {
            if (!held.live or held.to != to or held.arrival_ns > now_ns) continue;
            const best = if (due) |found| &network.in_flight[found] else {
                due = index;
                continue;
            };
            const earlier = held.arrival_ns < best.arrival_ns;
            const tied_and_older = held.arrival_ns == best.arrival_ns and held.sequence < best.sequence;
            if (earlier or tied_and_older) due = index;
        }
        return due;
    }
};

const testing = std.testing;

/// The network the tests drive, placed outside any stack frame: it holds every datagram in
/// flight. Test-only.
var test_network: Network = undefined;

/// A schedule with no drops, no duplicates and no marking, whose delay is fixed. Test-only.
fn fixed_delay(delay_ns: u64) Schedule {
    return .{ .delay_min_ns = delay_ns, .delay_max_ns = delay_ns };
}

/// Sends `octets` from the client at `now_ns` and requires the network to take it. Test-only.
fn send_ok(now_ns: u64, octets: []const u8) !void {
    try testing.expectEqual(Sent.queued, test_network.send(now_ns, .client, octets, .not_ect));
}

test "a datagram arrives at its delay and not before, and only at the other endpoint" {
    test_network.init(0, fixed_delay(10));
    try send_ok(100, "one");
    try testing.expectEqual(110, test_network.next_arrival_ns().?);
    // Before the arrival instant the receiver has nothing, and it is never the sender's.
    try testing.expectEqual(null, test_network.receive(109, .server));
    try testing.expectEqual(null, test_network.receive(1_000, .client));
    const delivery = test_network.receive(110, .server).?;
    try testing.expectEqualStrings("one", delivery.octets);
    try testing.expectEqual(Endpoint.client, delivery.from);
    try testing.expectEqual(110, delivery.arrival_ns);
    // It is delivered once, and nothing is left in flight.
    try testing.expectEqual(null, test_network.receive(1_000, .server));
    try testing.expectEqual(null, test_network.next_arrival_ns());
    try testing.expectEqual(0, test_network.in_flight_count());
    try testing.expectEqual(1, test_network.census.delivered);
}

test "a datagram sent later and delayed less arrives first, and the reordering is counted" {
    test_network.init(0, .{ .delay_min_ns = 10, .delay_max_ns = 10 });
    try send_ok(0, "first");
    // The second is sent later and takes less time, so it overtakes.
    test_network.schedule = .{ .delay_min_ns = 1, .delay_max_ns = 1 };
    try send_ok(1, "second");
    try testing.expectEqualStrings("second", test_network.receive(10, .server).?.octets);
    try testing.expectEqualStrings("first", test_network.receive(10, .server).?.octets);
    try testing.expectEqual(1, test_network.census.reordered);
}

test "two datagrams that arrive at one instant are delivered in the order they were sent" {
    test_network.init(0, fixed_delay(10));
    try send_ok(0, "a");
    try send_ok(0, "b");
    try send_ok(0, "c");
    // The order is the sequence, whatever slots the three landed in.
    try testing.expectEqualStrings("a", test_network.receive(10, .server).?.octets);
    try testing.expectEqualStrings("b", test_network.receive(10, .server).?.octets);
    try testing.expectEqualStrings("c", test_network.receive(10, .server).?.octets);
    try testing.expectEqual(0, test_network.census.reordered);
}

test "a slot freed and filled again does not decide the delivery order" {
    test_network.init(0, fixed_delay(10));
    try send_ok(0, "a");
    // The second arrives at once, freeing the slot between the first and the third.
    test_network.schedule = fixed_delay(1);
    try send_ok(0, "early");
    test_network.schedule = fixed_delay(10);
    try send_ok(0, "c");
    try testing.expectEqualStrings("early", test_network.receive(1, .server).?.octets);
    // The fourth takes the freed slot, so the array now holds a, d, c and the sequence a, c, d.
    test_network.schedule = fixed_delay(9);
    try send_ok(1, "d");
    try testing.expectEqualStrings("a", test_network.receive(10, .server).?.octets);
    try testing.expectEqualStrings("c", test_network.receive(10, .server).?.octets);
    try testing.expectEqualStrings("d", test_network.receive(10, .server).?.octets);
}

test "the highest sequence delivered never goes backward, and each endpoint keeps its own" {
    test_network.init(0, fixed_delay(30));
    try send_ok(0, "last sent");
    try send_ok(0, "first sent");
    try send_ok(0, "second sent");
    // Delivered in the order 2, 0, 1. Both of the last two are behind the highest sequence seen,
    // and the third is behind it only because the second did not pull the record down.
    test_network.in_flight[2].arrival_ns = 10;
    test_network.in_flight[0].arrival_ns = 20;
    try testing.expectEqualStrings("second sent", test_network.receive(30, .server).?.octets);
    try testing.expectEqualStrings("last sent", test_network.receive(30, .server).?.octets);
    try testing.expectEqualStrings("first sent", test_network.receive(30, .server).?.octets);
    try testing.expectEqual(2, test_network.census.reordered);

    // Two datagrams to the server and one to the client, all sent at once. The client's is
    // behind the server's last only if the two endpoints share one record.
    test_network.init(0, fixed_delay(10));
    try send_ok(0, "to server");
    try testing.expectEqual(Sent.queued, test_network.send(0, .server, "to client", .not_ect));
    try send_ok(0, "to server again");
    try testing.expectEqualStrings("to server", test_network.receive(10, .server).?.octets);
    try testing.expectEqualStrings("to server again", test_network.receive(10, .server).?.octets);
    try testing.expectEqualStrings("to client", test_network.receive(10, .client).?.octets);
    try testing.expectEqual(0, test_network.census.reordered);
}

test "a dropped datagram never arrives, and a duplicated one arrives twice" {
    // Every draw comes up, so every datagram is dropped.
    test_network.init(0, .{ .drop = constants.schedule_denominator, .delay_min_ns = 1, .delay_max_ns = 1 });
    try testing.expectEqual(Sent.dropped, test_network.send(0, .client, "gone", .not_ect));
    try testing.expectEqual(null, test_network.receive(1_000, .server));
    try testing.expectEqual(1, test_network.census.dropped);
    try testing.expectEqual(0, test_network.census.delivered);

    test_network.init(0, .{ .duplicate = constants.schedule_denominator, .delay_min_ns = 1, .delay_max_ns = 1 });
    try send_ok(0, "twice");
    try testing.expectEqual(2, test_network.in_flight_count());
    try testing.expectEqualStrings("twice", test_network.receive(1, .server).?.octets);
    try testing.expectEqualStrings("twice", test_network.receive(1, .server).?.octets);
    try testing.expectEqual(null, test_network.receive(1_000, .server));
    try testing.expectEqual(1, test_network.census.duplicated);
    try testing.expectEqual(2, test_network.census.delivered);
}

test "§13.4: a node marks an ECT datagram with ECN-CE, and never one sent Not-ECT" {
    const always: Schedule = .{ .mark_congestion = constants.schedule_denominator, .delay_min_ns = 1, .delay_max_ns = 1 };
    test_network.init(0, always);
    for ([_]Ecn{ .ect_0, .ect_1 }) |sent| {
        try testing.expectEqual(Sent.queued, test_network.send(0, .client, "marked", sent));
        try testing.expectEqual(Ecn.ecn_ce, test_network.receive(1, .server).?.ecn);
    }
    try testing.expectEqual(2, test_network.census.marked_congestion);
    // RFC 9000 §13.4: the codepoint says the sender asked for ECN treatment, and Not-ECT did not.
    try testing.expectEqual(Sent.queued, test_network.send(0, .client, "plain", .not_ect));
    try testing.expectEqual(Ecn.not_ect, test_network.receive(1, .server).?.ecn);
    try testing.expectEqual(2, test_network.census.marked_congestion);
    // A schedule that marks nothing leaves an ECT datagram as it was.
    test_network.init(0, fixed_delay(1));
    try testing.expectEqual(Sent.queued, test_network.send(0, .client, "kept", .ect_0));
    try testing.expectEqual(Ecn.ect_0, test_network.receive(1, .server).?.ecn);
}

test "the network holds what it was built for and refuses a send past it" {
    test_network.init(0, fixed_delay(1_000));
    for (0..constants.network_in_flight_max) |index| {
        try send_ok(index, "held");
    }
    try testing.expectEqual(constants.network_in_flight_max, test_network.in_flight_count());
    try testing.expectEqual(Sent.no_slot, test_network.send(0, .client, "one too many", .not_ect));
    // A slot freed by a delivery takes the next one.
    _ = test_network.receive(2_000, .server).?;
    try send_ok(0, "fits now");
}

test "one seed replays, and another draws a different run" {
    const schedule: Schedule = .{ .drop = 100, .duplicate = 100, .mark_congestion = 200 };
    var first: Census = undefined;
    for (0..2) |_| {
        test_network.init(0xc0ffee, schedule);
        first = drain_run();
    }
    const repeated = first;
    test_network.init(0xc0ffee, schedule);
    try testing.expectEqual(repeated, drain_run());
    test_network.init(0xc0ffef, schedule);
    try testing.expect(!std.meta.eql(repeated, drain_run()));
    // The run exercised every event the schedule permits.
    try testing.expect(repeated.dropped > 0 and repeated.duplicated > 0);
    try testing.expect(repeated.marked_congestion > 0 and repeated.reordered > 0);
    try testing.expectEqual(repeated.sent + repeated.duplicated - repeated.dropped, repeated.delivered);
}

/// Sends from both endpoints and reads everything, advancing the clock to each arrival, and
/// returns what the network counted. Test-only.
fn drain_run() Census {
    var now_ns: u64 = 0;
    for (0..test_replay_datagrams) |index| {
        const from: Endpoint = if (index % Endpoint.count == 0) .client else .server;
        _ = test_network.send(now_ns, from, "payload", .ect_0);
        now_ns += test_replay_step_ns;
        drain_endpoint(now_ns, from.peer());
    }
    // Everything still in flight arrives, so no run ends with a datagram held. Each pass takes at
    // least one datagram, so the slots bound the loop (non-negotiable 4).
    for (0..constants.network_in_flight_max + 1) |_| {
        const arrival_ns = test_network.next_arrival_ns() orelse break;
        now_ns = @max(now_ns, arrival_ns);
        for ([_]Endpoint{ .client, .server }) |to| drain_endpoint(now_ns, to);
    }
    assert(test_network.in_flight_count() == 0);
    return test_network.census;
}

/// Takes every datagram due for `to`, bounded by the slots the network has. Test-only.
fn drain_endpoint(now_ns: u64, to: Endpoint) void {
    for (0..constants.network_in_flight_max + 1) |_| {
        if (test_network.receive(now_ns, to) == null) return;
    }
    unreachable; // Each delivery frees a slot, so the network runs out first.
}

/// Datagrams one replay sends, and the interval between them: well under the delay range, so
/// several are in flight at once and reordering has room to happen. Test-only.
const test_replay_datagrams = 200;
const test_replay_step_ns = 2_000_000;
