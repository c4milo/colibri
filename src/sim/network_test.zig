//! The tests of `network.zig`.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const network_module = @import("network.zig");

const Network = network_module.Network;
const Schedule = network_module.Schedule;
const Sent = network_module.Sent;
const Ecn = network_module.Ecn;
const Endpoint = network_module.Endpoint;
const Census = network_module.Census;
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

test "a run of drops ends at drop_run_max, toward each endpoint on its own" {
    // Every draw comes up, so only the bound lets a datagram through.
    test_network.init(0, .{ .drop = constants.schedule_denominator, .drop_run_max = 3, .delay_min_ns = 1, .delay_max_ns = 1 });
    // Bounded by the run and the delivery that ends it.
    for (0..3) |_| try testing.expectEqual(Sent.dropped, test_network.send(0, .client, "gone", .not_ect));
    // The server's run is its own, so the client's three drops leave it at none.
    try testing.expectEqual(Sent.dropped, test_network.send(0, .server, "gone", .not_ect));
    try send_ok(0, "through");
    try testing.expectEqual(Sent.dropped, test_network.send(0, .client, "gone", .not_ect));
    try testing.expectEqualStrings("through", test_network.receive(1, .server).?.octets);
    try testing.expectEqual(5, test_network.census.dropped);

    // A delivery the draw decides ends a run too: two drops, a delivery, then three more drops.
    test_network.init(0, .{ .drop = constants.schedule_denominator, .drop_run_max = 3, .delay_min_ns = 1, .delay_max_ns = 1 });
    // Bounded by the run.
    for (0..2) |_| try testing.expectEqual(Sent.dropped, test_network.send(0, .client, "gone", .not_ect));
    test_network.schedule.drop = 0;
    try send_ok(0, "drawn");
    test_network.schedule.drop = constants.schedule_denominator;
    // Bounded by the run.
    for (0..3) |_| try testing.expectEqual(Sent.dropped, test_network.send(0, .client, "gone", .not_ect));
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
