//! The tests of `connection_timer.zig`: which deadline is nearest, and what firing it does.
//!
//! Each case arms one timer through the piece that owns it and reads the answer back, because
//! what this file joins is five rules that already had their own tests.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const key_update = @import("connection_key_update.zig");
const timer = @import("connection_timer.zig");
const connection_recovery = @import("connection_recovery.zig");
const Kind = @import("../space/space.zig").Kind;
const build_test = @import("packet_build/packet_build_test.zig");

const testing = std.testing;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

var test_connection: Connection = undefined;
var suite_holder: build_test.RoundTrip = undefined;
/// Where the loss timer's lost packets go (decision 59). Test-only.
var recovery_scratch: connection_recovery.Scratch = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
/// RFC 9000 §18.2's max_idle_timeout, as a value a test can see arrive.
const idle_timeout_ms: u64 = 30_000;
const idle_timeout_ns: u64 = idle_timeout_ms * constants.nanoseconds_per_millisecond;
/// RFC 9000 §18.2: "the default value is 25 milliseconds", which is what a connection that set
/// nothing else promises.
const default_max_ack_delay_ms: u64 = 25;
/// A PATH_CHALLENGE timeout short enough to be the nearest deadline (RFC 9000 §8.2.4).
const challenge_timeout_ns: u64 = 5_000_000;
const challenge_octet: u8 = 0x9c;
const challenge_data: [constants.path_challenge_len]u8 = @splat(challenge_octet);

const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const id_len: usize = 4;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

fn open_connection(idle_ms: u64) void {
    suite_holder.init();
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    held.max_idle_timeout_ms = idle_ms;
    test_connection.init(.{
        .role = .client,
        .local_parameters = held,
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    // RFC 9002 Appendix A.8 arms an anti-deadlock probe until the peer has validated this
    // endpoint's address, which would be the nearest deadline in every case below. A Handshake
    // ACK is what tells a client so ("has received Handshake ACK"). The case that is about that
    // probe takes it back.
    acknowledge_handshake(0);
}

fn next() ?timer.Deadline {
    return timer.next(&test_connection);
}

fn fire(now_ns: u64) !timer.Fired {
    return timer.on_instant(&test_connection, suite_holder.suite(), &recovery_scratch, now_ns);
}

/// Records that the peer acknowledged Handshake packet `number`, or nothing when null.
fn acknowledge_handshake(number: ?u64) void {
    test_connection.recovery.largest_acknowledged[@intFromEnum(Kind.handshake)] = number;
}

/// RFC 9001 §6.5's period, which the key update's own deadline is measured in.
fn three_probe_timeouts_ns() u64 {
    return constants.key_update_probe_timeouts * test_connection.recovery.rtt.probe_timeout_ns(true);
}

test "RFC 9002 Appendix A.8: a client arms a probe until the peer has validated its address" {
    open_connection(0);
    // "PeerCompletedAddressValidation": until it holds, a client with nothing outstanding still
    // sets a timer, so a handshake cannot deadlock on a lost first flight.
    acknowledge_handshake(null);
    // RFC 9002 Appendix A.5: a padded Initial that elicits nothing is in flight, and sets it.
    try test_connection.recovery.on_packet_sent(.initial, .{
        .number = 0,
        .sent_at_ns = test_now_ns,
        .sent_len = @intCast(constants.datagram_len_min),
        .ack_eliciting = false,
        .in_flight = true,
    }, test_now_ns);
    try testing.expectEqual(timer.Kind.loss, next().?.kind);
    acknowledge_handshake(0);
    try testing.expectEqual(null, next());
}

test "design §4.2: a connection with nothing armed asks for no instant" {
    // RFC 9000 §10.1: "a value of 0 ... means the timeout is disabled", and §18.2 makes 0 the
    // default, so this connection has no timer of any kind.
    open_connection(0);
    try testing.expectEqual(null, next());
    const fired = try fire(test_now_ns + idle_timeout_ns);
    try testing.expect(!fired.idle and !fired.period and !fired.path and !fired.loss);
}

test "RFC 9000 §10.1: the idle timeout is a deadline, and firing it closes the connection" {
    open_connection(idle_timeout_ms);
    const deadline = next().?;
    try testing.expectEqual(timer.Kind.idle, deadline.kind);
    try testing.expectEqual(test_now_ns + idle_timeout_ns, deadline.at_ns);

    // An instant short of it fires nothing.
    try testing.expect(!(try fire(deadline.at_ns - 1)).idle);
    try testing.expectEqual(.send_anything, test_connection.termination.permission());

    const fired = try fire(deadline.at_ns);
    try testing.expect(fired.idle);
    // §10.1: the connection is closed silently, so nothing may be sent afterwards.
    try testing.expectEqual(.send_nothing, test_connection.termination.permission());
    // A connection already closed asks for no further instant.
    try testing.expectEqual(null, next());
}

test "RFC 9000 §8.2.4: an outstanding PATH_CHALLENGE is the nearer deadline" {
    open_connection(idle_timeout_ms);
    // §21.1.1.1 exempts a client establishing a connection, so its path begins validated; this
    // case is about a path being probed, which is the state §8.2 measures.
    test_connection.path.init(.unvalidated);
    test_connection.path.on_challenge_sent(challenge_data, constants.datagram_len_min, test_now_ns, challenge_timeout_ns);
    const deadline = next().?;
    // §8.2.4's timer is shorter than §10.1's, so it is what colibri wants to be called at.
    try testing.expectEqual(timer.Kind.path, deadline.kind);
    try testing.expectEqual(test_now_ns + challenge_timeout_ns, deadline.at_ns);

    const fired = try fire(deadline.at_ns);
    try testing.expect(fired.path);
    // "Path validation only fails when the endpoint attempting to validate the path abandons its
    // attempt", which is what the timer did.
    try testing.expectEqual(.abandoned, test_connection.path.state());
    // With the challenge gone the idle timeout is the nearest again.
    try testing.expectEqual(timer.Kind.idle, next().?.kind);
}

test "RFC 9000 §10.2: the closing period replaces the idle timeout" {
    open_connection(idle_timeout_ms);
    const probe_timeout_ns = test_connection.recovery.rtt.probe_timeout_ns(true);
    test_connection.termination.on_close_sent(test_now_ns, probe_timeout_ns);

    const deadline = next().?;
    try testing.expectEqual(timer.Kind.period, deadline.kind);
    // §10.2: the period is three times the Probe Timeout.
    try testing.expectEqual(test_now_ns + constants.close_probe_timeouts * probe_timeout_ns, deadline.at_ns);
    // §10.1's timer belongs to an active connection, and this one is closing.
    try testing.expectEqual(null, test_connection.termination.idle_deadline_ns());

    try testing.expect(!(try fire(deadline.at_ns - 1)).period);
    try testing.expect((try fire(deadline.at_ns)).period);
    // §10.2: once the period ends the caller discards the state.
    try testing.expectEqual(null, next());
}

test "RFC 9001 §6.5: the previous read keys are a deadline of their own" {
    open_connection(idle_timeout_ms);
    // The state a key update this endpoint answered leaves: the old read keys are held, and a
    // packet under the new ones arrived at `test_now_ns`.
    test_connection.key_phase.previous_held = true;
    test_connection.key_phase.previous_since_ns = test_now_ns;

    const deadline = next().?;
    try testing.expectEqual(timer.Kind.previous_keys, deadline.kind);
    try testing.expectEqual(test_now_ns + three_probe_timeouts_ns(), deadline.at_ns);

    try testing.expect(!(try fire(deadline.at_ns - 1)).previous_keys);
    try testing.expectEqual(0, suite_holder.previous_discards);
    const fired = try fire(deadline.at_ns);
    try testing.expect(fired.previous_keys);
    try testing.expectEqual(1, suite_holder.previous_discards);
    try testing.expectEqual(timer.Kind.idle, next().?.kind);
}

test "RFC 9002 Appendix A.9, decision 59: a packet in flight arms the loss timer, which runs" {
    open_connection(idle_timeout_ms);
    // RFC 9002 Appendix A.8's `GetPtoTimeAndSpace` skips the Application Data space until the
    // handshake is confirmed, so the packet that arms this one is an Initial.
    try test_connection.recovery.on_packet_sent(.initial, .{
        .number = 0,
        .sent_at_ns = test_now_ns,
        .sent_len = @intCast(constants.datagram_len_min),
        .ack_eliciting = true,
        .in_flight = true,
    }, test_now_ns);

    const deadline = next().?;
    try testing.expectEqual(timer.Kind.loss, deadline.kind);
    try testing.expect(!(try fire(deadline.at_ns - 1)).loss);
    const fired = try fire(deadline.at_ns);
    try testing.expect(fired.loss);
    // Decision 59: Appendix A.9's `OnLossDetectionTimeout` ran. Nothing was old enough to be lost,
    // so it was the Probe Timeout, and §6.2.4 owes two probes while a packet is in flight.
    try testing.expectEqual(constants.probe_packets, test_connection.probes_owed[@intFromEnum(core.Level.initial)]);
}

test "design §4.2: more than one deadline can come due at one instant" {
    open_connection(idle_timeout_ms);
    test_connection.path.on_challenge_sent(challenge_data, constants.datagram_len_min, test_now_ns, idle_timeout_ns);
    test_connection.key_phase.previous_held = true;
    test_connection.key_phase.previous_since_ns = test_now_ns;

    // Every one of the three is past at an instant beyond them all, and `Fired` is a set rather
    // than a choice, so each says so.
    const fired = try fire(test_now_ns + idle_timeout_ns);
    try testing.expect(fired.idle);
    try testing.expect(fired.path);
    try testing.expect(fired.previous_keys);
}

test "RFC 9000 §13.2.1: an unacknowledged ack-eliciting packet is a deadline of its own" {
    open_connection(idle_timeout_ms);
    // One in-order ack-eliciting 1-RTT packet: §13.2.2's count of two is not met, so what makes
    // the acknowledgment owed is §13.2.1's "explicit contract" and nothing else.
    _ = test_connection.space_at(.application).receive(0, test_now_ns, true, .not_ect);

    const deadline = next().?;
    try testing.expectEqual(timer.Kind.acknowledgment, deadline.kind);
    // §18.2's default max_ack_delay, spelled here rather than read back off the connection, so a
    // deadline computed in the wrong unit shows.
    try testing.expectEqual(
        test_now_ns + default_max_ack_delay_ms * constants.nanoseconds_per_millisecond,
        deadline.at_ns,
    );

    // A second ack-eliciting packet meets §13.2.2's count, so one is owed now and wants no
    // timer: the caller writes it on its next pass and the idle timeout is nearest again.
    _ = test_connection.space_at(.application).receive(1, test_now_ns, true, .not_ect);
    try testing.expectEqual(timer.Kind.idle, next().?.kind);
}
