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

/// Where an endpoint is, as the other one sees it: a host and a port. The server's never
/// changes. The client's changes when the network rebinds it, as a NAT does (RFC 9000 §9.3).
pub const Address = struct {
    host: u8,
    port: u16,

    pub fn eql(address: Address, other: Address) bool {
        return address.host == other.host and address.port == other.port;
    }
};

pub const server_address: Address = .{ .host = constants.network_server_host, .port = constants.network_server_port };
pub const client_address_initial: Address = .{ .host = constants.network_client_host, .port = constants.network_client_port };

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
    /// The most datagrams dropped in a row toward one endpoint, or null for no bound. After that
    /// many the next is delivered whatever the draw, which is how the QUIC Interop Runner's
    /// drop-rate scenario bounds its runs of loss.
    drop_run_max: ?u32 = null,
    /// Datagrams delivered a second time, each copy with a delay of its own (RFC 9000 §13.3 has
    /// an endpoint prepared for a packet it has already received).
    duplicate: u32 = 0,
    /// Datagrams whose ECT codepoint a node changes to ECN-CE (RFC 9000 §13.4). A datagram sent
    /// Not-ECT is never marked: a node that did so would be breaking the field's meaning, and
    /// RFC 9000 §13.4.2's validation exists for networks that do.
    mark_congestion: u32 = 0,
    /// The instant the network first rebinds the client, or null for never, and how often it
    /// does again after that, or 0 for once. A rebind gives the client a new port, and with
    /// `rebind_host` a new host too, as the QUIC Interop Runner's rebind scenario does. A datagram
    /// sent to the old binding is dropped, as a NAT drops one to a binding it no longer holds.
    rebind_first_ns: ?u64 = null,
    rebind_every_ns: u64 = 0,
    rebind_host: bool = false,
    /// The delay one datagram takes, in nanoseconds, drawn from `[delay_min_ns, delay_max_ns]`.
    /// A range wider than one endpoint's sending interval is what produces reordering.
    delay_min_ns: u64 = constants.network_delay_min_ns,
    delay_max_ns: u64 = constants.network_delay_max_ns,

    /// Asserts the schedule is one the network can draw from.
    pub fn validate(schedule: Schedule) void {
        assert(schedule.drop <= constants.schedule_denominator);
        assert(schedule.drop_run_max orelse 1 > 0);
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
    /// The sender's address when it sent the datagram.
    from_address: Address = client_address_initial,
    len: usize = 0,
    octets: [constants.network_datagram_len_max]u8 = @splat(0),
};

/// A datagram the network gave to an endpoint.
pub const Delivery = struct {
    from: Endpoint,
    /// The sender's address when it sent the datagram, which a rebind since may have changed.
    from_address: Address,
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
    /// It was sent to an address its receiver no longer holds, so the network dropped it.
    misrouted,
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
    /// Times the network rebound the client, and datagrams sent to a binding it no longer held.
    rebinds: u64 = 0,
    misrouted: u64 = 0,
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
    /// The client's address now, which a rebind changes.
    client_address: Address,
    /// The instant of the next rebind, or null when none is scheduled.
    next_rebind_ns: ?u64,
    /// The datagrams toward each endpoint dropped since the last one delivered, which
    /// `Schedule.drop_run_max` bounds.
    dropped_in_a_row: [Endpoint.count]u32,
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
        network.client_address = client_address_initial;
        network.next_rebind_ns = schedule.rebind_first_ns;
        network.dropped_in_a_row = @splat(0);
        network.census = .{};
    }

    /// Hands a datagram to the network. `now_ns` is the instant it left the sender, and every
    /// draw for it is made here, so a datagram's fate does not depend on when it is collected.
    pub fn send(network: *Network, now_ns: u64, from: Endpoint, octets: []const u8, ecn: Ecn) Sent {
        network.rebind_until(now_ns);
        return network.send_to(now_ns, from, octets, ecn, network.address_of(from.peer()));
    }

    /// Hands a datagram to the network, addressed to `to`, which may be a binding the receiver
    /// has since lost.
    pub fn send_to(network: *Network, now_ns: u64, from: Endpoint, octets: []const u8, ecn: Ecn, to: Address) Sent {
        assert(octets.len > 0 and octets.len <= constants.network_datagram_len_max);
        network.rebind_until(now_ns);
        network.census.sent += 1;
        network.census.octets += octets.len;
        if (!to.eql(network.address_of(from.peer()))) {
            network.census.misrouted += 1;
            return .misrouted;
        }
        // RFC 9000 §13.4: a node that drops a datagram and one that marks it are the same node,
        // so the draw that drops comes first and a dropped datagram is never marked.
        if (network.drops(from.peer())) {
            network.census.dropped += 1;
            return .dropped;
        }
        const source = network.address_of(from);
        if (!network.queue(now_ns, from.peer(), octets, network.mark(ecn), source)) return .no_slot;
        // A duplicate is a second datagram with its own delay, so it may arrive before the first.
        if (network.draws(network.schedule.duplicate)) {
            if (network.queue(now_ns, from.peer(), octets, network.mark(ecn), source)) {
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
            .from_address = held.from_address,
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

    /// Whether the next datagram toward `to` is dropped. A run of `drop_run_max` drops ends with
    /// a delivery, which takes no draw.
    fn drops(network: *Network, to: Endpoint) bool {
        const run = &network.dropped_in_a_row[@intFromEnum(to)];
        if (network.schedule.drop_run_max) |most| {
            if (run.* >= most) {
                run.* = 0;
                return false;
            }
        }
        if (!network.draws(network.schedule.drop)) {
            run.* = 0;
            return false;
        }
        run.* += 1;
        return true;
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

    /// Where `endpoint` is now.
    pub fn address_of(network: *const Network, endpoint: Endpoint) Address {
        return if (endpoint == .client) network.client_address else server_address;
    }

    /// Takes every rebind due by `now_ns` at once: each moves the port on by one, and the host too
    /// under `rebind_host`, so the count of rebinds, not their order, decides the address.
    fn rebind_until(network: *Network, now_ns: u64) void {
        const due_ns = network.next_rebind_ns orelse return;
        if (now_ns < due_ns) return;
        const every_ns = network.schedule.rebind_every_ns;
        const count: u64 = if (every_ns == 0) 1 else (now_ns - due_ns) / every_ns + 1;
        network.next_rebind_ns = if (every_ns == 0) null else due_ns + count * every_ns;
        network.census.rebinds += count;
        const address = &network.client_address;
        address.port +%= @truncate(count);
        if (network.schedule.rebind_host) address.host +%= @truncate(count);
    }

    /// Puts one datagram in flight. False when every slot is full.
    fn queue(network: *Network, now_ns: u64, to: Endpoint, octets: []const u8, ecn: Ecn, source: Address) bool {
        const delay_ns = network.random.between(network.schedule.delay_min_ns, network.schedule.delay_max_ns);
        const held = network.free_slot() orelse return false;
        held.* = .{
            .live = true,
            .to = to,
            .arrival_ns = now_ns + delay_ns,
            .sequence = network.next_sequence,
            .ecn = ecn,
            .from_address = source,
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

test {
    _ = @import("network_test.zig");
}
