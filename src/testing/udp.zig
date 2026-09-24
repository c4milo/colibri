//! The UDP socket of design §9's QUIC endpoints, on rotor's loop (decision 58). Nothing here is
//! packaged: `src/testing/` is excluded from the library, and this is the only module in the tree
//! that imports rotor.
//!
//! An endpoint is one loop, one bound datagram socket and one multishot receive into a group of
//! buffers the loop owns. rotor allocates nothing, so every block of memory it runs on is a field
//! of `Memory`, which the caller places (decision 35 holds in `src/testing/` too). The QUIC
//! session stays pure: it takes octets and gives octets, and this file is the thin socket around
//! it that decision 52 asked for.
//!
//! Every wait is rotor's one system call per `tick`, so an endpoint here never blocks anywhere
//! else, which is decision 46's rule on a loop colibri did not write.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");

pub const Address = rotor.Address;
pub const Event = rotor.Event;
pub const Outbound = rotor.datagram.Outbound;
pub const Delivery = rotor.Delivery;

/// The loop's options. One multishot receive and the sends in flight.
const loop_options: rotor.Loop.Options = .{ .operations = constants.udp_operations_max };

/// The group every endpoint receives into. Not 0, so a read naming the wrong group cannot pass by
/// naming the default.
const group_id: u16 = 1;

/// The reserve in front of each datagram: rotor's default, which holds the three control messages
/// a QUIC stack asks for.
const group_options: rotor.datagram.GroupOptions = .{};

const group_bytes = rotor.buffers.group_bytes(constants.udp_receive_buffers, constants.udp_buffer_bytes);

/// The user data of the endpoint's receive. Sends carry the caller's, which must differ.
pub const receive_user_data: u64 = std.math.maxInt(u64);

/// Every block rotor runs an endpoint on, placed by the caller.
pub const Memory = struct {
    loop: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment),
    /// Larger than the group by its alignment, because a static declared that aligned is not
    /// always placed that aligned on macOS, and rotor's guide aligns forward inside the block.
    group: [group_bytes + rotor.buffers.group_alignment]u8 align(rotor.buffers.group_alignment),

    fn group_memory(memory: *Memory) []align(rotor.buffers.group_alignment) u8 {
        const start = std.mem.alignForward(usize, @intFromPtr(&memory.group), rotor.buffers.group_alignment);
        const aligned: [*]align(rotor.buffers.group_alignment) u8 = @ptrFromInt(start);
        return aligned[0..group_bytes];
    }
};

pub const Endpoint = struct {
    loop: rotor.Loop,
    socket: rotor.Descriptor,
    receiving: rotor.Handle,

    /// Starts the loop in `memory`, binds a datagram socket to `bind_to` and starts receiving.
    pub fn open(endpoint: *Endpoint, memory: *Memory, bind_to: Address) !void {
        try endpoint.loop.init(&memory.loop, loop_options);
        errdefer endpoint.loop.deinit();
        try endpoint.loop.provide_datagram_buffers(
            group_id,
            memory.group_memory(),
            constants.udp_receive_buffers,
            constants.udp_buffer_bytes,
            group_options,
        );
        endpoint.socket = try rotor.sync.open_datagram(bind_to.family, &bind_to, .{});
        errdefer rotor.sync.close_now(endpoint.socket);
        endpoint.start_receive();
    }

    /// Starts the multishot receive. rotor ends one with a final event, the one without `more`,
    /// when the kernel stops it — its buffers ran out, say — and `restart_receive` starts it again.
    fn start_receive(endpoint: *Endpoint) void {
        const receive: rotor.Operation = .{ .user_data = receive_user_data, .kind = .{ .receive_from = .{
            .socket = endpoint.socket,
            .group = group_id,
        } } };
        var handles: [1]rotor.Handle = undefined;
        const taken = endpoint.loop.submit(&.{receive}, &handles);
        assert(taken == 1);
        endpoint.receiving = handles[0];
    }

    /// Ends the endpoint's part in a receive event, once its datagram has been read: gives the
    /// buffer back, and starts the receive again when this was its final event. rotor ends a
    /// multishot receive with `buffers_exhausted` when the group runs out, and has the caller give
    /// buffers back before it starts one again, which is the order here.
    pub fn finish_receive(endpoint: *Endpoint, event: Event) void {
        assert(event.user_data == receive_user_data);
        if (event.flags.buffer) endpoint.give_back(event);
        if (!event.flags.more) endpoint.start_receive();
    }

    /// The address the socket is bound to, with the port the kernel chose when it was asked for 0.
    pub fn local_address(endpoint: *const Endpoint) !Address {
        return rotor.sync.local_address(endpoint.socket);
    }

    /// Sends `octets` as one datagram to where `outbound` says. Both belong to the loop until the
    /// send's event, which carries `user_data` (rotor's rule 3). False when the loop has no room
    /// for the send yet.
    pub fn send(endpoint: *Endpoint, user_data: u64, octets: []const u8, outbound: *const Outbound) bool {
        assert(user_data != receive_user_data);
        const operation: rotor.Operation = .{ .user_data = user_data, .kind = .{ .send_to = .{
            .socket = endpoint.socket,
            .buffer = .{ .bytes = octets },
            .to = outbound,
        } } };
        return endpoint.loop.submit(&.{operation}, &.{}) == 1;
    }

    /// Waits at most `wait_ns` for events and returns them. A received datagram's event is the
    /// endpoint's `receive_user_data`, which `delivery` reads and `give_back` releases.
    pub fn tick(endpoint: *Endpoint, events: []Event, wait_ns: u64) ![]Event {
        const count = try endpoint.loop.tick(events, wait_ns);
        return events[0..count];
    }

    /// The instant the last `tick` read from the monotonic clock, in nanoseconds, which the QUIC
    /// endpoints pass to colibri (decision 63). 0 until the first tick. It makes no system call.
    pub fn now_ns(endpoint: *const Endpoint) u64 {
        return endpoint.loop.now_ns();
    }

    /// The peer and the octets of a received datagram.
    pub fn delivery(endpoint: *Endpoint, event: Event) rotor.Delivery {
        assert(event.user_data == receive_user_data);
        return endpoint.loop.datagram(group_id, event);
    }

    /// Returns a received datagram's buffer to the group, once its octets have been read.
    pub fn give_back(endpoint: *Endpoint, event: Event) void {
        assert(event.user_data == receive_user_data and event.flags.buffer);
        endpoint.loop.give_back_buffer(group_id, event.flags.buffer_id);
    }

    /// Ends the receive, waits for every operation's final event, closes the socket and the loop.
    pub fn close(endpoint: *Endpoint) !void {
        endpoint.loop.cancel(endpoint.receiving);
        var events: [constants.udp_operations_max]Event = undefined;
        try endpoint.loop.drain(&events);
        rotor.sync.close_now(endpoint.socket);
        endpoint.loop.deinit();
    }
};

comptime {
    // A datagram as large as the endpoint's paths carry arrives whole.
    assert(rotor.datagram.payload_capacity(constants.udp_buffer_bytes, group_options) >= constants.udp_payload_len_min);
}

const testing = std.testing;

/// A receiver and a sender. Test-only.
const test_endpoint_count: usize = 2;
var test_memory: [test_endpoint_count]Memory = undefined;
var test_endpoints: [test_endpoint_count]Endpoint = undefined;
/// Loopback, 127.0.0.1 as one big-endian word, port 0, so the kernel picks a free port for each
/// endpoint. Test-only.
const loopback_word: u32 = 0x7f00_0001;
const loopback_octets: [@sizeOf(u32)]u8 = @bitCast(std.mem.nativeToBig(u32, loopback_word));
/// A wait long enough for loopback, one second, bounded so a lost datagram fails the test.
/// Test-only.
const test_wait_ns: u64 = 1_000_000_000;
const test_send_user_data: u64 = 1;
const test_octets = "a datagram crosses rotor";

/// Datagrams the test sends in turn: more than twice the receive group, so a buffer not given back
/// runs the group out. Test-only.
const test_datagrams: usize = 33;

comptime {
    assert(test_datagrams > constants.udp_receive_buffers + constants.udp_receive_buffers);
}

test "decision 58: datagrams cross between two endpoints through rotor's loop" {
    const receiver = &test_endpoints[0];
    const sender = &test_endpoints[1];
    try receiver.open(&test_memory[0], Address.ipv4(loopback_octets, 0));
    try sender.open(&test_memory[1], Address.ipv4(loopback_octets, 0));
    const outbound: Outbound = .{
        .peer = try receiver.local_address(),
        .local = undefined,
        .segment_bytes = 0,
        .ecn = .not_ect,
        .flags = .{ .peer = true },
    };
    // Decision 63: no instant before the first tick, and none that runs backwards after it.
    try testing.expectEqual(0, receiver.now_ns());
    var previous_ns: u64 = 0;
    for (0..test_datagrams) |_| {
        try exchange(sender, receiver, &outbound);
        try testing.expect(receiver.now_ns() > 0 and receiver.now_ns() >= previous_ns);
        previous_ns = receiver.now_ns();
    }
    try receiver.close();
    try sender.close();
}

/// Events one receive may deliver before it has to end: one per buffer, and the final one. Test-only.
const test_burst: usize = constants.udp_receive_buffers + 1;

test "decision 58: a receive that ran out of buffers starts again" {
    const receiver = &test_endpoints[0];
    const sender = &test_endpoints[1];
    try receiver.open(&test_memory[0], Address.ipv4(loopback_octets, 0));
    try sender.open(&test_memory[1], Address.ipv4(loopback_octets, 0));
    const outbound: Outbound = .{
        .peer = try receiver.local_address(),
        .local = undefined,
        .segment_bytes = 0,
        .ecn = .not_ect,
        .flags = .{ .peer = true },
    };
    var events: [constants.udp_operations_max]Event = undefined;
    // More datagrams than the group holds, none of them given back, so the receive ends.
    for (0..test_burst) |_| {
        try testing.expect(sender.send(test_send_user_data, test_octets, &outbound));
        try testing.expectEqual(1, (try sender.tick(&events, test_wait_ns)).len);
    }
    var held: [test_burst]Event = undefined;
    var held_len: usize = 0;
    // Bounded: each tick delivers at least one event, and the receive ends within the burst.
    while (held_len == 0 or held[held_len - 1].flags.more) {
        const arrived = try receiver.tick(&events, test_wait_ns);
        try testing.expect(arrived.len > 0 and held_len + arrived.len <= held.len);
        @memcpy(held[held_len..][0..arrived.len], arrived);
        held_len += arrived.len;
    }
    try testing.expect(!held[held_len - 1].flags.buffer);
    for (held[0..held_len]) |event| receiver.finish_receive(event);
    // The receive started again. The datagram that found the group empty stayed in the kernel,
    // on both of Rotor's backends, so it arrives, and so does the next one. io_uring hands both
    // over in one tick and kqueue one in each.
    try testing.expect(sender.send(test_send_user_data, test_octets, &outbound));
    try testing.expectEqual(1, (try sender.tick(&events, test_wait_ns)).len);
    try receive_datagrams(receiver, leftover_and_next);
    try receiver.close();
    try sender.close();
}

/// The datagram the empty group turned away, and the one sent after the receive started again.
/// Test-only.
const leftover_and_next: usize = 2;

/// Waits until `count` datagrams have arrived at `receiver`, in however many ticks, checks each,
/// and gives its buffer back. Test-only.
fn receive_datagrams(receiver: *Endpoint, count: usize) !void {
    var events: [constants.udp_operations_max]Event = undefined;
    var arrived_count: usize = 0;
    // Bounded: each tick delivers at least one datagram, or its wait ends and fails the test.
    while (arrived_count < count) {
        const arrived = try receiver.tick(&events, test_wait_ns);
        try testing.expect(arrived.len > 0 and arrived_count + arrived.len <= count);
        for (arrived) |event| {
            try testing.expectEqualStrings(test_octets, receiver.delivery(event).bytes);
            receiver.finish_receive(event);
        }
        arrived_count += arrived.len;
    }
}

/// Sends one datagram, waits for the send's event, then for the datagram at the receiver, reads
/// it and gives its buffer back. Test-only.
fn exchange(sender: *Endpoint, receiver: *Endpoint, outbound: *const Outbound) !void {
    try testing.expect(sender.send(test_send_user_data, test_octets, outbound));
    var events: [constants.udp_operations_max]Event = undefined;
    const sent = try sender.tick(&events, test_wait_ns);
    try testing.expectEqual(1, sent.len);
    try testing.expectEqual(test_send_user_data, sent[0].user_data);
    try testing.expectEqual(@as(u32, test_octets.len), try sent[0].outcome());

    const arrived = try receiver.tick(&events, test_wait_ns);
    try testing.expectEqual(1, arrived.len);
    const got = receiver.delivery(arrived[0]);
    try testing.expectEqualStrings(test_octets, got.bytes);
    try testing.expectEqual((try sender.local_address()).port, got.from.peer.port);
    receiver.finish_receive(arrived[0]);
}
