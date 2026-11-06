//! The UDP socket of a `colibri.Server` (design §8 step 37c): h3 over QUIC on the UDP port of the
//! same number as the TCP listener's, on the same Rotor loop. One multishot receive reads into a
//! group of buffers the server holds. On Linux the kernel coalesces datagrams from one peer
//! (UDP_GRO) and cuts each batch the server sends into datagrams (UDP_SEGMENT, design §8 step
//! 13f.6). Moved from the test-only UDP server's `udp.zig`, `udp_run_h3.zig` and `udp_peer.zig`.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const rotor = @import("rotor");
const server = @import("server");
const constants = @import("constants.zig");
const batch_module = @import("datagram_batch.zig");

const PeerAddress = @FieldType(server.Datagram, "from");
const ReceivedEcn = @FieldType(server.Datagram, "ecn");

/// The receive's user data, and the first of the sends', which count down from it by batch. The
/// accept's is above both, and every TCP socket's below them (`server_loop.zig`).
pub const receive_user_data: u64 = std.math.maxInt(u64) - 1;
pub const send_user_data_first: u64 = receive_user_data - 1;
pub const send_user_data_last: u64 = send_user_data_first - (constants.limits.udp_batches - 1);

/// The group the socket receives into. Not 0, so a read naming the wrong group cannot pass.
const group_id: u16 = 1;
const group_options: rotor.datagram.GroupOptions = .{};
pub const group_bytes = rotor.buffers.group_bytes(constants.limits.udp_receive_buffers, constants.limits.udp_receive_buffer_len);

/// The operations the UDP socket holds in flight: one receive and a send for each batch.
pub const operations: u32 = 1 + constants.limits.udp_batches;

/// Whether `user_data` is one of the UDP socket's operations.
pub fn owns(user_data: u64) bool {
    return user_data <= receive_user_data and user_data >= send_user_data_last;
}

/// Opens the UDP socket on the listener's address and port. Linux coalesces what arrives.
pub fn open(state: anytype) (rotor.sync.SocketError || rotor.sync.ListenError || error{HostInvalid})!void {
    var address = try @import("server_loop.zig").address_of(state.config.host, state.bound_port);
    assert(address.port == state.bound_port);
    state.udp_socket = try rotor.sync.open_datagram(address.family, &address, .{ .coalesce = builtin.os.tag == .linux });
}

/// Opens the UDP socket when the server serves h3: `quic_slots` and an identity. RFC 9114 §3.1:
/// h3 runs over QUIC, which needs TLS (RFC 9001 §4). A TCP connection over TLS then advertises h3
/// on the same port (RFC 7838 §3), unless the program named another alternative.
pub fn open_when_served(state: anytype, quic_slots: bool) !void {
    assert(!state.udp_open);
    if (!quic_slots or state.config.identity == null) return;
    try open(state);
    state.udp_open = true;
    if (state.endpoint_config.h3_alternative == null) state.endpoint_config.h3_alternative = .{ .port = state.bound_port };
}

/// Gives the loop the receive buffers and starts the multishot receive.
pub fn start(state: anytype) rotor.Loop.ProvideError!void {
    const memory = group_memory(state);
    try state.loop.provide_datagram_buffers(group_id, memory, constants.limits.udp_receive_buffers, constants.limits.udp_receive_buffer_len, group_options);
    state.batches = .of(true);
    start_receive(state);
}

/// The receive buffers' block, aligned forward inside the field: a static declared that aligned is
/// not always placed that aligned on macOS, which rotor's guide notes.
fn group_memory(state: anytype) []align(rotor.buffers.group_alignment) u8 {
    const at = std.mem.alignForward(usize, @intFromPtr(&state.udp_group), rotor.buffers.group_alignment);
    const aligned: [*]align(rotor.buffers.group_alignment) u8 = @ptrFromInt(at);
    return aligned[0..group_bytes];
}

/// Starts the multishot receive. Rotor ends one with a final event, the one without `more`, when
/// the kernel stops it, and `on_event` starts it again.
fn start_receive(state: anytype) void {
    const receive: rotor.Operation = .{ .user_data = receive_user_data, .kind = .{ .receive_from = .{
        .socket = state.udp_socket,
        .group = group_id,
    } } };
    var handles: [1]rotor.Handle = undefined;
    const taken = state.loop.submit(&.{receive}, &handles);
    assert(taken == 1);
    state.udp_receiving = handles[0];
}

/// A send's event gives its batch back. A receive's hands each datagram to the endpoint, gives the
/// buffer back, and starts the receive again after its final event.
pub fn on_event(run: anytype, event: rotor.Event, now_ns: u64) void {
    const state = run.server;
    if (event.user_data != receive_user_data) {
        state.batches.release(@intCast(send_user_data_first - event.user_data));
        return;
    }
    if (event.flags.buffer) {
        take_delivery(run, state.loop.datagram(group_id, event), now_ns);
        state.loop.give_back_buffer(group_id, event.flags.buffer_id);
    }
    if (!event.flags.more and !state.shut_down) start_receive(state);
}

/// Hands the endpoint each datagram of a delivery: the delivery itself, or each segment of one the
/// kernel coalesced. A delivery cut short is dropped, as a lost datagram is. `server_udp_test.zig`
/// calls it with a delivery it builds.
pub fn take_delivery(run: anytype, delivery: rotor.Delivery, now_ns: u64) void {
    if (delivery.from.flags.truncated) return;
    const ecn = received_ecn(&delivery.from);
    const from = peer_address(delivery.from.peer);
    var segments = batch_module.Segments.of(delivery.bytes, delivery.from.segment_bytes);
    // Bounded: each pass takes one segment, and a delivery holds at most `udp_segments_max`.
    for (0..constants.limits.udp_segments_max) |_| {
        const bytes = segments.next() orelse return;
        take(run, .{ .datagram = .{ .bytes = bytes, .ecn = ecn, .from = from } }, now_ns);
    }
}

/// Passes `input` to the endpoint, then routes every event it reports until it reports none.
fn take(run: anytype, input: server.Input, now_ns: u64) void {
    const state = run.server;
    state.now_ns = now_ns;
    var rest = input;
    for (0..constants.limits.events_per_step_max) |_| {
        const reported = state.endpoint.receive(rest, now_ns).event orelse return;
        rest = .none;
        @import("server_pump.zig").route(run, reported);
    }
}

/// Sends every datagram the endpoint owes now, while a batch is free to take it, one send for each
/// batch.
pub fn flush(state: anytype, now_ns: u64) void {
    // Bounded: each pass adds one datagram, and the batches hold at most this many.
    for (0..constants.limits.udp_batches * constants.limits.udp_segments_max) |_| {
        if (!state.batches.has_free()) break;
        const sent = state.endpoint.send_datagram(&state.udp_datagram, now_ns) orelse break;
        state.batches.add(sent);
    }
    for (&state.batches.batches, 0..) |*batch, index| {
        if (batch.state != .open) continue;
        state.udp_outbound[index] = outbound(batch);
        const operation: rotor.Operation = .{ .user_data = send_user_data_first - index, .kind = .{ .send_to = .{
            .socket = state.udp_socket,
            .buffer = .{ .bytes = batch.bytes[0..batch.len] },
            .to = &state.udp_outbound[index],
        } } };
        // A batch Rotor has no room for is freed, and its datagrams are lost on the way, as on a
        // path that drops them (RFC 9002 §6 recovers them).
        batch.state = if (state.loop.submit(&.{operation}, &.{}) == 1) .sending else .free;
    }
}

/// Where a batch goes, asking Rotor to set the codepoint colibri named (decision 68), and to cut
/// it into segments of its first datagram's length.
fn outbound(batch: *const batch_module.Batch) rotor.datagram.Outbound {
    const ecn = sent_ecn(batch.ecn);
    return .{
        .peer = udp_address(batch.to),
        .local = undefined,
        .segment_bytes = batch.segment_bytes(),
        .ecn = ecn,
        .flags = .{ .peer = true, .ecn = ecn != .not_ect },
    };
}

/// A socket address as colibri names a peer's (decision 72).
fn peer_address(address: rotor.Address) PeerAddress {
    const len: usize = if (address.family == .ipv4) rotor.Address.ipv4_bytes else address.bytes.len;
    var peer = PeerAddress.of(address.bytes[0..len], address.port);
    peer.scope_id = address.scope_id;
    return peer;
}

/// The socket address colibri named, back in Rotor's form.
fn udp_address(address: PeerAddress) rotor.Address {
    if (address.len == rotor.Address.ipv4_bytes) return rotor.Address.ipv4(address.octets[0..rotor.Address.ipv4_bytes].*, address.port);
    assert(address.len == address.octets.len);
    return rotor.Address.ipv6(address.octets, address.port, address.scope_id);
}

/// The codepoint Rotor read off a datagram's IP header, as colibri names it (RFC 9000 §13.4).
fn received_ecn(from: *const rotor.datagram.Received) ReceivedEcn {
    if (!from.flags.ecn) return .not_ect;
    return switch (from.ecn) {
        .not_ect => .not_ect,
        .ect0 => .ect_0,
        .ect1 => .ect_1,
        .ce => .ecn_ce,
    };
}

/// The codepoint colibri named for a datagram, as Rotor sets it (RFC 9000 §13.4).
fn sent_ecn(ecn: server.Ecn) rotor.datagram.Ecn {
    return switch (ecn) {
        .not_ect => .not_ect,
        .ect_0 => .ect0,
        .ect_1 => .ect1,
        .ecn_ce => .ce,
    };
}

/// Ends the receive at shutdown. Its final event follows, and `run` drains it.
pub fn stop(state: anytype) void {
    state.loop.cancel(state.udp_receiving);
}

comptime {
    assert(send_user_data_last > std.math.maxInt(u64) / 2);
    assert(constants.limits.udp_batches > 0);
}

const testing = std.testing;

/// The peer of the tests of the codepoints, on loopback. Test-only.
const test_port: u16 = 4433;
const test_loopback_word: u32 = 0x7f00_0001;
const test_peer = rotor.Address.ipv4(@bitCast(std.mem.nativeToBig(u32, test_loopback_word)), test_port);
/// Each codepoint as Rotor names it, and as colibri names it, in the same order. Test-only.
const rotor_codepoints = [_]rotor.datagram.Ecn{ .not_ect, .ect0, .ect1, .ce };
const colibri_codepoints = [_]server.Ecn{ .not_ect, .ect_0, .ect_1, .ecn_ce };

test "design §8 step 37: a batch goes to Rotor with the codepoint the endpoint named" {
    for (colibri_codepoints, rotor_codepoints) |named, expected| {
        const batch: batch_module.Batch = .{ .count = 1, .to = peer_address(test_peer), .ecn = named, .state = .open };
        const sent = outbound(&batch);
        // RFC 9000 §13.4: Rotor sets the codepoint in the IP header only when its flag is set.
        try testing.expectEqual(expected, sent.ecn);
        try testing.expectEqual(named != .not_ect, sent.flags.ecn);
        try testing.expect(sent.flags.peer);
        try testing.expectEqual(test_port, sent.peer.port);
    }
}

test "design §8 step 37: the endpoint gets the codepoint Rotor read, and Not-ECT when Rotor read none" {
    for (rotor_codepoints, colibri_codepoints) |read, expected| {
        var from: rotor.datagram.Received = .{ .peer = test_peer, .local = undefined, .segment_bytes = 0, .ecn = read, .flags = .{ .ecn = true } };
        try testing.expectEqual(expected, received_ecn(&from));
        from.flags.ecn = false;
        try testing.expectEqual(ReceivedEcn.not_ect, received_ecn(&from));
    }
}
