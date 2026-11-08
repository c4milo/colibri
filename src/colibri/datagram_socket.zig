//! One UDP socket on a Rotor loop, with no QUIC in it (design §8 steps 37c and 42). A server's UDP
//! socket and a client's are each one of these. One multishot receive reads into a group of
//! buffers the socket holds. On Linux the kernel coalesces datagrams from one peer (UDP_GRO),
//! which Rotor splits again, and cuts each batch the socket sends into datagrams (UDP_SEGMENT,
//! design §8 step 13f.6). Moved out of `server_udp.zig`, which took it from the test-only UDP
//! server.
//!
//! The socket does not know who reads the datagrams or who writes them:
//! - `on_event` hands each datagram it read to the function the caller gives;
//! - `flush` sends what the caller's `send_datagram(output, now_ns)` returns, which a
//!   `server.Engine` and a `client.ConnectionPool` each have.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const rotor = @import("rotor");
const server = @import("server");
const constants = @import("constants.zig");
const batch_module = @import("datagram_batch.zig");

/// A peer's address and a datagram's codepoint, as colibri names them (decisions 68 and 72).
pub const PeerAddress = @FieldType(server.Datagram, "from");
pub const ReceivedEcn = @FieldType(server.Datagram, "ecn");

/// The receive's user data, and the first of the sends', which count down from it by batch. A
/// server's accept is above both, and every TCP socket's below them (`server_loop.zig`).
pub const receive_user_data: u64 = std.math.maxInt(u64) - 1;
pub const send_user_data_first: u64 = receive_user_data - 1;
pub const send_user_data_last: u64 = send_user_data_first - (constants.limits.udp_batches - 1);

const group_options: rotor.datagram.GroupOptions = .{};
pub const group_bytes = rotor.buffers.group_bytes(constants.limits.udp_receive_buffers, constants.limits.udp_receive_buffer_len);

/// The operations the UDP socket holds in flight: one receive and a send for each batch.
pub const operations: u32 = 1 + constants.limits.udp_batches;

/// Whether `user_data` is one of the UDP socket's operations.
pub fn owns(user_data: u64) bool {
    return user_data <= receive_user_data and user_data >= send_user_data_last;
}

/// One datagram the socket read: a delivery, or one segment of a delivery the kernel coalesced.
pub const Received = struct {
    bytes: []u8,
    ecn: ReceivedEcn,
    from: PeerAddress,
};

pub const BindError = rotor.sync.SocketError || rotor.sync.ListenError;
pub const StartError = rotor.Loop.ProvideError || error{BufferGroupsFull};

pub const DatagramSocket = struct {
    /// Whether `descriptor` is open: `bind` opens it, and `close` closes it once.
    open: bool,
    descriptor: rotor.Descriptor,
    /// The multishot receive in flight.
    receiving: rotor.Handle,
    /// The group the socket receives into, which `start` reserves on the loop (Rotor's decision
    /// 29).
    buffer_group: rotor.BufferGroup,
    /// The receive buffers, the batches and their destinations, and the room each datagram is
    /// written in.
    group: [group_bytes + rotor.buffers.group_alignment]u8 align(rotor.buffers.group_alignment),
    batches: batch_module.Batches,
    outbound: [constants.limits.udp_batches]rotor.datagram.Outbound,
    datagram: [constants.limits.udp_datagram_len_max]u8,

    /// Opens the socket on `address`. Linux coalesces what arrives.
    pub fn bind(socket: *DatagramSocket, address: *const rotor.Address) BindError!void {
        assert(!socket.open);
        socket.descriptor = try rotor.sync.open_datagram(address.family, address, .{ .coalesce = builtin.os.tag == .linux });
        socket.open = true;
    }

    /// Closes the socket when it is open. A socket that `close` closed is not closed again: the
    /// system can give that number to another file of the program.
    pub fn close(socket: *DatagramSocket) void {
        if (socket.open) rotor.sync.close_now(socket.descriptor);
        socket.open = false;
    }

    /// Reserves a buffer group on the loop, gives the loop the receive buffers and starts the
    /// multishot receive. The group id stays reserved until the loop's `deinit`.
    pub fn start(socket: *DatagramSocket, loop: *rotor.Loop) StartError!void {
        assert(socket.open);
        socket.buffer_group = try loop.reserve_buffer_group();
        try loop.provide_datagram_buffers(socket.buffer_group, socket.group_memory(), constants.limits.udp_receive_buffers, constants.limits.udp_receive_buffer_len, group_options);
        socket.batches = .of(true);
        socket.start_receive(loop);
    }

    /// The receive buffers' block, aligned forward inside the field: a static declared that
    /// aligned is not always placed that aligned on macOS, which rotor's guide notes.
    fn group_memory(socket: *DatagramSocket) []align(rotor.buffers.group_alignment) u8 {
        const at = std.mem.alignForward(usize, @intFromPtr(&socket.group), rotor.buffers.group_alignment);
        const aligned: [*]align(rotor.buffers.group_alignment) u8 = @ptrFromInt(at);
        return aligned[0..group_bytes];
    }

    /// Starts the multishot receive. Rotor ends one with a final event, the one without `more`,
    /// when the kernel stops it, and `on_event` starts it again.
    fn start_receive(socket: *DatagramSocket, loop: *rotor.Loop) void {
        const receive: rotor.Operation = .{ .user_data = receive_user_data, .kind = .{ .receive_from = .{
            .socket = socket.descriptor,
            .group = socket.buffer_group,
        } } };
        var handles: [1]rotor.Handle = undefined;
        const taken = loop.submit(&.{receive}, &handles);
        assert(taken == 1);
        socket.receiving = handles[0];
    }

    /// A send's event gives its batch back. A receive's hands each datagram to `take(context,
    /// received, now_ns)`, gives the buffer back, and starts the receive again after its final
    /// event while `receives` is true.
    pub fn on_event(socket: *DatagramSocket, loop: *rotor.Loop, event: rotor.Event, receives: bool, context: anytype, comptime take: anytype, now_ns: u64) void {
        assert(owns(event.user_data));
        if (event.user_data != receive_user_data) {
            socket.batches.release(@intCast(send_user_data_first - event.user_data));
            return;
        }
        if (event.flags.buffer) {
            take_delivery(loop.datagram(socket.buffer_group, event), context, take, now_ns);
            loop.give_back_buffer(socket.buffer_group, event.flags.buffer_id);
        }
        if (!event.flags.more and receives) socket.start_receive(loop);
    }

    /// Sends every datagram `sender` owes now, while a batch is free to take it, one send for each
    /// batch.
    pub fn flush(socket: *DatagramSocket, loop: *rotor.Loop, sender: anytype, now_ns: u64) void {
        // Bounded: each pass adds one datagram, and the batches hold at most this many.
        for (0..constants.limits.udp_batches * constants.limits.udp_segments_max) |_| {
            if (!socket.batches.has_free()) break;
            const sent = sender.send_datagram(&socket.datagram, now_ns) orelse break;
            socket.batches.add(sent);
        }
        for (&socket.batches.batches, 0..) |*batch, index| {
            if (batch.state != .open) continue;
            socket.outbound[index] = outbound(batch);
            const operation: rotor.Operation = .{ .user_data = send_user_data_first - index, .kind = .{ .send_to = .{
                .socket = socket.descriptor,
                .buffer = .{ .bytes = batch.bytes[0..batch.len] },
                .to = &socket.outbound[index],
            } } };
            // A batch Rotor has no room for is freed, and its datagrams are lost on the way, as on
            // a path that drops them (RFC 9002 §6 recovers them).
            batch.state = if (loop.submit(&.{operation}, &.{}) == 1) .sending else .free;
        }
    }

    /// Ends the receive. Its final event follows, and the loop's drain reads it.
    pub fn stop(socket: *DatagramSocket, loop: *rotor.Loop) void {
        loop.cancel(socket.receiving);
    }
};

/// Hands `take` the datagram of a delivery. Rotor splits what the kernel coalesced, so each
/// delivery holds one datagram (Rotor's decision 15 as amended). A delivery cut short is dropped,
/// as a lost datagram is. `server_udp_test.zig` calls it with a delivery it builds.
pub fn take_delivery(delivery: rotor.Delivery, context: anytype, comptime take: anytype, now_ns: u64) void {
    assert(delivery.from.segment_bytes == 0);
    if (delivery.from.flags.truncated) return;
    const ecn = received_ecn(&delivery.from);
    const from = peer_address(delivery.from.peer);
    take(context, .{ .bytes = delivery.bytes, .ecn = ecn, .from = from }, now_ns);
}

/// Where a batch goes, asking Rotor to set the codepoint colibri named (decision 68), and to cut
/// it into segments of its first datagram's length.
fn outbound(batch: *const batch_module.Batch) rotor.datagram.Outbound {
    const ecn = sent_ecn(batch.ecn);
    return .{
        .peer = rotor_address(batch.to),
        .local = undefined,
        .segment_bytes = batch.segment_bytes(),
        .ecn = ecn,
        .flags = .{ .peer = true, .ecn = ecn != .not_ect },
    };
}

/// A socket address as colibri names a peer's (decision 72).
pub fn peer_address(address: rotor.Address) PeerAddress {
    const len: usize = if (address.family == .ipv4) rotor.Address.ipv4_bytes else address.bytes.len;
    var peer = PeerAddress.of(address.bytes[0..len], address.port);
    peer.scope_id = address.scope_id;
    return peer;
}

/// A peer's address as colibri names it, back in Rotor's form, for a UDP send or a TCP connect.
pub fn rotor_address(address: PeerAddress) rotor.Address {
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

test "design §8 step 37: a batch goes to Rotor with the codepoint the engine named" {
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

test "design §8 step 37: the engine gets the codepoint Rotor read, and Not-ECT when Rotor read none" {
    for (rotor_codepoints, colibri_codepoints) |read, expected| {
        var from: rotor.datagram.Received = .{ .peer = test_peer, .local = undefined, .segment_bytes = 0, .ecn = read, .flags = .{ .ecn = true } };
        try testing.expectEqual(expected, received_ecn(&from));
        from.flags.ecn = false;
        try testing.expectEqual(ReceivedEcn.not_ect, received_ecn(&from));
    }
}
