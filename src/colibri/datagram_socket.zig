//! The UDP sockets of a driver, with no QUIC and no I/O in them (design §8 steps 37c, 42 and 44f,
//! decision 159). A server has one UDP socket. A client has one for each family, and sends from
//! the one of its peer's family (decision 156 ruling 13). The sockets of one driver share one set
//! of batches. One receive stays in flight on each socket, which the host completes once for each
//! datagram, into its own memory. On Linux the private host's kernel coalesces datagrams from one
//! peer (UDP_GRO), which Rotor splits again, and cuts each batch that a socket sends into
//! datagrams (UDP_SEGMENT, design §8 step 13f.6). Moved out of `server_udp.zig`, which took it
//! from the test-only UDP server.
//!
//! The sockets do not know who reads the datagrams or who writes them:
//! - `complete` hands each datagram to the function the caller gives;
//! - `write` sends what the caller's `send_datagram(output, now_ns)` returns, which a
//!   `server.Engine` and a `client.ConnectionPool` each have.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const constants = @import("constants.zig");
const batch_module = @import("datagram_batch.zig");
const host = @import("host.zig");
const operation_table = @import("operation_table.zig");

/// A peer's address and a datagram's codepoint, as colibri names them (decisions 68 and 72).
pub const PeerAddress = server.Address;
pub const ReceivedEcn = @FieldType(server.Datagram, "ecn");

/// The octets of an IPv4 address (RFC 791 §3.1).
const ipv4_len = @sizeOf(u32);

/// One datagram a socket read.
pub const Received = struct {
    bytes: []u8,
    ecn: ReceivedEcn,
    from: PeerAddress,
};

/// One UDP socket and its receive.
pub const Receiver = struct {
    /// Whether the host opened the socket before the run.
    open: bool,
    /// The socket's id in the host's table.
    socket: host.SocketId,
    /// The receive is in flight, and a cancel of it was written.
    receiving: bool,
    receive_canceled: bool,
};

/// The `count` UDP sockets of a driver: 1 for a server, and 2 for a client, IPv4's at index 0 and
/// IPv6's at index 1.
pub fn DatagramSockets(comptime count: u32) type {
    comptime {
        assert(count == 1 or count == 2);
    }
    return struct {
        const Self = @This();

        /// The slots of the driver's operation table that the sockets hold, from their first: the
        /// receive of each socket, then one send for each batch (`operation_table.zig`).
        pub const slots: u32 = count + constants.limits.udp_batches;
        /// The operations the sockets hold in flight: a receive for each and a send for each
        /// batch.
        pub const operations: u32 = slots;

        /// Whether the object has a UDP socket: the host opened one before the run.
        served: bool,
        receivers: [count]Receiver,
        /// The first slot in the operation table.
        first_slot: u32,
        /// The batches and their destinations, and the room each datagram is written in.
        batches: batch_module.Batches,
        datagram: [constants.limits.udp_datagram_len_max]u8,

        /// Marks every socket closed, before `init` records the ones that the host opened.
        pub fn close_all(sockets: *Self) void {
            sockets.served = false;
            close_receivers(&sockets.receivers);
        }

        /// Records that the host opened socket `index` as `id`.
        pub fn open(sockets: *Self, index: usize, id: host.SocketId) void {
            assert(!sockets.receivers[index].open);
            sockets.receivers[index] = .{ .open = true, .socket = id, .receiving = false, .receive_canceled = false };
            sockets.served = true;
        }

        /// Starts a run: nothing in flight, and every batch free. The first `write` starts each
        /// receive. With `segments` the host sends a batch of equal segments in one call.
        pub fn start(sockets: *Self, first_slot: u32, segments: bool) void {
            assert(sockets.served);
            sockets.first_slot = first_slot;
            stop_receivers(&sockets.receivers);
            sockets.batches = .of(segments);
        }

        /// Whether a socket is open that sends to `to`: the server's one, or the client's socket
        /// of `to`'s family.
        pub fn sends_to(sockets: *const Self, to: *const PeerAddress) bool {
            return sockets.served and sockets.receivers[family_index(count, to)].open;
        }

        /// Whether `slot` is one of the sockets' slots.
        pub fn owns(sockets: *const Self, slot: u32) bool {
            return slot >= sockets.first_slot and slot < sockets.first_slot + slots;
        }

        /// Writes each open socket's receive while `receives` holds, and its cancel once it does
        /// not. Then it takes every datagram `sender` owes now, while a batch is free, and writes
        /// one send for each open batch, from the socket of its peer's family.
        pub fn write(sockets: *Self, out: *operation_table.Outbox, table: anytype, receives: bool, sender: anytype, now_ns: u64) void {
            write_all(sockets, count, out, table, receives, sender, now_ns);
        }

        /// Takes one completion of the sockets' `slot`. A send's gives its batch back. A
        /// receive's hands its datagram to `take(context, received, now_ns)` at once, because the
        /// host lends the bytes for the call alone. After a receive's final completion the next
        /// `write` starts it again.
        pub fn complete(sockets: *Self, slot: u32, completion: *const host.Completion, context: anytype, comptime take: anytype, now_ns: u64) void {
            assert(sockets.owns(slot));
            complete_one(sockets, count, slot - sockets.first_slot, completion, context, take, now_ns);
        }
    };
}

/// Marks each receiver closed.
fn close_receivers(receivers: anytype) void {
    for (receivers) |*receiver| receiver.open = false;
}

/// Marks no receive in flight.
fn stop_receivers(receivers: anytype) void {
    for (receivers) |*receiver| {
        receiver.receiving = false;
        receiver.receive_canceled = false;
    }
}

/// The index of the socket that sends to `to` among `count` sockets: the server's one, or the
/// client's socket of `to`'s family, 0 for IPv4 and 1 for IPv6 (decision 156 ruling 13).
fn family_index(comptime count: u32, to: *const PeerAddress) usize {
    if (count == 1) return 0;
    return if (to.len == ipv4_len) 0 else 1;
}

/// `DatagramSockets.write` of `count` sockets.
fn write_all(sockets: anytype, comptime count: u32, out: *operation_table.Outbox, table: anytype, receives: bool, sender: anytype, now_ns: u64) void {
    for (&sockets.receivers, 0..) |*receiver, index| {
        if (receiver.open) write_receive(receiver, sockets.first_slot + @as(u32, @intCast(index)), out, table, receives);
    }
    // Bounded: each pass adds one datagram, and the batches hold at most this many.
    for (0..constants.limits.udp_batches * constants.limits.udp_segments_max) |_| {
        if (!sockets.batches.has_free()) break;
        const sent = sender.send_datagram(&sockets.datagram, now_ns) orelse break;
        sockets.batches.add(sent);
    }
    for (&sockets.batches.batches, 0..) |*batch, index| {
        if (batch.state != .open) continue;
        // A batch with no room stays open, and the next turn writes it.
        if (!out.room()) return;
        const receiver = &sockets.receivers[family_index(count, &batch.to)];
        // The pool sends to the address of its QUIC connection alone, and the client ends an
        // open of QUIC to a family with no socket (`client_loop.zig`).
        assert(receiver.open);
        const id = table.issue(sockets.first_slot + count + @as(u32, @intCast(index)));
        out.put(.{ .id = id, .kind = .{ .send_datagram = .{
            .socket = receiver.socket,
            .bytes = batch.bytes[0..batch.len],
            .to = batch.to,
            .ecn = batch.ecn,
            .segment_bytes = batch.segment_bytes(),
        } } });
        batch.state = .sending;
    }
}

/// `DatagramSockets.complete` of `count` sockets, for the slot `offset` past their first.
fn complete_one(sockets: anytype, comptime count: u32, offset: u32, completion: *const host.Completion, context: anytype, comptime take: anytype, now_ns: u64) void {
    if (offset >= count) {
        assert(!completion.more);
        sockets.batches.release(offset - count);
        return;
    }
    const receiver = &sockets.receivers[offset];
    assert(receiver.open);
    switch (completion.result) {
        .datagram => |datagram| take(context, .{ .bytes = datagram.bytes, .ecn = datagram.ecn, .from = datagram.from }, now_ns),
        else => assert(!completion.more),
    }
    if (!completion.more) receiver.receiving = false;
}

/// Starts a socket's receive again after its final completion while `receives` holds. Once it
/// does not, it cancels the receive in flight, whose final completion follows.
fn write_receive(receiver: *Receiver, slot: u32, out: *operation_table.Outbox, table: anytype, receives: bool) void {
    if (receives and !receiver.receiving) {
        if (!out.room()) return;
        out.put(.{ .id = table.issue(slot), .kind = .{ .receive_datagram = .{ .socket = receiver.socket } } });
        receiver.receiving = true;
        receiver.receive_canceled = false;
        return;
    }
    if (receives or !receiver.receiving or receiver.receive_canceled) return;
    if (!out.room()) return;
    const target = table.id(slot);
    out.put(.{ .id = target, .kind = .{ .cancel = .{ .target = target } } });
    receiver.receive_canceled = true;
}

comptime {
    assert(constants.limits.udp_batches > 0);
    // A server's datagrams and a client's carry one address type and one codepoint type, so one
    // type serves both (decisions 68 and 72).
    assert(@FieldType(server.Datagram, "from") == PeerAddress);
    assert(ReceivedEcn == server.Ecn);
}

const testing = std.testing;

/// A sender that owes `count` datagrams of `len` octets to `to`. Test-only.
const TestSender = struct {
    count: u32,
    len: usize,
    to: PeerAddress = test_peer,

    pub fn send_datagram(sender: *TestSender, output: []u8, _: u64) ?server.Sent {
        if (sender.count == 0) return null;
        sender.count -= 1;
        @memset(output[0..sender.len], 'd');
        return .{ .bytes = output[0..sender.len], .ecn = .ect_0, .to = sender.to };
    }
};
const test_loopback_word: u32 = 0x7f00_0001;
const test_loopback: [@sizeOf(u32)]u8 = @bitCast(std.mem.nativeToBig(u32, test_loopback_word));
/// ::1, the IPv6 loopback (RFC 4291 §2.5.3).
const test_loopback_ipv6_word: u128 = 1;
const test_loopback_ipv6: [@sizeOf(u128)]u8 = @bitCast(std.mem.nativeToBig(u128, test_loopback_ipv6_word));
const test_port: u16 = 4433;
const test_peer = PeerAddress.of(&test_loopback, test_port);
const test_peer_ipv6 = PeerAddress.of(&test_loopback_ipv6, test_port);
const test_datagram_len = 1200;

/// A client's two sockets, which the tests drive outside any stack frame. Test-only.
const test_families: u32 = 2;
const TestSockets = DatagramSockets(test_families);
threadlocal var test_sockets: TestSockets align(@alignOf(TestSockets)) = undefined;
const test_ipv4_index: u16 = 3;
const test_ipv4: host.SocketId = @enumFromInt(test_ipv4_index);
const test_ipv6: host.SocketId = @enumFromInt(test_ipv4_index + 1);

/// Opens the test's sockets of IPv4 and of IPv6 when `ipv6` is set, and starts a run. Test-only.
fn start_test_sockets(ipv6: bool) void {
    test_sockets.close_all();
    test_sockets.open(0, test_ipv4);
    if (ipv6) test_sockets.open(1, test_ipv6);
    test_sockets.start(0, true);
}

test "decision 159: each receive is written once, and cancelled once receives stop" {
    var table: operation_table.Table(TestSockets.slots) = .empty;
    var written: [TestSockets.slots]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &written };
    var sender: TestSender = .{ .count = 0, .len = test_datagram_len };
    start_test_sockets(false);
    test_sockets.write(&out, &table, true, &sender, 0);
    try testing.expectEqual(1, out.len);
    try testing.expectEqual(test_ipv4, written[0].kind.receive_datagram.socket);
    test_sockets.write(&out, &table, true, &sender, 0);
    try testing.expectEqual(1, out.len);
    // Receives stop: one cancel names the receive, and a later turn writes no second one.
    test_sockets.write(&out, &table, false, &sender, 0);
    test_sockets.write(&out, &table, false, &sender, 0);
    try testing.expectEqual(2, out.len);
    try testing.expectEqual(written[0].id, written[1].kind.cancel.target);
}

test "decision 156 ruling 13: a client receives on the socket of each family" {
    var table: operation_table.Table(TestSockets.slots) = .empty;
    var written: [TestSockets.slots]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &written };
    var sender: TestSender = .{ .count = 0, .len = test_datagram_len };
    start_test_sockets(true);
    test_sockets.write(&out, &table, true, &sender, 0);
    try testing.expectEqual(2, out.len);
    try testing.expectEqual(test_ipv4, written[0].kind.receive_datagram.socket);
    try testing.expectEqual(test_ipv6, written[1].kind.receive_datagram.socket);
    // The final completion of IPv6's receive starts it again, and leaves IPv4's in flight.
    const slot = table.find(written[1].id).?;
    table.finish(slot);
    test_sockets.complete(slot, &.{ .id = written[1].id, .result = .canceled }, {}, take_nothing, 0);
    test_sockets.write(&out, &table, true, &sender, 0);
    try testing.expectEqual(3, out.len);
    try testing.expectEqual(test_ipv6, written[2].kind.receive_datagram.socket);
}

test "decision 156 ruling 13: a client sends from the socket of its peer's family" {
    for ([_]PeerAddress{ test_peer, test_peer_ipv6 }, [_]host.SocketId{ test_ipv4, test_ipv6 }) |to, expected| {
        var table: operation_table.Table(TestSockets.slots) = .empty;
        var written: [TestSockets.slots]host.Operation = undefined;
        var out: operation_table.Outbox = .{ .operations = &written };
        var sender: TestSender = .{ .count = 1, .len = test_datagram_len, .to = to };
        start_test_sockets(true);
        test_sockets.write(&out, &table, false, &sender, 0);
        try testing.expectEqual(1, out.len);
        try testing.expectEqual(expected, written[0].kind.send_datagram.socket);
    }
}

test "decision 159: the engine's datagrams leave in one send for each batch, with their codepoint" {
    var table: operation_table.Table(TestSockets.slots) = .empty;
    var written: [TestSockets.slots]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &written };
    var sender: TestSender = .{ .count = 2, .len = test_datagram_len };
    start_test_sockets(false);
    test_sockets.write(&out, &table, false, &sender, 0);
    const sends: u32 = if (batch_module.segmented) 1 else 2;
    try testing.expectEqual(sends, out.len);
    const send = written[0].kind.send_datagram;
    try testing.expectEqual(server.Ecn.ect_0, send.ecn);
    try testing.expectEqual(test_port, send.to.port);
    // A send's completion gives its batch back.
    const slot = table.find(written[0].id).?;
    table.finish(slot);
    test_sockets.complete(slot, &.{ .id = written[0].id, .result = .{ .datagram_sent = @intCast(send.bytes.len) } }, {}, take_nothing, 0);
    try testing.expectEqual(batch_module.Batch.State.free, test_sockets.batches.batches[0].state);
}

fn take_nothing(_: void, _: Received, _: u64) void {}
