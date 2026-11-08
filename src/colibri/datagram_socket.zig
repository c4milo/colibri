//! One UDP socket of a driver, with no QUIC and no I/O in it (design §8 steps 37c and 42,
//! decision 159). A server's UDP socket and a client's are each one of these. One receive stays
//! in flight, which the host completes once for each datagram, into its own memory. On Linux the
//! private host's kernel coalesces datagrams from one peer (UDP_GRO), which Rotor splits again,
//! and cuts each batch that the socket sends into datagrams (UDP_SEGMENT, design §8 step 13f.6).
//! Moved out of `server_udp.zig`, which took it from the test-only UDP server.
//!
//! The socket does not know who reads the datagrams or who writes them:
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

/// The slots of the driver's operation table that the socket holds, from its first: the receive,
/// then one send for each batch (`operation_table.zig`).
pub const slots: u32 = 1 + constants.limits.udp_batches;

/// The operations the UDP socket holds in flight: one receive and a send for each batch.
pub const operations: u32 = slots;

/// One datagram the socket read.
pub const Received = struct {
    bytes: []u8,
    ecn: ReceivedEcn,
    from: PeerAddress,
};

pub const DatagramSocket = struct {
    /// Whether the object has this socket: the host opened it before the run.
    served: bool,
    /// The socket's id in the host's table, and its first slot in the operation table.
    socket: host.SocketId,
    first_slot: u32,
    /// The receive is in flight, and a cancel of it was written.
    receiving: bool,
    receive_canceled: bool,
    /// The batches and their destinations, and the room each datagram is written in.
    batches: batch_module.Batches,
    datagram: [constants.limits.udp_datagram_len_max]u8,

    /// Starts a run: nothing in flight, and every batch free. The first `write` starts the
    /// receive.
    pub fn start(socket: *DatagramSocket, id: host.SocketId, first_slot: u32) void {
        assert(socket.served);
        socket.socket = id;
        socket.first_slot = first_slot;
        socket.receiving = false;
        socket.receive_canceled = false;
        socket.batches = .of(true);
    }

    /// Whether `slot` is one of the socket's slots.
    pub fn owns(socket: *const DatagramSocket, slot: u32) bool {
        return slot >= socket.first_slot and slot < socket.first_slot + slots;
    }

    /// Writes the receive while `receives` holds, and its cancel once it does not. Then it takes
    /// every datagram `sender` owes now, while a batch is free, and writes one send for each
    /// open batch.
    pub fn write(socket: *DatagramSocket, out: *operation_table.Outbox, table: anytype, receives: bool, sender: anytype, now_ns: u64) void {
        socket.write_receive(out, table, receives);
        // Bounded: each pass adds one datagram, and the batches hold at most this many.
        for (0..constants.limits.udp_batches * constants.limits.udp_segments_max) |_| {
            if (!socket.batches.has_free()) break;
            const sent = sender.send_datagram(&socket.datagram, now_ns) orelse break;
            socket.batches.add(sent);
        }
        for (&socket.batches.batches, 0..) |*batch, index| {
            if (batch.state != .open) continue;
            // A batch with no room stays open, and the next turn writes it.
            if (!out.room()) return;
            const id = table.issue(socket.first_slot + 1 + @as(u32, @intCast(index)));
            out.put(.{ .id = id, .kind = .{ .send_datagram = .{
                .socket = socket.socket,
                .bytes = batch.bytes[0..batch.len],
                .to = batch.to,
                .ecn = batch.ecn,
                .segment_bytes = batch.segment_bytes(),
            } } });
            batch.state = .sending;
        }
    }

    /// Starts the receive again after its final completion while `receives` holds. Once it does
    /// not, it cancels the receive in flight, whose final completion follows.
    fn write_receive(socket: *DatagramSocket, out: *operation_table.Outbox, table: anytype, receives: bool) void {
        if (receives and !socket.receiving) {
            if (!out.room()) return;
            out.put(.{ .id = table.issue(socket.first_slot), .kind = .{ .receive_datagram = .{ .socket = socket.socket } } });
            socket.receiving = true;
            socket.receive_canceled = false;
            return;
        }
        if (receives or !socket.receiving or socket.receive_canceled) return;
        if (!out.room()) return;
        const target = table.id(socket.first_slot);
        out.put(.{ .id = target, .kind = .{ .cancel = .{ .target = target } } });
        socket.receive_canceled = true;
    }

    /// Takes one completion of the socket's `slot`. A send's gives its batch back. A receive's
    /// hands its datagram to `take(context, received, now_ns)` at once, because the host lends
    /// the bytes for the call alone. After the receive's final completion the next `write`
    /// starts it again.
    pub fn complete(socket: *DatagramSocket, slot: u32, completion: *const host.Completion, context: anytype, comptime take: anytype, now_ns: u64) void {
        assert(socket.owns(slot));
        if (slot != socket.first_slot) {
            assert(completion.final());
            socket.batches.release(slot - socket.first_slot - 1);
            return;
        }
        switch (completion.result) {
            .datagram => |datagram| take(context, .{ .bytes = datagram.bytes, .ecn = datagram.ecn, .from = datagram.from }, now_ns),
            else => assert(completion.final()),
        }
        if (completion.final()) socket.receiving = false;
    }
};

comptime {
    assert(constants.limits.udp_batches > 0);
    // A server's datagrams and a client's carry one address type and one codepoint type, so one
    // socket serves both (decisions 68 and 72).
    assert(@FieldType(server.Datagram, "from") == PeerAddress);
    assert(ReceivedEcn == server.Ecn);
}

const testing = std.testing;

/// A sender that owes `count` datagrams of `len` octets to one peer. Test-only.
const TestSender = struct {
    count: u32,
    len: usize,

    pub fn send_datagram(sender: *TestSender, output: []u8, _: u64) ?server.Sent {
        if (sender.count == 0) return null;
        sender.count -= 1;
        @memset(output[0..sender.len], 'd');
        return .{ .bytes = output[0..sender.len], .ecn = .ect_0, .to = test_peer };
    }
};
const test_loopback_word: u32 = 0x7f00_0001;
const test_loopback: [@sizeOf(u32)]u8 = @bitCast(std.mem.nativeToBig(u32, test_loopback_word));
const test_port: u16 = 4433;
const test_peer = PeerAddress.of(&test_loopback, test_port);
const test_datagram_len = 1200;

/// The socket the tests drive, outside any stack frame. Test-only.
threadlocal var test_socket: DatagramSocket align(@alignOf(DatagramSocket)) = undefined;

test "decision 159: the receive is written once, and cancelled once receives stop" {
    var table: operation_table.Table(slots) = .empty;
    var written: [slots]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &written };
    var sender: TestSender = .{ .count = 0, .len = test_datagram_len };
    test_socket.served = true;
    test_socket.start(@enumFromInt(3), 0);
    test_socket.write(&out, &table, true, &sender, 0);
    try testing.expectEqual(1, out.len);
    try testing.expectEqual(3, @intFromEnum(written[0].kind.receive_datagram.socket));
    test_socket.write(&out, &table, true, &sender, 0);
    try testing.expectEqual(1, out.len);
    // Receives stop: one cancel names the receive, and a later turn writes no second one.
    test_socket.write(&out, &table, false, &sender, 0);
    test_socket.write(&out, &table, false, &sender, 0);
    try testing.expectEqual(2, out.len);
    try testing.expectEqual(written[0].id, written[1].kind.cancel.target);
}

test "decision 159: the engine's datagrams leave in one send for each batch, with their codepoint" {
    var table: operation_table.Table(slots) = .empty;
    var written: [slots]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &written };
    var sender: TestSender = .{ .count = 2, .len = test_datagram_len };
    test_socket.served = true;
    test_socket.start(@enumFromInt(0), 0);
    test_socket.write(&out, &table, false, &sender, 0);
    const sends: u32 = if (batch_module.segmented) 1 else 2;
    try testing.expectEqual(sends, out.len);
    const send = written[0].kind.send_datagram;
    try testing.expectEqual(server.Ecn.ect_0, send.ecn);
    try testing.expectEqual(test_port, send.to.port);
    // A send's completion gives its batch back.
    const slot = table.find(written[0].id).?;
    table.finish(slot);
    test_socket.complete(slot, &.{ .id = written[0].id, .result = .{ .datagram_sent = @intCast(send.bytes.len) } }, {}, take_nothing, 0);
    try testing.expectEqual(batch_module.Batch.State.free, test_socket.batches.batches[0].state);
}

fn take_nothing(_: void, _: Received, _: u64) void {}
