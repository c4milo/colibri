//! The tests of a socket's send side (`socket.zig`): the operations it writes, the final
//! completions it waits for, the shutdown of a staged close, and the count each send hands back
//! (decision 159, decision 160, design §8 step 79). Split from `socket.zig`, which stays under 500
//! lines.
const std = @import("std");
const constants = @import("constants.zig");
const host = @import("host.zig");
const operation_table = @import("operation_table.zig");
const socket_module = @import("socket.zig");

const testing = std.testing;
const slots_per_socket = socket_module.slots_per_socket;
const operations_per_socket = socket_module.operations_per_socket;

/// The socket the tests drive, outside any stack frame: its buffers are larger than one should
/// hold. Test-only.
threadlocal var test_socket: socket_module.Socket align(@alignOf(socket_module.Socket)) = undefined;

test "decision 159: a socket writes the operations it needs, and none while they are in flight" {
    var table: operation_table.Table(slots_per_socket) = .empty;
    var operations: [operations_per_socket]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &operations };
    test_socket.open();
    test_socket.give("abc");
    try testing.expect(test_socket.arm(&out, &table, 0));
    try testing.expectEqual(2, out.len);
    try testing.expectEqualStrings("abc", operations[0].kind.send.bytes);
    try testing.expectEqual(constants.limits.socket_input_len, operations[1].kind.receive.buffer.len);
    try testing.expectEqual(2, table.count);
    // Both are in flight, so a second turn writes nothing.
    try testing.expect(test_socket.arm(&out, &table, 0));
    try testing.expectEqual(2, out.len);
    // A failed socket writes its close alone, and an outbox with no room leaves it owed.
    test_socket.failed = true;
    out = .{ .operations = operations[0..0] };
    try testing.expect(!test_socket.arm(&out, &table, 0));
    try testing.expect(out.full and !test_socket.close_submitted);
    out = .{ .operations = &operations };
    try testing.expect(test_socket.arm(&out, &table, 0));
    try testing.expect(operations[0].kind == .close);
    try testing.expect(test_socket.close_submitted);
}

test "decision 159: a socket whose close completes first is finished only after its receive's final completion" {
    test_socket.open();
    test_socket.receiving = true;
    test_socket.sending = true;
    // Rule 2: the host may give the close's completion before those of the operations it ended.
    test_socket.closed = true;
    try testing.expect(!test_socket.finished());
    try testing.expectEqual(0, test_socket.on_sent(.canceled));
    try testing.expect(!test_socket.finished());
    test_socket.on_received(.canceled);
    try testing.expect(test_socket.finished());
    // The same holds when the send's final completion comes last.
    test_socket.open();
    test_socket.receiving = true;
    test_socket.sending = true;
    test_socket.closed = true;
    test_socket.on_received(.canceled);
    try testing.expect(!test_socket.finished());
    _ = test_socket.on_sent(.canceled);
    try testing.expect(test_socket.finished());
}

test "decision 160: the write side closes once the octets are out, and the socket is finished after it" {
    var table: operation_table.Table(slots_per_socket) = .empty;
    var operations: [operations_per_socket]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &operations };
    test_socket.open();
    test_socket.half_closing = true;
    test_socket.give("abc");
    // RFC 9112 §9.6: the response goes out first.
    try testing.expect(!test_socket.half_close_due());
    try testing.expect(test_socket.arm(&out, &table, 0));
    try testing.expectEqual(2, out.len);
    try testing.expect(operations[0].kind == .send and operations[1].kind == .receive);
    try testing.expectEqual(3, test_socket.on_sent(.{ .sent = 3 }));
    try testing.expect(test_socket.half_close_due());
    out = .{ .operations = &operations };
    try testing.expect(test_socket.arm(&out, &table, 0));
    // The shutdown is written once, and the receive stays in flight.
    try testing.expectEqual(1, out.len);
    try testing.expectEqual(0, @intFromEnum(operations[0].kind.shutdown_send.socket));
    try testing.expect(test_socket.receiving and !test_socket.half_close_due());
    // The close may complete before the shutdown that it ended.
    test_socket.closed = true;
    try testing.expect(!test_socket.finished());
    test_socket.on_received(.canceled);
    test_socket.on_shut_down(.canceled);
    try testing.expect(test_socket.finished() and test_socket.failed);
    // A socket that failed shuts nothing down.
    test_socket.open();
    test_socket.half_closing = true;
    test_socket.failed = true;
    try testing.expect(!test_socket.half_close_due());
}

test "design §8 step 79: a send hands back its count, and a stopped socket drops what it was given" {
    var table: operation_table.Table(slots_per_socket) = .empty;
    var operations: [operations_per_socket]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &operations };
    test_socket.open();
    test_socket.give("abcde");
    try testing.expect(test_socket.arm(&out, &table, 0));
    // A send in flight still owns what it writes.
    try testing.expectEqual(0, test_socket.drop_unsent());
    try testing.expectEqual(2, test_socket.on_sent(.{ .sent = 2 }));
    try testing.expectEqual(0, test_socket.outgoing.len);
    // A socket that failed before it wrote the send hands back all it was given, sent by none.
    test_socket.give("cde");
    test_socket.failed = true;
    try testing.expectEqual(3, test_socket.drop_unsent());
    try testing.expectEqual(0, test_socket.outgoing.len);
}
