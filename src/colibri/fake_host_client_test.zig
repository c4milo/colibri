//! A test of a `.hosted` `colibri.Client` on a fake host (decision 159, rule 2): the client
//! stops only once each operation had its final completion. The test is the host, and opens no
//! socket. The other tests of hosted objects are in `fake_host_test.zig`.
const std = @import("std");
const client = @import("client");
const server = @import("server");
const host = @import("host.zig");
const client_module = @import("client.zig");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");

const testing = std.testing;

/// The turns the test runs at most, and the room each turn writes into.
const turns_max = 8;
const operations_len = 16;
/// The instant of `init`: the test identity's Unix seconds, and the host's first instant.
const started: server.Timestamp = .{ .unix_seconds = fixture.now_seconds, .monotonic_ns = 0 };

/// A hosted client with one TCP connection and QUIC, which the test places outside any stack
/// frame. Test-only.
const TestClient = client_module.Client(.{ .tcp_connections = 1, .requests = fixture.requests_max }, .hosted);
var test_client: TestClient align(@alignOf(TestClient)) = undefined;

/// A handler that the test never calls, because the client gets no request. Test-only.
const IdleHandler = struct {
    pub fn on_finished(_: *IdleHandler, _: *TestClient, _: client.Finished) void {
        unreachable;
    }
};

test "decision 159: a client stops once its cancelled receive of datagrams had its final completion" {
    var counter: support.Counter = .{};
    var handler: IdleHandler = .{};
    const pool = fixture.pool_config(.{ .prefer = .quic }, true);
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = pool, .random = counter.random(), .now = started, .datagram = .{ .ipv4 = .{} } }, &handler);
    var operations: [operations_len]host.Operation = undefined;
    var turned = test_client.turn(0, &operations);
    try testing.expectEqual(1, turned.operations);
    const receive = operations[0];
    try testing.expect(receive.kind == .receive_datagram);
    test_client.shutdown();
    var canceled = false;
    for (0..turns_max) |_| {
        turned = test_client.turn(1, &operations);
        for (operations[0..turned.operations]) |operation| {
            if (operation.kind == .cancel and operation.kind.cancel.target == receive.id) canceled = true;
        }
    }
    // The pool closed and no TCP socket is live, but the receive still owes its final completion.
    try testing.expect(canceled and test_client.closed);
    try testing.expect(!test_client.stopped());
    test_client.complete(&.{ .id = receive.id, .result = .canceled }, 1);
    try testing.expect(test_client.stopped());
    test_client.deinit();
}
