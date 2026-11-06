//! The test of `Server.deinit` after `run` (design §8 step 37): `run` closes the listener and the
//! UDP socket, and `deinit` then closes neither again. The system gives the lowest free number to
//! the next descriptor, so two sockets the test opens after `run` take the old numbers, and a
//! second close would close them. Decision 150 ruling 7 lets this test bind loopback.
const std = @import("std");
const rotor = @import("rotor");
const server = @import("server");
const testdata = @import("testdata");
const server_module = @import("server.zig");
const support = @import("test_support.zig");

const testing = std.testing;

/// RFC 9110 §15.6.1: 500 (Internal Server Error).
const internal_server_error = 500;
/// The room of the router's one response, which holds a head and no body.
const response_bytes = 64;

const routes = server.router(void, .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/", answer },
    },
});
const Router = @TypeOf(routes).Of(.{ .requests = 1, .response_bytes = response_bytes, .body_bytes = 0 });

fn answer(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.end();
}

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}

/// A server with one TCP connection and one QUIC connection, so `init` opens the UDP socket.
const TestServer = server_module.ServerOf(.{ .tcp_connections = 1, .quic_connections = 1 });

/// The server and its router, which the test places outside any stack frame. Test-only.
var test_server: TestServer align(@alignOf(TestServer)) = undefined;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};

fn serve() void {
    test_server.run(&router, &context) catch |failure| std.debug.panic("run failed: {t}", .{failure});
}

test "design §8 step 37: deinit after run closes no socket a second time" {
    var counter: support.Counter = .{};
    router = .{};
    try test_server.init(.{
        .identity = .{ .pem = .{ .chain = testdata.chain_pem, .key = testdata.key_pem } },
        .cpu = support.cpu(),
        .random = counter.random(),
    });
    try testing.expect(test_server.udp_open);
    const listener = test_server.listener;
    const udp_socket = test_server.udp_socket;
    const thread = try std.Thread.spawn(.{}, serve, .{});
    test_server.shutdown();
    thread.join();
    // `run` closed both sockets, and two new sockets take their numbers, the lower one first.
    const address = rotor.Address.ipv4(.{ 127, 0, 0, 1 }, 0);
    const first = try rotor.sync.listen(&address, .{ .backlog = 1, .reuse_port = false });
    const second = try rotor.sync.open_datagram(address.family, &address, .{});
    try testing.expectEqual(@min(listener, udp_socket), first);
    try testing.expectEqual(@max(listener, udp_socket), second);
    test_server.deinit();
    // A second close of an old number would have closed the new socket that holds it.
    _ = try rotor.sync.local_address(first);
    _ = try rotor.sync.local_address(second);
    rotor.sync.close_now(first);
    rotor.sync.close_now(second);
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.key.private_key, 0));
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.cookie_key, 0));
}
