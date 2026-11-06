//! The tests of `Server.deinit` after `run` and of the end of `run` (design §8 step 37). `run`
//! closes the listener, the UDP socket and each accepted socket, also when it fails, and `deinit`
//! then closes neither of the first two again. The system gives the lowest free number to
//! the next descriptor, so two sockets the test opens after `run` take the old numbers, and a
//! second close would close them. Decision 150 ruling 7 lets this test bind loopback.
const std = @import("std");
const rotor = @import("rotor");
const server = @import("server");
const testdata = @import("testdata");
const server_module = @import("server.zig");
const server_loop = @import("server_loop.zig");
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
        .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem },
        .cpu = support.cpu(),
        .random = counter.random(),
    });
    try testing.expect(test_server.udp.open);
    const listener = test_server.listener;
    const udp_socket = test_server.udp.descriptor;
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

/// Starts the loop of a server in cleartext, as `run` does before its first turn.
fn begin_cleartext(counter: *support.Counter) !void {
    try test_server.init(.{ .cpu = support.cpu(), .random = counter.random() });
    try test_server.loop.init(&test_server.loop_memory, .{ .operations = test_server.events.len });
}

test "design §8 step 37: the end of a run closes an accepted socket whose close was never submitted" {
    var counter: support.Counter = .{};
    try begin_cleartext(&counter);
    defer test_server.deinit();
    server_loop.reset(&test_server);
    // A socket the listener accepted, as the test opens it.
    const descriptor = try rotor.sync.open_socket(.ipv4);
    test_server.sockets[0].open(descriptor);
    // A run that fails, as a failed tick does, ends with the socket open.
    server_loop.end(&test_server);
    try testing.expect(!test_server.sockets[0].live);
    // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
    try testing.expectError(error.Unexpected, rotor.sync.local_address(descriptor));
}

test "design §8 step 37: init leaves no TCP socket live, so a run that fails at once closes none" {
    var counter: support.Counter = .{};
    // A socket of the test's own, which an earlier run's entry still names.
    const descriptor = try rotor.sync.open_socket(.ipv4);
    defer rotor.sync.close_now(descriptor);
    test_server.sockets[0].descriptor = descriptor;
    test_server.sockets[0].close_submitted = false;
    test_server.sockets[0].live = true;
    try begin_cleartext(&counter);
    defer test_server.deinit();
    // The run failed before `reset`, so nothing else cleared the sockets before its end.
    server_loop.end(&test_server);
    // The end closed no descriptor the server does not hold.
    _ = try rotor.sync.local_address(descriptor);
}
