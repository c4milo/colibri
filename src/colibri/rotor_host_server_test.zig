//! The tests of a `colibri.Server`'s sockets on colibri's own Rotor host (design §8 step 37,
//! decision 159): `init` binds the listener and the UDP socket on one port, `run` closes them and
//! each accepted socket, also when it fails, and `deinit` then closes neither of the first two
//! again. The system gives the lowest free number to the next descriptor, so two sockets the test
//! opens after `run` take the old numbers, and a second close would close them. Decision 150
//! ruling 7 lets these tests bind loopback.
const std = @import("std");
const rotor = @import("rotor");
const server = @import("server");
const testdata = @import("testdata");
const server_module = @import("server.zig");
const server_loop = @import("server_loop.zig");
const rotor_host = @import("rotor_host.zig");
const support = @import("test_support.zig");

const testing = std.testing;

/// RFC 9110 §15.6.1: 500 (Internal Server Error).
const internal_server_error: server.Status = .internal_server_error;
/// The room of the router's one response, which holds a head and no body.
const response_bytes = 64;

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/", answer },
    },
};
const Router = server.Router(void, routes, .{ .requests = 1, .response_bytes = response_bytes, .body_bytes = 0 });

fn answer(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.end();
}

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}

/// A server with one TCP connection and one QUIC connection, so `init` opens the UDP socket.
const TestServer = server_module.Server(.{ .tcp_connections = 1, .quic_connections = 1 }, .private);
const listener_id = server_loop.listener_id(1);
const datagram_id = server_loop.datagram_id(1);
const socket_id: @import("host.zig").SocketId = @enumFromInt(0);

/// The server and its router, which the test places outside any stack frame. Test-only.
var test_server: TestServer align(@alignOf(TestServer)) = undefined;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};

fn serve() void {
    test_server.run() catch |failure| std.debug.panic("run failed: {t}", .{failure});
}

fn init_with_identity(counter: *support.Counter) !void {
    try test_server.init(&.{
        .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem },
        .cpu = support.cpu(),
        .unix_seconds = testdata.now_seconds,
        .random = counter.random(),
    }, &router, &context);
}

test "design §8 step 37c: an identity opens UDP on the listener's port, which Alt-Svc names" {
    var counter: support.Counter = .{};
    try init_with_identity(&counter);
    defer test_server.deinit();
    try testing.expect(test_server.udp.served);
    const local = try rotor.sync.local_address(test_server.host.descriptor_of(datagram_id));
    try testing.expectEqual(test_server.port(), local.port);
    // RFC 7838 §3: the TCP connections over TLS advertise h3 on the same port.
    try testing.expectEqual(test_server.port(), test_server.engine_config.h3_alternative.?.port);
}

test "design §8 step 37: deinit closes the listener and the UDP socket, and wipes both keys" {
    var counter: support.Counter = .{};
    try init_with_identity(&counter);
    const listener = test_server.host.descriptor_of(listener_id);
    const udp_socket = test_server.host.descriptor_of(datagram_id);
    try testing.expect(!std.mem.allEqual(u8, &test_server.identity.key.private_key, 0));
    try testing.expect(!std.mem.allEqual(u8, &test_server.identity.cookie_key, 0));
    test_server.deinit();
    // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
    try testing.expectError(error.Unexpected, rotor.sync.local_address(listener));
    try testing.expectError(error.Unexpected, rotor.sync.local_address(udp_socket));
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.key.private_key, 0));
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.cookie_key, 0));
}

test "design §8 step 37: deinit after run closes no socket a second time" {
    var counter: support.Counter = .{};
    router = .{};
    try init_with_identity(&counter);
    const listener = test_server.host.descriptor_of(listener_id);
    const udp_socket = test_server.host.descriptor_of(datagram_id);
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
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.ticket_key, 0));
}

/// Starts the loop of a server in cleartext, as `run` does before its first turn.
fn begin_cleartext(counter: *support.Counter) !void {
    try test_server.init(&.{ .cpu = support.cpu(), .unix_seconds = testdata.now_seconds, .random = counter.random() }, &router, &context);
    _ = try test_server.host.begin();
}

/// Ends a run as `run` does, whether it finished or failed.
fn end_run() void {
    test_server.host.end();
    test_server.host.close_open();
}

/// Records `descriptor` as the socket an accept gave socket 0, as the host does.
fn hold_accepted(descriptor: rotor.Descriptor) void {
    test_server.host.descriptors[0] = descriptor;
    test_server.host.states[0] = .open;
}

test "design §8 step 37: the end of a run closes an accepted socket whose close was never submitted" {
    var counter: support.Counter = .{};
    try begin_cleartext(&counter);
    defer test_server.deinit();
    // A socket the listener accepted, as the test opens it.
    const descriptor = try rotor.sync.open_socket(.ipv4);
    hold_accepted(descriptor);
    // A run that fails, as a failed tick does, ends with the socket open.
    end_run();
    try testing.expect(!test_server.host.open(socket_id));
    // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
    try testing.expectError(error.Unexpected, rotor.sync.local_address(descriptor));
}

test "design §8 step 42: the end of a run closes an accepted socket whose close it canceled" {
    var counter: support.Counter = .{};
    try begin_cleartext(&counter);
    defer test_server.deinit();
    const descriptor = try rotor.sync.open_socket(.ipv4);
    hold_accepted(descriptor);
    // The socket failed, so the driver wrote its close. io_uring holds it until the next tick, and
    // the end's `cancel_all` cancels it there. kqueue and epoll closed the socket at submit.
    test_server.host.submit(&.{ .id = @enumFromInt(0), .kind = .{ .close = .{ .socket = socket_id } } });
    try testing.expectEqual(.closing, test_server.host.states[0]);
    end_run();
    try testing.expect(!test_server.host.open(socket_id));
    // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
    try testing.expectError(error.Unexpected, rotor.sync.local_address(descriptor));
}

test "decision 160: the end of a run reads a shutdown of a write side, and closes its socket" {
    var counter: support.Counter = .{};
    try begin_cleartext(&counter);
    defer test_server.deinit();
    const descriptor = try rotor.sync.open_socket(.ipv4);
    hold_accepted(descriptor);
    // A staged close left the shutdown in flight. The socket has no peer, so the shutdown fails.
    test_server.host.submit(&.{ .id = @enumFromInt(0), .kind = .{ .shutdown_send = .{ .socket = socket_id } } });
    try testing.expectEqual(.open, test_server.host.states[0]);
    end_run();
    try testing.expect(!test_server.host.open(socket_id));
    // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
    try testing.expectError(error.Unexpected, rotor.sync.local_address(descriptor));
}

/// The user data of the test's own operations on the server's loop: a socket past the host's
/// table, so the end of the run reads none of them as its own.
const test_user_data = rotor_host.user_data(@enumFromInt(0), .connect, @enumFromInt(server_loop.sockets_max(1)), 0);

/// Connects a socket of the test's own to the server's listener, through the server's loop, and
/// returns it once the connection waits in the listener's backlog.
fn connect_to_listener() !rotor.Descriptor {
    const address = try rotor_host.address_of("127.0.0.1", test_server.port());
    const descriptor = try rotor.sync.open_socket(.ipv4);
    errdefer rotor.sync.close_now(descriptor);
    const connect = rotor.Operation.connect(test_user_data, descriptor, &address);
    try testing.expectEqual(1, test_server.host.loop.submit(&.{connect}, &.{}));
    // Rotor reads the address until the event, so the test waits for it here.
    try testing.expectEqual(1, try test_server.host.loop.tick(test_server.host.events[0..1], connect_wait_ns));
    _ = try test_server.host.events[0].outcome();
    return descriptor;
}
const connect_wait_ns: u64 = 2_000_000_000;

test "design §8 step 42: the end of a run closes a socket an accept delivered after the run" {
    var counter: support.Counter = .{};
    try begin_cleartext(&counter);
    defer test_server.deinit();
    const peer = try connect_to_listener();
    defer rotor.sync.close_now(peer);
    // The peer sends in the tick of the accept, ahead of it, so that tick's one event is the
    // send's, and the accept's event stays for the end of the run.
    const free = try rotor.sync.open_socket(.ipv4);
    // The lowest free number, which the accept takes.
    rotor.sync.close_now(free);
    const accept_user_data = rotor_host.user_data(@enumFromInt(0), .accept, socket_id, 0);
    const operations = [_]rotor.Operation{
        rotor.Operation.send(test_user_data, peer, "GET"),
        rotor.Operation.accept(accept_user_data, test_server.host.descriptor_of(listener_id)),
    };
    try testing.expectEqual(2, test_server.host.loop.submit(&operations, &.{}));
    try testing.expectEqual(1, try test_server.host.loop.tick(test_server.host.events[0..1], 0));
    try testing.expectEqual(test_user_data, test_server.host.events[0].user_data);
    // The connection waits in the backlog, so the accept succeeds before `cancel_all` reaches it.
    end_run();
    // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
    try testing.expectError(error.Unexpected, rotor.sync.local_address(free));
}

test "design §8 step 37: init leaves no TCP socket open, so a run that fails at once closes none" {
    var counter: support.Counter = .{};
    // A socket of the test's own, which an earlier run's table still names.
    const descriptor = try rotor.sync.open_socket(.ipv4);
    defer rotor.sync.close_now(descriptor);
    hold_accepted(descriptor);
    try begin_cleartext(&counter);
    defer test_server.deinit();
    // The run failed before its first turn, so nothing else cleared the table before its end.
    end_run();
    // The end closed no descriptor the server does not hold.
    _ = try rotor.sync.local_address(descriptor);
}

/// The descriptors `ip_sockets_open` reads, from 0. The system gives each new descriptor the
/// lowest free number, so the few sockets of a test stay below it.
const descriptors_read = 1024;

/// How many descriptors below `descriptors_read` are open IP sockets: getsockname(2) gives an
/// address for each one. A count does not depend on the number a closed socket had, which the
/// system gives to the next file. The test reads it while no other thread of the test runs.
fn ip_sockets_open() u32 {
    var count: u32 = 0;
    for (0..descriptors_read) |descriptor| {
        if (rotor.sync.local_address(@intCast(descriptor))) |_| count += 1 else |_| {}
    }
    return count;
}

/// A TCP listener and a UDP socket of the test on one port of 127.0.0.1.
const HeldPort = struct { listener: rotor.Descriptor, datagram: rotor.Descriptor, port: u16 };

/// The ports `hold_port` tries. Another program can hold the UDP port of each TCP port it gets.
const hold_port_tries = 16;

/// Opens a TCP listener on a port the system chooses, then a UDP socket on that port. The listener
/// sets SO_REUSEPORT, as the server's does: the server binds the port too, and no other program
/// can take it before.
fn hold_port() !HeldPort {
    // Port 0 asks the system for a port.
    const any_port = try rotor_host.address_of("127.0.0.1", 0);
    for (0..hold_port_tries) |_| {
        const listener = try rotor.sync.listen(&any_port, .{ .backlog = 1, .reuse_port = true });
        errdefer rotor.sync.close_now(listener);
        const port = (try rotor.sync.local_address(listener)).port;
        if (try open_datagram_unless_held(port)) |datagram| {
            return .{ .listener = listener, .datagram = datagram, .port = port };
        }
        rotor.sync.close_now(listener);
    }
    return error.AddressInUse;
}

/// Closes `descriptor` when it is still a socket with an address, so that a test whose code under
/// test closed it fails on its own check and not on a second close.
fn close_if_open(descriptor: rotor.Descriptor) void {
    _ = rotor.sync.local_address(descriptor) catch return;
    rotor.sync.close_now(descriptor);
}

/// A UDP socket on `port` of 127.0.0.1, or null when another socket holds the port.
fn open_datagram_unless_held(port: u16) !?rotor.Descriptor {
    const address = try rotor_host.address_of("127.0.0.1", port);
    return rotor.sync.open_datagram(address.family, &address, .{}) catch |failure| switch (failure) {
        error.AddressInUse => null,
        else => failure,
    };
}

test "design §8 step 37: an init whose UDP open fails closes the listener and no other socket" {
    var counter: support.Counter = .{};
    // The test holds a port for TCP and UDP. The server's TCP bind shares the port, and its UDP
    // open on that port fails.
    const held = try hold_port();
    // init must not close either socket. When it does, the checks below fail, and these defers
    // must not stop the test binary on the second close.
    defer close_if_open(held.listener);
    defer close_if_open(held.datagram);
    // The number of an earlier server's UDP socket, which the program now uses for another file.
    test_server.host.descriptors[@intFromEnum(datagram_id)] = held.datagram;
    test_server.host.bound_port = 0;
    const open_before = ip_sockets_open();
    try testing.expectError(error.AddressInUse, test_server.init(&.{
        .port = held.port,
        .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem },
        .cpu = support.cpu(),
        .unix_seconds = testdata.now_seconds,
        .random = counter.random(),
    }, &router, &context));
    // The listener was bound, so the UDP open is the step that failed.
    try testing.expectEqual(held.port, test_server.host.bound_port);
    try testing.expect(!test_server.host.open(listener_id) and !test_server.host.open(datagram_id));
    // init closed the listener and the UDP socket it opened, and neither socket of the test.
    try testing.expectEqual(open_before, ip_sockets_open());
    _ = try rotor.sync.local_address(held.listener);
    _ = try rotor.sync.local_address(held.datagram);
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.key.private_key, 0));
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.cookie_key, 0));
}
