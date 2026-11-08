//! The tests of a `colibri.Server` over TCP (design §8 step 37b): a server runs on a thread of its
//! own on 127.0.0.1, and a client of `std.Io.Threaded` fetches from it over h11, in cleartext and
//! over TLS. Decision 150 ruling 7 lets these tests bind loopback. The test of the staged close
//! (decision 160) starts no thread: it runs the loop itself, a turn at a time, and names the
//! instant of each turn.
const std = @import("std");
const server = @import("server");
const testdata = @import("testdata");
const server_module = @import("server.zig");
const server_loop = @import("server_loop.zig");
const socket_module = @import("socket.zig");
const support = @import("test_support.zig");

const testing = std.testing;

const greeting = "hello from colibri";
/// The connections the test server holds, the router's requests at once, and its response room.
const connections = 2;
const response_bytes = 256;
/// The buffers of the test client's reader and writer, and the room for a response.
const client_buffer_len = 256;
const response_len = 1024;
/// The buffers of the test client's TLS records: std's client needs room for one record.
const record_buffer_len = std.crypto.tls.Client.min_buffer_len;
/// RFC 9110 §15.6.1: 500 (Internal Server Error).
const internal_server_error: server.Status = .internal_server_error;

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/greeting", greet },
    },
};
const Router = server.Router(void, routes, .{ .requests = connections, .response_bytes = response_bytes, .body_bytes = 0 });

fn greet(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.header("content-type", "text/plain");
    try response.body().writeAll(greeting);
    try response.end();
}

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}

const TestServer = server_module.ServerOf(.{ .tcp_connections = connections, .quic_connections = 0 });

/// The server and its router, which the tests place outside any stack frame. Test-only.
var test_server: TestServer align(@alignOf(TestServer)) = undefined;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};

fn serve() void {
    test_server.run(&router, &context) catch |failure| std.debug.panic("run failed: {t}", .{failure});
}

/// Sends `request` over a new connection to the server, and returns what the server sent until it
/// closed the connection or `response` is full.
fn fetch(io: std.Io, request: []const u8, response: []u8) ![]const u8 {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", test_server.port());
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var write_buffer: [client_buffer_len]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.writeAll(request);
    try writer.interface.flush();
    var read_buffer: [client_buffer_len]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const len = try reader.interface.readSliceShort(response);
    return response[0..len];
}

test "decision 150: a server on port 0 answers an h11 request through its router, and shuts down" {
    var counter: support.Counter = .{};
    router = .{};
    try test_server.init(.{ .cpu = support.cpu(), .random = counter.random() });
    try testing.expect(test_server.port() != 0);
    const thread = try std.Thread.spawn(.{}, serve, .{});
    var threaded: std.Io.Threaded = .init_single_threaded;
    var response: [response_len]u8 = undefined;
    // RFC 9112 §9.6: "Connection: close" makes the server close the connection after the
    // response, so the read ends.
    const answer = try fetch(threaded.io(), "GET /greeting HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", &response);
    try testing.expect(std.mem.startsWith(u8, answer, "HTTP/1.1 200"));
    try testing.expect(std.mem.endsWith(u8, answer, greeting));
    const missing = try fetch(threaded.io(), "GET /missing HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", &response);
    try testing.expect(std.mem.startsWith(u8, missing, "HTTP/1.1 404"));
    test_server.shutdown();
    thread.join();
    test_server.deinit();
}

/// Sends `request` over a new TLS connection to the server, and returns what the server sent until
/// it closed the connection or `response` is full. The client judges no certificate: the test
/// shows the server's TLS path, not the client's trust.
fn fetch_tls(io: std.Io, request: []const u8, response: []u8) ![]const u8 {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", test_server.port());
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var socket_write: [record_buffer_len]u8 = undefined;
    var socket_read: [record_buffer_len]u8 = undefined;
    var writer = stream.writer(io, &socket_write);
    var reader = stream.reader(io, &socket_read);
    var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    var counter: support.Counter = .{};
    counter.random().bytes(&entropy);
    var plain_write: [record_buffer_len]u8 = undefined;
    var plain_read: [record_buffer_len]u8 = undefined;
    var client = try std.crypto.tls.Client.init(&reader.interface, &writer.interface, .{
        .host = .no_verification,
        .ca = .no_verification,
        .write_buffer = &plain_write,
        .read_buffer = &plain_read,
        .entropy = &entropy,
        .realtime_now = .zero,
        // RFC 9112 §9.6: the server may close after "Connection: close" with no close_notify.
        .allow_truncation_attacks = true,
    });
    try client.writer.writeAll(request);
    try client.writer.flush();
    try writer.interface.flush();
    const len = try client.reader.readSliceShort(response);
    return response[0..len];
}

test "decision 150: a server with an identity answers an h11 request over TLS" {
    var counter: support.Counter = .{};
    router = .{};
    try test_server.init(.{ .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem }, .cpu = support.cpu(), .random = counter.random() });
    defer test_server.deinit();
    const thread = try std.Thread.spawn(.{}, serve, .{});
    defer thread.join();
    defer test_server.shutdown();
    var threaded: std.Io.Threaded = .init_single_threaded;
    var response: [response_len]u8 = undefined;
    // std's client offers no ALPN, and the server then speaks h11.
    const answer = try fetch_tls(threaded.io(), "GET /greeting HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", &response);
    try testing.expect(std.mem.startsWith(u8, answer, "HTTP/1.1 200"));
    try testing.expect(std.mem.endsWith(u8, answer, greeting));
}

/// How long one turn of a test's own loop waits for an event, and the turns one wait of a test
/// takes at most. A turn returns as soon as an event is ready. A wait takes all its turns, 10 s,
/// only when its event never comes, and the test then fails.
const turn_wait_ns: u64 = 10_000_000;
const turns_max: usize = 1000;

/// What a test that runs the server's loop itself passes each turn, as `run` holds it.
const Running = struct { server: *TestServer, router: *Router, context: *void };

/// Starts the loop and the engine of `test_server` on the test's thread, as `run` starts them.
/// The test then runs each turn itself, so it names the instant of each. Test-only.
fn start_loop() !Running {
    try test_server.loop.init(&test_server.loop_memory, &.{ .operations = test_server.events.len });
    server_loop.reset(&test_server);
    try test_server.engine.init(&test_server.engine_config, test_server.config.random.?, .{ .ns = test_server.now_ns, .unix_seconds = 0 });
    return .{ .server = &test_server, .router = &router, .context = &context };
}

/// One turn of the server's loop at `now_ns`, an instant that the test names. Returns the octets
/// that the receives of the first socket read in the turn. Test-only.
fn turn_at(running: *Running, now_ns: u64) !usize {
    const state = running.server;
    const deadline_ns = server_loop.prepare(state);
    const count = try state.loop.tick(&state.events, turn_wait_ns);
    var read: usize = 0;
    for (state.events[0..count]) |event| {
        if (event.user_data == socket_module.user_data(0, .receive)) read += event.outcome() catch 0;
    }
    server_loop.handle(running, state.events[0..count], deadline_ns, now_ns);
    return read;
}

/// What a test waits for in the server's first socket: the end of the shutdown of its write
/// side, a receive that read octets, the end of its connection, or its own end.
const Wait = enum { shut_down, read, ended, freed };

/// Turns the loop at `now_ns` until `wait` holds, and fails after `turns_max` turns. Test-only.
fn turn_until(running: *Running, wait: Wait, now_ns: u64) !void {
    const socket = &test_server.sockets[0];
    for (0..turns_max) |_| {
        const read = try turn_at(running, now_ns);
        const reached = switch (wait) {
            .shut_down => socket.live and socket.shutdown_submitted and !socket.shutting_down,
            .read => read > 0,
            .ended => !test_server.entries[0].attached,
            .freed => !socket.live,
        };
        if (reached) return;
    }
    return error.TestUnexpectedResult;
}

test "decision 160: after the half-close the socket receives again, and the peer's close ends the connection" {
    var counter: support.Counter = .{};
    router = .{};
    try test_server.init(.{ .cpu = support.cpu(), .random = counter.random() });
    defer test_server.deinit();
    var running = try start_loop();
    defer server_loop.end(&test_server);
    // Each turn gets this one instant, so the bound of `half_close_ns` cannot pass in the test.
    const now_ns = test_server.now_ns;
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", test_server.port());
    const stream = try address.connect(io, .{ .mode = .stream });
    var client_open = true;
    defer if (client_open) stream.close(io);
    var write_buffer: [client_buffer_len]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    // RFC 9112 §9.3: 1 MiB is past `discard_len_max`, so the server closes in stages.
    try writer.interface.writeAll("POST /greeting HTTP/1.1\r\nHost: a\r\nContent-Length: 1048576\r\n\r\nabc");
    try writer.interface.flush();
    try turn_until(&running, .shut_down, now_ns);
    const socket = &test_server.sockets[0];
    try testing.expect(socket.half_closing and !socket.closing and !socket.failed);
    // RFC 9112 §9.6: the bound runs from the `half_close`, at the one instant of this test.
    try testing.expectEqual(now_ns + server.constants.limits.half_close_ns, test_server.engine.deadline_ns().?);
    // The shutdown ran, so the read ends at the end of the server's data, and waits for no clock.
    var read_buffer: [client_buffer_len]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var response: [response_len]u8 = undefined;
    const answer = response[0..try reader.interface.readSliceShort(&response)];
    // RFC 9110 §15.6.2: no route names POST, so the router answers 501 at the head.
    try testing.expect(std.mem.startsWith(u8, answer, "HTTP/1.1 501"));
    try testing.expect(std.mem.endsWith(u8, answer, "\r\n\r\n"));
    // RFC 9110 §10.1.1: the Content-Length is past the bound, so the 501 says that the server closes.
    try testing.expect(std.mem.indexOf(u8, answer, "\r\nConnection: close\r\n") != null);
    // RFC 9112 §9.6: the client writes on, and the socket reads the octets and then receives again.
    try writer.interface.writeAll("more of the body");
    try writer.interface.flush();
    try turn_until(&running, .read, now_ns);
    try testing.expect(socket.receiving and socket.unread().len == 0);
    // The peer closes first. The receive reads its close, and the connection ends with no `close`
    // from the engine, at the instant of the `half_close`.
    stream.close(io);
    client_open = false;
    try turn_until(&running, .ended, now_ns);
    try testing.expect(socket.failed and !test_server.entries[0].closing);
    try turn_until(&running, .freed, now_ns);
}
