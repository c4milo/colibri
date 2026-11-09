//! The tests of a `colibri.Server` over TCP (design §8 step 37b): a server runs on a thread of its
//! own on 127.0.0.1, and a client of `std.Io.Threaded` fetches from it over h11, in cleartext and
//! over TLS. Decision 150 ruling 7 lets these tests bind loopback.
const std = @import("std");
const server = @import("server");
const testdata = @import("testdata");
const server_module = @import("server.zig");
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

/// How long the test client waits for the end of the server's data after its answer: the server's
/// half-close sends it at once, and its full close comes `half_close_ns`, 1 s, later.
const half_close_wait_us: i32 = 500_000;
const microseconds_per_second: i32 = 1_000_000;

test "decision 160: a POST past the bound reads its 501 whole, then the half-close ends the data" {
    var counter: support.Counter = .{};
    router = .{};
    try test_server.init(.{ .cpu = support.cpu(), .random = counter.random() });
    defer test_server.deinit();
    const thread = try std.Thread.spawn(.{}, serve, .{});
    defer thread.join();
    defer test_server.shutdown();
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", test_server.port());
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    // A read that waits longer than the half-close needs fails, so a full close at 1 s fails it.
    const wait: std.posix.timeval = .{ .sec = @divTrunc(half_close_wait_us, microseconds_per_second), .usec = half_close_wait_us };
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&wait));
    var write_buffer: [client_buffer_len]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    // RFC 9112 §9.3: 1 MiB is past `discard_len_max`, so the server closes in stages.
    try writer.interface.writeAll("POST /greeting HTTP/1.1\r\nHost: a\r\nContent-Length: 1048576\r\n\r\nabc");
    try writer.interface.flush();
    var read_buffer: [client_buffer_len]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var response: [response_len]u8 = undefined;
    const len = try reader.interface.readSliceShort(&response);
    // RFC 9110 §15.6.2: no route names POST, so the router answers 501 at the head.
    try testing.expect(std.mem.startsWith(u8, response[0..len], "HTTP/1.1 501"));
    try testing.expect(std.mem.endsWith(u8, response[0..len], "\r\n\r\n"));
}
