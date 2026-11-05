//! Example: a program serves a route table through `colibri.Server`, the one module of colibri that
//! binds sockets and runs a loop (decision 150).
//!
//! The program gives the server a host, a port and its CPU, and calls `init`, which binds. Port 0
//! asks the system for a port, which `port()` returns. `run` serves on the thread that calls it,
//! through Rotor's loop, until another thread calls `shutdown`. With no identity the server speaks
//! h11 and h2 in cleartext, and opens no UDP socket.
//!
//! The run goes in this order:
//! 1. The program places the server and calls `init` on 127.0.0.1, port 0.
//! 2. A thread of its own calls `run` with the router of a route table.
//! 3. A client of `std.Io.Threaded` sends two GETs over h11, each on a connection of its own, and
//!    checks each response octet for octet.
//! 4. The program calls `shutdown`, and `run` returns once each connection has closed.
//!
//! This example binds a loopback socket, which decision 96 as amended allows for `colibri` alone.
//! The fetch over h2 and h3 comes with `colibri.Client` (design §8 step 42).
//!
//! Run it with `zig build example-colibri_server`, or every example with `zig build examples`.
const std = @import("std");
const colibri = @import("colibri");
const server = @import("server");
const tls = @import("tls");
const platform = @import("platform");
// chapulin's hook, which every program that links `tls` defines.
const program = @import("tls_program.zig");

comptime {
    _ = program;
}

/// The program's own state, which each route's function gets: the requests it answered.
const App = struct {
    answered: u32 = 0,
};
var app: App align(@alignOf(App)) = .{};

/// The server's table of routes, which the compiler builds and checks.
const routes = server.router(App, .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/greeting", greet },
        .{ .get, "/greetings/:name", greet_named },
    },
});

/// The router's pool: an entry for each request at once, with room for its response.
const Router = @TypeOf(routes).Of(.{ .requests = connections, .response_bytes = 256, .body_bytes = 0 });
var router: Router align(@alignOf(Router)) = .{};

/// A server that holds four TCP connections and no QUIC connection. `colibri.Server` is the
/// default capacity. The program places the server once, outside any stack frame, and does not
/// move it.
const connections = 4;
const Server = colibri.ServerOf(.{ .tcp_connections = connections, .quic_connections = 0 });
var http_server: Server align(@alignOf(Server)) = undefined;

const greeting = "hello from colibri\n";
/// Each response, as the server writes it over h11.
const greeting_response = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 19\r\n" ++
    "Connection: close\r\n\r\n" ++ greeting;
const named_response = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 16\r\n" ++
    "Connection: close\r\n\r\nhello, colibri!\n";
/// The room for one response, and the buffers of the client's reader and writer.
const response_len_max = 1024;
const client_buffer_len = 256;
/// RFC 9110 §15.6.1: 500 (Internal Server Error).
const internal_server_error = 500;

pub fn main() !void {
    // A program probes its CPU once and passes it to every TLS configuration, the server's
    // included. With no `random`, the server draws from the system's entropy.
    const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
    try http_server.init(.{ .host = "127.0.0.1", .port = 0, .cpu = cpu });
    const thread = try std.Thread.spawn(.{}, serve, .{});
    defer thread.join();
    defer http_server.shutdown();

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var response: [response_len_max]u8 = undefined;
    // RFC 9112 §9.6: with "Connection: close" the server closes the connection after its
    // response, so the client reads until the end.
    const first = try fetch(io, "GET /greeting HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", &response);
    try expect_octets(greeting_response, first);
    const second = try fetch(io, "GET /greetings/colibri HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", &response);
    try expect_octets(named_response, second);
    std.debug.print("colibri_server: two GETs over h11 to port {d}\n", .{http_server.port()});
}

/// Runs the server until `shutdown`, on the thread that calls it.
fn serve() void {
    http_server.run(&router, &app) catch |failure| std.debug.panic("run failed: {t}", .{failure});
}

/// Sends `request` over a new connection to the server, and returns what the server sent until it
/// closed the connection, or until `response` is full.
fn fetch(io: std.Io, request: []const u8, response: []u8) ![]const u8 {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", http_server.port());
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

fn expect_octets(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    std.debug.print("colibri_server: expected {f}\ncolibri_server: got {f}\n", .{ std.zig.fmtString(expected), std.zig.fmtString(actual) });
    return error.ResponseWrong;
}

/// Answers a GET of `/greeting`. The router ends a response the function leaves open, and `end`
/// adds its Content-Length.
fn greet(state: *App, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    state.answered += 1;
    try response.header("content-type", "text/plain");
    try response.body().writeAll(greeting);
    try response.end();
}

/// Answers a GET of `/greetings/:name` with a greeting to the name.
fn greet_named(
    state: *App,
    _: *const server.Request,
    path: struct { name: []const u8 },
    _: void,
    response: *server.ResponseWriter,
) !void {
    state.answered += 1;
    try response.header("content-type", "text/plain");
    try response.body().print("hello, {s}!\n", .{path.name});
    try response.end();
}

/// Answers 500 when a route's function fails.
fn on_error(_: *App, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}
