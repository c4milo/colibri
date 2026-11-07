//! Example: a program serves a route table through `colibri.Server`, and fetches from it through
//! `colibri.Client`. `colibri` is the one module of colibri that binds sockets and runs a loop
//! (decisions 150 and 153).
//!
//! The server gets a host, a port, its identity and its CPU, and `init` binds. Port 0 asks the
//! system for a port, which `port()` returns. `run` serves on the thread that calls it, through
//! Rotor's loop, until another thread calls `shutdown`. With an identity the server speaks h11 and
//! h2 over TLS, as ALPN selects, and h3 on the UDP socket of the same port.
//!
//! The client gets the server's address, its port and a pool's configuration. The program hands it
//! requests, calls `shutdown`, and calls `run`, which returns once each exchange has finished.
//!
//! The run goes in this order:
//! 1. The program places the server and calls `init` on 127.0.0.1, port 0, with the test identity.
//! 2. A thread of its own calls `run` with the router of a route table.
//! 3. A `colibri.Client` sends two GETs over h11, then over h2, then over h3, and the program
//!    checks each response octet for octet.
//! 4. The program calls `shutdown`, and the server's `run` returns once each connection has
//!    closed.
//! 5. The program calls `deinit`, which wipes the private key and the cookie key. `run` has
//!    closed the sockets, and `deinit` closes neither again.
//!
//! This example binds loopback sockets, which decision 96 as amended allows for `colibri` alone.
//! The test identity stands in for the certificate and the key a program reads from its files.
//!
//! Run it with `zig build example-colibri_server`, or every example with `zig build examples`.
const std = @import("std");
const colibri = @import("colibri");
const server = @import("server");
const client = @import("client");
const tls = @import("tls");
const platform = @import("platform");
const identity = @import("testdata");
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
const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/greeting", greet },
        .{ .get, "/greetings/:name", greet_named },
    },
};

/// The router's pool: an entry for each request at once, with room for its response.
const Router = server.Router(App, routes, .{ .requests = connections, .response_bytes = 256, .body_bytes = 0 });
var router: Router align(@alignOf(Router)) = .{};

/// A server that holds four TCP connections and four QUIC connections. `colibri.Server` is the
/// default capacity. The program places the server once, outside any stack frame, and does not
/// move it.
const connections = 4;
const Server = colibri.ServerOf(.{ .tcp_connections = connections, .quic_connections = connections });
var http_server: Server align(@alignOf(Server)) = undefined;

/// The client, placed the same way. `colibri.Client` holds one TCP connection, one QUIC
/// connection, and `client.constants.limits.requests_max` requests at once.
var http_client: colibri.Client align(@alignOf(colibri.Client)) = undefined;

/// The origin the client names, and the root it trusts for it.
const origin = "localhost";
const anchors = [_]tls.Anchor{.{ .subject = identity.root_name, .spki = identity.root_spki }};
/// Seconds since 1970, which a program reads from its clock: the client judges each chain's dates
/// at this instant.
const now_seconds = identity.now_seconds;

const greeting = "hello from colibri\n";
const named_greeting = "hello, colibri!\n";
/// RFC 9110 §15.3.1: 200 (OK), and §15.6.1: 500 (Internal Server Error).
const ok: client.Status = .ok;
const internal_server_error: server.Status = .internal_server_error;
/// The room for each response's body.
const body_len_max = 256;

pub fn main() !void {
    // A program probes its CPU once and passes it to every TLS configuration. With no `random`,
    // the server and the client draw from the system's entropy.
    const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
    try http_server.init(.{
        .host = "127.0.0.1",
        .port = 0,
        .identity = .{ .chain = identity.chain_pem, .key = identity.key_pem },
        .cpu = cpu,
    });
    defer http_server.deinit();
    const thread = try std.Thread.spawn(.{}, serve, .{});
    defer thread.join();
    defer http_server.shutdown();

    // h11 alone: ALPN offers `http/1.1`. Then h11 and h2, and the server selects h2. Then every
    // version: by default the client opens TCP first, and with `.prefer = .quic` QUIC first.
    try fetch(cpu, .{ .h2 = false, .h3 = false }, .h11);
    try fetch(cpu, .{ .h3 = false }, .h2);
    try fetch(cpu, .{}, .h2);
    try fetch(cpu, .{ .prefer = .quic }, .h3);
    std.debug.print("colibri_server: two GETs over h11, h2 and h3 to port {d}\n", .{http_server.port()});
}

/// Runs the server until `shutdown`, on the thread that calls it.
fn serve() void {
    http_server.run(&router, &app) catch |failure| std.debug.panic("run failed: {t}", .{failure});
}

/// What the program keeps for its two exchanges, and what its handler records. The client writes
/// each response from `request` until its `finished` event.
const Fetch = struct {
    requests: [2]client.Request = .{
        .{ .method = "GET", .path = "/greeting" },
        .{ .method = "GET", .path = "/greetings/colibri" },
    },
    responses: [2]client.Response = undefined,
    bodies: [2][body_len_max]u8 = undefined,
    finished: u32 = 0,
    protocol: ?client.Protocol = null,

    /// `run` calls it on the loop's thread for each exchange that ended.
    pub fn on_finished(self: *Fetch, _: *colibri.Client, _: client.Finished) void {
        self.finished += 1;
    }

    /// `run` calls it for the connection that takes the exchanges, since the handler declares it.
    pub fn on_connected(self: *Fetch, _: *colibri.Client, connected: client.Connected) void {
        self.protocol = connected.protocol;
    }
};
var fetched: Fetch align(@alignOf(Fetch)) = .{};

/// Sends the two GETs through a client that speaks `protocols`, over TLS to the server, and checks
/// that `expected` carried them and that each response arrived octet for octet.
fn fetch(cpu: tls.Cpu, protocols: client.Protocols, expected: client.Protocol) !void {
    try http_client.init(.{
        .host = "127.0.0.1",
        .port = http_server.port(),
        .pool = .{
            .authority = origin,
            .protocols = protocols,
            .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } }, .cpu = cpu },
        },
        .unix_seconds = now_seconds,
    });
    defer http_client.deinit();
    fetched = .{};
    for (&fetched.requests, &fetched.responses, &fetched.bodies) |*request, *response, *body| {
        response.* = .{ .body = body };
        _ = try http_client.request(request, response);
    }
    // `run` returns once both exchanges have finished and each connection has closed.
    http_client.shutdown();
    try http_client.run(&fetched);
    if (fetched.finished != 2 or fetched.protocol != expected) return error.FetchWrong;
    try expect_response(greeting, &fetched.responses[0]);
    try expect_response(named_greeting, &fetched.responses[1]);
}

fn expect_response(expected: []const u8, response: *const client.Response) !void {
    if (response.result != .response or response.status != ok) return error.ResponseWrong;
    const actual = response.body_received();
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
