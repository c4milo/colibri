//! What the tests of `colibri.Client` share (design §8 step 42): a `colibri.Server` that runs on a
//! thread of its own on 127.0.0.1 port 0, a handler that records how each exchange ended, and a
//! watchdog that halts a test whose run does not return. Decision 150 ruling 7 lets these tests
//! bind loopback. Test-only.
const std = @import("std");
const client = @import("client");
const server = @import("server");
const tls = @import("tls");
const testdata = @import("testdata");
const server_module = @import("server.zig");
const client_module = @import("client.zig");
const support = @import("test_support.zig");

pub const greeting = "hello from colibri";
/// The instant the tests pass as `unix_seconds`, inside the test identity's dates.
pub const now_seconds = testdata.now_seconds;
/// The requests a test makes at most, and the room of each response's body.
pub const requests_max = 4;
const body_len = 64;
/// The connections the test server holds, and the router's room for each response.
const connections = 4;
const response_bytes = 256;
/// RFC 9110 §15.3.1: 200 (OK), and §15.6.1: 500 (Internal Server Error).
const ok = 200;
const internal_server_error = 500;
/// How long a test's run may last before the watchdog halts the test, and the step it checks in.
/// It is shorter than the server's deadlines of 10 s (decision 110), so a run that ends only when
/// the server cuts an idle connection fails.
pub const watchdog_ms = 8_000;
/// How long a run may last whose QUIC connection the server never answers. The pool closes it once
/// TCP takes the exchanges, and it stays closing for three PTOs (RFC 9000 §10.2), which its lost
/// Initial packets have doubled (RFC 9002 §6.2.1).
pub const unanswered_quic_watchdog_ms = 30_000;
const watchdog_step_ms = 50;

const routes = server.router(void, .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/greeting", greet },
        .{ .get, "/goodbye", greet_and_close },
    },
});
const Router = @TypeOf(routes).Of(.{ .requests = connections, .response_bytes = response_bytes, .body_bytes = 0 });

fn greet(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.header("content-type", "text/plain");
    try response.body().writeAll(greeting);
    try response.end();
}

/// Answers with the greeting, and closes the connection after it (RFC 9112 §9.6).
fn greet_and_close(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.header("connection", "close");
    try response.header("content-type", "text/plain");
    try response.body().writeAll(greeting);
    try response.end();
}

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}

/// The server the tests run: with QUIC slots, so an identity opens its UDP socket, or with none.
pub const TestServer = server_module.ServerOf(.{ .tcp_connections = connections, .quic_connections = connections });
pub const TcpServer = server_module.ServerOf(.{ .tcp_connections = connections, .quic_connections = 0 });

/// The servers, their router and the thread that runs one, which the tests place outside any
/// stack frame. `udp_served` says which server runs.
pub var test_server: TestServer align(@alignOf(TestServer)) = undefined;
pub var tcp_server: TcpServer align(@alignOf(TcpServer)) = undefined;
var udp_served: bool = false;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};
var server_thread: std.Thread align(@alignOf(std.Thread)) = undefined;

/// The client the tests run: QUIC, one TCP connection, and `requests_max` requests.
pub const TestClient = client_module.ClientOf(.{ .tcp_connections = 1, .requests = requests_max });
pub var test_client: TestClient align(@alignOf(TestClient)) = undefined;

/// The clients `client.zig`'s tests place: one of the default capacity, and one with no QUIC.
/// Neither is `threadlocal`: glibc places the static TLS of each new thread on that thread's
/// stack, and these tests spawn threads (`server_test_support.zig`).
pub const TcpClient = client_module.ClientOf(.{ .quic = false });
pub var default_client: client_module.Client align(@alignOf(client_module.Client)) = undefined;
pub var tcp_client: TcpClient align(@alignOf(TcpClient)) = undefined;

/// Starts a server on 127.0.0.1 port 0 on a thread of its own: over TLS with the test identity
/// when `identity` is set, and with a UDP socket for h3 when `udp` is set too. Its QUIC
/// connections read and set ECN codepoints, as each `colibri.Server`'s do (decision 68).
pub fn start_server(identity: bool, udp: bool) !void {
    var config: server_module.ServerConfig = .{ .cpu = support.cpu() };
    if (identity) config.identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem };
    router = .{};
    udp_served = udp;
    if (udp) try test_server.init(config) else try tcp_server.init(config);
    server_thread = try std.Thread.spawn(.{}, serve, .{});
}

/// The port the running server bound, for TCP and UDP.
pub fn port() u16 {
    return if (udp_served) test_server.port() else tcp_server.port();
}

/// Stops the server and waits for its thread.
pub fn stop_server() void {
    if (udp_served) test_server.shutdown() else tcp_server.shutdown();
    server_thread.join();
    if (udp_served) test_server.deinit() else tcp_server.deinit();
}

fn serve() void {
    const result = if (udp_served) test_server.run(&router, &context) else tcp_server.run(&router, &context);
    result catch |failure| std.debug.panic("run failed: {t}", .{failure});
}

/// Whether the client's last QUIC connection read each of the server's 1-RTT datagrams as ECT(0),
/// the codepoint the server sets (RFC 9000 §13.4.1). It reads the counts of the connection's
/// application space, a field no program reads.
pub fn ecn_read_as_ect0() bool {
    const spaces = &test_client.pool.quic.transport.spaces;
    const counts = spaces[spaces.len - 1].ecn;
    return counts.ect_0 > 0 and counts.ect_1 == 0 and counts.ecn_ce == 0;
}

/// The anchor that trusts the test identity's root.
const anchors = [_]tls.Anchor{.{ .subject = testdata.root_name, .spki = testdata.root_spki }};

/// A pool configuration for `localhost` with `protocols`, over TLS when `secure` is set. The trust
/// judges the chain for `localhost` under the test identity's root.
pub fn pool_config(protocols: client.Protocols, secure: bool) client.Config {
    var config: client.Config = .{ .authority = "localhost", .protocols = protocols };
    if (secure) config.tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "localhost" } }, .cpu = support.cpu() };
    return config;
}

/// A GET of `/greeting`, and the room its response fills.
pub const Exchange = struct {
    request: client.Request = .{ .method = "GET", .path = "/greeting" },
    body: [body_len]u8 = undefined,
    response: client.Response = .{},
};

/// The program's handler: it records each exchange that ended and the protocol of the connection
/// that took them. It makes `more` requests from `on_finished`, and shuts the client down once
/// `stop_after` exchanges have ended.
pub const Handler = struct {
    exchanges: [requests_max]Exchange = @splat(.{}),
    finished: u32 = 0,
    requested: u32 = 0,
    more: u32 = 0,
    stop_after: u32 = std.math.maxInt(u32),
    connected: ?client.Protocol = null,
    connections: u32 = 0,
    greetings: u32 = 0,
    path: []const u8 = "/greeting",
    method: []const u8 = "GET",

    /// Requests `count` GETs of `/greeting` through the client.
    pub fn request(handler: *Handler, count: u32) !void {
        for (0..count) |_| {
            // A test that makes more requests than this makes each after the one before ended.
            const exchange = &handler.exchanges[handler.requested % requests_max];
            exchange.request.path = handler.path;
            exchange.request.method = handler.method;
            exchange.response = .{ .body = &exchange.body };
            _ = try test_client.request(&exchange.request, &exchange.response);
            handler.requested += 1;
        }
    }

    pub fn on_finished(handler: *Handler, running: *TestClient, finished: client.Finished) void {
        std.debug.assert(running == &test_client);
        handler.finished += 1;
        if (greeting_in(finished.response)) handler.greetings += 1;
        if (handler.more > 0) {
            handler.more -= 1;
            handler.request(1) catch |failure| std.debug.panic("request failed: {t}", .{failure});
        }
        if (handler.finished == handler.stop_after) running.shutdown();
    }

    pub fn on_connected(handler: *Handler, _: *TestClient, connected: client.Connected) void {
        handler.connected = connected.protocol;
        handler.connections += 1;
    }

    /// Whether each exchange requested ended with the greeting.
    pub fn greeted(handler: *const Handler) bool {
        return handler.finished == handler.requested and handler.greetings == handler.finished;
    }
};

/// Whether `response` holds the greeting, whole.
fn greeting_in(response: *const client.Response) bool {
    if (response.result != .response or response.status != ok) return false;
    return std.mem.eql(u8, greeting, response.body_received());
}

/// Halts the test binary when a run lasts longer than `watchdog_ms`: a run that never returns
/// fails at once, not at the mutation runner's limit.
pub const Watchdog = struct {
    limit_ms: u64 = watchdog_ms,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,

    pub fn start(watchdog: *Watchdog) !void {
        watchdog.thread = try std.Thread.spawn(.{}, watch, .{watchdog});
    }

    pub fn stop(watchdog: *Watchdog) void {
        watchdog.done.store(true, .release);
        watchdog.thread.join();
    }

    fn watch(watchdog: *Watchdog) void {
        var threaded: std.Io.Threaded = .init_single_threaded;
        const io = threaded.io();
        for (0..watchdog.limit_ms / watchdog_step_ms) |_| {
            if (watchdog.done.load(.acquire)) return;
            io.sleep(.fromMilliseconds(watchdog_step_ms), .awake) catch {};
        }
        @panic("the client's run did not return");
    }
};

/// Runs the client with `handler` on this thread, under a watchdog.
pub fn run(handler: *Handler) !void {
    return run_within(handler, watchdog_ms);
}

/// Runs the client as `run` does, under a watchdog of `limit_ms`.
pub fn run_within(handler: *Handler, limit_ms: u64) !void {
    var watchdog: Watchdog = .{ .limit_ms = limit_ms };
    try watchdog.start();
    defer watchdog.stop();
    try test_client.run(handler);
}
