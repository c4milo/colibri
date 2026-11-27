//! The program the hosted consumer project builds (decision 159). It reaches `h11` and the
//! `.hosted` kind of `colibri.Server` and `colibri.Client` through `colibri`, the one module
//! colibri exports (decision 170), in a build with no Rotor. The program is the host of each object: it calls `turn`, reads the
//! operations each one wrote, and gives back each completion. It opens no socket, so it starts
//! each object, stops it, and ends the one operation in flight.
const std = @import("std");
const colibri = @import("colibri");
const h11 = colibri.h11;
const tls = colibri.tls;
const stdx = @import("stdx");
const platform = stdx.platform;

var connection: h11.Connection align(@alignOf(h11.Connection)) = undefined;
var output: [256]u8 = undefined;

// A `colibri.Server` of one TCP connection on this program's loop, and the router that `init`
// takes. `colibri.server` is the module `server`, which the root of `colibri` names.
const Server = colibri.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .hosted);
var hosted_server: Server align(@alignOf(Server)) = undefined;
const routes = .{
    .error_handler = on_route_error,
    .routes = .{
        .{ .get, "/", on_root },
    },
};
const Router = colibri.server.Router(void, routes, .{ .requests = 1, .response_buffer_bytes = 256, .request_body_bytes = 0, .request_header_bytes = 0 });
var router: Router align(@alignOf(Router)) = undefined;
var router_context: void = {};
// A `colibri.Client` of one TCP connection and no QUIC, on this program's loop.
const Client = colibri.Client(.{ .quic = false, .tcp_connections = 1, .requests = 1 }, .hosted);
var hosted_client: Client align(@alignOf(Client)) = undefined;
// The room of the operations one turn writes: a host sizes it by `operations_max`.
var operations: [Server.operations_max + Client.operations_max]colibri.Operation align(@alignOf(colibri.Operation)) = undefined;

/// A random source over the operating system's entropy, which every TLS session of the program
/// draws from (decision 175). A hosted server has no default source (decision 150 ruling 9 as
/// amended). Each draw calls `io.randomSecure`, which is thread-safe, keeps no state that a fork
/// copies, and has no weaker fallback. A draw that fails halts the program, so no session runs on
/// bytes the system did not give.
const SecureRandom = struct {
    io: std.Io,

    fn fill(pointer: *anyopaque, bytes: []u8) void {
        const self: *SecureRandom = @ptrCast(@alignCast(pointer));
        self.io.randomSecure(bytes) catch |err| std.debug.panic("no entropy: {t}", .{err});
    }

    fn random(self: *SecureRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

/// Unix seconds, which a program reads from its clock; colibri reads none.
const now_seconds: u64 = 1_800_000_000;
/// The server's address, which a DNS lookup returns, and the port of an "http" origin (RFC 9110
/// §4.2.1). The program opens no socket, so nothing connects to them.
const loopback = [_]u8{ 127, 0, 0, 1 };
const server_addresses = [_]colibri.client.Address{.init(&loopback, 0)};
const server_port: u16 = 80;

pub fn main(init: std.process.Init) !void {
    // The random source of every TLS session: the operating system's entropy.
    var secure: SecureRandom = .{ .io = init.io };
    // The CPU features the program detects once, for its codecs (decision 169) and for TLS.
    const cpu_features: platform.CpuFeatures = .detect();
    // The program's one context, which a hosted server takes (decision 175).
    const crypto = stdx.crypto.init(cpu_features, secure.random());
    // A protocol module, which never needed Rotor.
    connection.init(.{ .role = .client, .cpu_features = cpu_features });
    const head_len = try connection.write_request(&output, "GET", "/", &.{
        .{ .name = "Host", .value = "example.test" },
    });
    if (!std.mem.startsWith(u8, output[0..head_len], "GET / HTTP/1.1\r\n")) return error.RequestWrong;

    // The server: its first turn writes the accept on the listener that a host opened. This
    // program opened none, so it stops the server, and ends the accept that the server cancels.
    router.init();
    try hosted_server.init(&.{ .crypto = crypto, .now = .{ .unix_seconds = now_seconds, .monotonic_ns = 0 }, .engine = .{ .cpu_features = cpu_features } }, &router, &router_context);
    const first = hosted_server.turn(0, &operations);
    if (first.operations != 1 or operations[0].kind != .accept) return error.AcceptMissing;
    const accept = operations[0].id;
    hosted_server.shutdown();
    _ = hosted_server.turn(0, &operations);
    hosted_server.complete(&.{ .id = accept, .result = .canceled }, 0);
    if (!hosted_server.stopped()) return error.NotStopped;
    hosted_server.deinit();

    // The client: with no request it holds no operation, so one turn after `shutdown` stops it.
    try hosted_client.init(&.{
        .destination = .{ .addresses = &server_addresses, .port = server_port },
        .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false }, .cpu_features = cpu_features },
        .now = .{ .unix_seconds = now_seconds, .monotonic_ns = 0 },
    }, null);
    hosted_client.shutdown();
    const last = hosted_client.turn(0, &operations);
    if (last.operations != 0 or !hosted_client.stopped()) return error.NotStopped;
    hosted_client.deinit();
    std.debug.print("consumer_hosted: h11 and colibri's .hosted kind link and run with no Rotor\n", .{});
}

/// Answers a GET of `/` with an empty 200. No request arrives, because the program opens no
/// socket.
fn on_root(_: *void, _: *colibri.server.RequestContext, _: *const colibri.server.Request, response: *colibri.server.Response) !void {
    try response.end();
}

/// Answers 500 when a route's function fails (RFC 9110 §15.6.1).
fn on_route_error(_: *void, _: *colibri.server.RequestContext, _: *const colibri.server.Request, _: anyerror, response: *colibri.server.Response) void {
    response.status = .internal_server_error;
}
