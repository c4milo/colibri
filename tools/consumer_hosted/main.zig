//! The program the hosted consumer project builds (decision 159). It reaches `h11` and the
//! `.hosted` kind of `colibri.Server` and `colibri.Client` through the modules colibri exports,
//! in a build with no Rotor. The program is the host of each object: it calls `turn`, reads the
//! operations each one wrote, and gives back each completion. It opens no socket, so it starts
//! each object, stops it, and ends the one operation in flight.
const std = @import("std");
const h11 = @import("h11");
const tls = @import("tls");
const platform = @import("platform");
const colibri = @import("colibri");

var connection: h11.Connection align(@alignOf(h11.Connection)) = undefined;
var output: [256]u8 = undefined;

// A `colibri.Server` of one TCP connection on this program's loop, and the router that `init`
// takes. `colibri.server` is the module `server`, which the root of `colibri` re-exports.
const Server = colibri.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .hosted);
var hosted_server: Server align(@alignOf(Server)) = undefined;
const routes = .{
    .error_handler = on_route_error,
    .routes = .{
        .{ .get, "/", on_root },
    },
};
const Router = colibri.server.Router(void, routes, .{ .requests = 1, .header_bytes = 0 });
var router: Router align(@alignOf(Router)) = .{};
var router_context: void = {};
// A `colibri.Client` of one TCP connection and no QUIC, on this program's loop.
const Client = colibri.Client(.{ .quic = false, .tcp_connections = 1, .requests = 1 }, .hosted);
var hosted_client: Client align(@alignOf(Client)) = undefined;
// The room of the operations one turn writes: a host sizes it by `operations_max`.
var operations: [Server.operations_max + Client.operations_max]colibri.Operation align(@alignOf(colibri.Operation)) = undefined;

/// chapulin's one hook, which a program that links colibri's `tls` defines.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}

/// The source each TLS session draws from. A hosted object has no default source (decision 150
/// ruling 9 as amended), so the program passes the operating system's `getentropy`.
extern "c" fn getentropy(buffer: [*]u8, len: usize) c_int;
const getentropy_len_max = 256;
var entropy_state: u8 = 0;
const entropy: std.Random = .{ .ptr = &entropy_state, .fillFn = fill_entropy };

fn fill_entropy(_: *anyopaque, buffer: []u8) void {
    var filled: usize = 0;
    while (filled < buffer.len) {
        const part = @min(buffer.len - filled, getentropy_len_max);
        if (getentropy(buffer[filled..].ptr, part) != 0) @panic("getentropy failed");
        filled += part;
    }
}

/// Unix seconds, which a program reads from its clock; colibri reads none.
const now_seconds: u64 = 1_800_000_000;
/// The server's address, which a DNS lookup returns, and the port of an "http" origin (RFC 9110
/// §4.2.1). The program opens no socket, so nothing connects to them.
const loopback = [_]u8{ 127, 0, 0, 1 };
const server_addresses = [_]colibri.client.Address{.init(&loopback, 0)};
const server_port: u16 = 80;

pub fn main() !void {
    // A protocol module, which never needed Rotor.
    connection.init(.{ .role = .client });
    const head_len = try connection.write_request(&output, "GET", "/", &.{
        .{ .name = "Host", .value = "example.test" },
    });
    if (!std.mem.startsWith(u8, output[0..head_len], "GET / HTTP/1.1\r\n")) return error.RequestWrong;

    // The server: its first turn writes the accept on the listener that a host opened. This
    // program opened none, so it stops the server, and ends the accept that the server cancels.
    const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
    try hosted_server.init(&.{ .cpu = cpu, .random = entropy, .now = .{ .unix_seconds = now_seconds, .monotonic_ns = 0 } }, &router, &router_context);
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
        .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } },
        .random = entropy,
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
