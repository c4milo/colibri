//! The server that `server.zig`'s tests place, outside any stack frame, and a router of one route.
//! Test-only.
//!
//! The server is not `threadlocal`. glibc places the static TLS of each new thread on that
//! thread's stack, and `pthread_create` returns EINVAL when the stack cannot hold it. The default
//! server is about 58 MB, and `std.Thread.spawn` asks for a stack of 16 MiB. So a `threadlocal`
//! server stops each test of this module that spawns a thread, on Linux only.
const server = @import("server");
const server_module = @import("server.zig");

const Server = server_module.Server(.{}, .private);

pub var test_server: Server align(@alignOf(Server)) = undefined;

const Hosted = server_module.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .hosted);

/// A hosted server with one TCP socket and no QUIC, which the test of decision 161 places.
pub var hosted_server: Hosted align(@alignOf(Hosted)) = undefined;

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

/// A router that answers a GET of `/` with an empty 200, and its context.
pub const Router = server.Router(void, routes, .{ .requests = 1, .response_bytes = response_bytes, .body_bytes = 0 });
pub var router: Router align(@alignOf(Router)) = .{};
pub var context: void = {};

fn answer(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.end();
}

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}
