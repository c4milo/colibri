//! The cases of `zig build colibri-loop-check` (build/colibri_loop_check.zig, design §8 step 44d).
//! It is a test file: it runs on one thread, and no library module imports it.
//! A program compiles this file. It imports `colibri`, `server`, `client` and `tls` by the names
//! that a dependent uses, and the root of `colibri` does not import it. The build option `case`
//! names one case:
//! - `hosted_init`: a `.hosted` client and server that call `init`, `turn`, `complete`,
//!   `shutdown`, `stopped` and `deinit`. It must compile.
//! - Each other compile case calls one function that its kind does not have. Its compile must fail
//!   with colibri's message (decision 156 ruling 4 as amended by decision 159).
//! - `halt_stray_completion` and `halt_deinit_early` must compile. Each run must halt with
//!   colibri's message: a completion that names no operation in flight (rule 6), and `deinit` of a
//!   `.hosted` object before `stopped()` (rule 2). A test binary does not live through its own
//!   halt, so the step runs each one as a program.
const std = @import("std");
const colibri = @import("colibri");
const server = @import("server");
const client = @import("client");
const tls = @import("tls");
const case = @import("loop_case").case;

/// The smallest objects of each kind: one TCP connection, no QUIC.
const HostedServer = colibri.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .hosted);
const PrivateServer = colibri.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .private);
const HostedClient = colibri.Client(.{ .quic = false, .tcp_connections = 1, .requests = 1 }, .hosted);
const PrivateClient = colibri.Client(.{ .quic = false, .tcp_connections = 1, .requests = 1 }, .private);

var hosted_server: HostedServer align(@alignOf(HostedServer)) = undefined;
var private_server: PrivateServer align(@alignOf(PrivateServer)) = undefined;
var hosted_client: HostedClient align(@alignOf(HostedClient)) = undefined;
var private_client: PrivateClient align(@alignOf(PrivateClient)) = undefined;

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/", answer },
    },
};
const Router = server.Router(void, routes, .{ .requests = 1 });
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};

fn answer(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.end();
}

/// RFC 9110 §15.6.1: a route's function that fails answers 500 (Internal Server Error).
fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = .internal_server_error;
}

/// chapulin's one hook, which a program that links `tls` defines.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}

/// A source that fills each octet with 0. A program passes its own entropy.
const Zero = struct {
    fn fill(_: *Zero, buffer: []u8) void {
        @memset(buffer, 0);
    }
};
var zero: Zero align(@alignOf(Zero)) = .{};
const zero_source: tls.Random = tls.Random.init(&zero, Zero.fill);

/// A CPU with no fast path, which each TLS configuration names.
const cpu: tls.Cpu = .{
    .probe = .{ .aes_clmul = .no, .dit = .not_known, .sha256 = .no, .sha512 = .no, .sha3 = .no, .ssse3 = .no, .sse4_1 = .no, .avx2 = .no, .vaes = .no },
    .timing = .not_stated,
};

/// The room of the operations that one turn writes.
var operations: [HostedServer.operations_max + HostedClient.operations_max]colibri.Operation align(@alignOf(colibri.Operation)) = undefined;

/// An id that no turn wrote: its slot is past every table (`operation_table.zig`).
const stray_id: colibri.OperationId = @enumFromInt(std.math.maxInt(u32));

const cases = struct {
    /// A hosted server and client that a host starts, turns and stops, with no socket.
    pub fn hosted_init() !void {
        try hosted_server.init(&.{ .cpu = cpu, .random = zero_source }, &router, &context);
        const turned = hosted_server.turn(0, &operations);
        const accept = operations[0];
        if (turned.operations != 1 or accept.kind != .accept) return error.AcceptMissing;
        hosted_server.shutdown();
        _ = hosted_server.turn(0, &operations);
        hosted_server.complete(&.{ .id = accept.id, .result = .canceled }, 0);
        if (!hosted_server.stopped()) return error.NotStopped;
        hosted_server.deinit();
        try hosted_client.init(&.{ .host = "127.0.0.1", .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } }, .random = zero_source, .unix_seconds = 0 }, null);
        hosted_client.shutdown();
        _ = hosted_client.turn(0, &operations);
        if (!hosted_client.stopped()) return error.NotStopped;
        hosted_client.deinit();
    }

    pub fn hosted_server_run() !void {
        try hosted_server.run();
    }

    pub fn hosted_server_port() !void {
        _ = hosted_server.port();
    }

    pub fn hosted_client_run() !void {
        try hosted_client.run();
    }

    pub fn private_server_turn() !void {
        _ = private_server.turn(0, &operations);
    }

    pub fn private_server_complete() !void {
        private_server.complete(&.{ .id = @enumFromInt(0), .result = .closed }, 0);
    }

    pub fn private_client_turn() !void {
        _ = private_client.turn(0, &operations);
    }

    pub fn private_client_complete() !void {
        private_client.complete(&.{ .id = @enumFromInt(0), .result = .closed }, 0);
    }

    /// A completion of an operation that the client never wrote: a halt (decision 159, rule 6).
    pub fn halt_stray_completion() !void {
        try hosted_client.init(&.{ .host = "127.0.0.1", .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } }, .random = zero_source, .unix_seconds = 0 }, null);
        _ = hosted_client.turn(0, &operations);
        hosted_client.complete(&.{ .id = stray_id, .result = .closed }, 0);
    }

    /// `deinit` while the server's accept is in flight: a halt (decision 159, rule 2).
    pub fn halt_deinit_early() !void {
        try hosted_server.init(&.{ .cpu = cpu, .random = zero_source }, &router, &context);
        _ = hosted_server.turn(0, &operations);
        hosted_server.deinit();
    }
};

pub fn main() !void {
    try @field(cases, case)();
    // A halt case that returns broke its rule with no halt.
    if (std.mem.startsWith(u8, case, "halt_")) return error.NoHalt;
}
