//! The cases of `zig build colibri-loop-check` (build/colibri_loop_check.zig, design §8 step 44d).
//! `zig build colibri-hosted-check` compiles three of them against `colibri` with no Rotor
//! (build/colibri_hosted_check.zig, step 44k).
//! It is a test file: it runs on one thread, and no library module imports it.
//! A program compiles this file. It imports `colibri`, `server`, `client` and `tls` by the names
//! that a dependent uses, and the root of `colibri` does not import it. The build option `case`
//! names one case:
//! - `hosted_init`: a `.hosted` client and server that call `init`, `turn`, `complete`,
//!   `shutdown`, `stopped` and `deinit`. It must compile.
//! - Each other compile case calls one function that its kind does not have. Its compile must fail
//!   with colibri's message (decision 156 ruling 4 as amended by decision 159).
//! - Each `halt_` case must compile, and its run must halt with colibri's message:
//!   - `halt_stray_completion`: a completion that names no operation in flight (rule 6).
//!   - `halt_deinit_early`: `deinit` of a `.hosted` object before `stopped()` (rule 2).
//!   - `halt_client_turn_in_handler`, `halt_client_complete_in_handler`,
//!     `halt_client_run_in_handler`, `halt_server_turn_in_route`, `halt_server_complete_in_route`
//!     and `halt_server_run_in_route`: a handler or a route that calls `turn`, `complete` or `run`
//!     from inside a turn (rule 4, design §8 step 44e).
//!   - `halt_client_fetch_in_handler`: a handler that calls `fetch` from inside a turn (rule 4,
//!     design §8 step 44h).
//!   - `halt_server_turn_before_init`, `halt_server_complete_back`,
//!     `halt_client_turn_before_init`, `halt_client_complete_back` and `halt_client_cancel_back`:
//!     a call whose instant goes back, from the `now` of `init` or from the call before it
//!     (rule 6).
//!   - `halt_context_values_type`, `halt_context_path_type` and `halt_context_query_type`: a
//!     route that asks its `server.RequestContext` for a type the router did not lend, and
//!     `halt_context_path_early`: a middleware that asks for the path, which the router lends
//!     during the route's first call alone (decision 163 ruling 3, design §8 step 50c).
//!   A test binary does not live through its own halt, so the step runs each one as a program.
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

/// A route that calls `turn`, `complete` or `run` of its own server, as `route_call` names, which
/// breaks decision 159's rule 4.
const reentrant_routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/", call_inside },
    },
};
const ReentrantRouter = server.Router(void, reentrant_routes, .{ .requests = 1 });
var reentrant_router: ReentrantRouter align(@alignOf(ReentrantRouter)) = .{};
const RouteCall = enum { turn, complete, run };
var route_call: RouteCall align(@alignOf(RouteCall)) = .turn;

fn call_inside(_: *void, _: *server.RequestContext, _: *const server.Request, response: *server.Response) !void {
    switch (route_call) {
        .turn => _ = hosted_server.turn(0, &inner_operations),
        // Its id names no operation, so a complete that the flag does not refuse halts with rule
        // 6's message instead.
        .complete => hosted_server.complete(&.{ .id = stray_id, .result = .closed }, 0),
        .run => private_server.run() catch {},
    }
    try response.end();
}

fn answer(_: *void, _: *server.RequestContext, _: *const server.Request, response: *server.Response) !void {
    try response.end();
}

/// What the route table of the context cases names: the values of a request, a path and a query.
/// `Other` is a type the table does not name.
const Values = struct { number: u32 = 0 };
const Name = struct { name: []const u8 };
const Mark = struct { mark: ?[]const u8 = null };
const Other = struct { other: u32 = 0 };
const ContextCall = enum { values_type, path_type, query_type, path_early };
var context_call: ContextCall align(@alignOf(ContextCall)) = .values_type;

/// A middleware that asks for the path before the route's first call, which breaks decision 163
/// ruling 3.
const Early = struct {
    pub fn on_request(_: *void, ctx: *server.RequestContext, _: *const server.Request, _: *server.Response) !server.middleware.Next {
        if (context_call == .path_early) _ = ctx.path(Name);
        return .next;
    }
};

/// A route that asks its context for `Other`, as `context_call` names, which the router did not
/// lend (decision 163 ruling 3).
fn ask_other(_: *void, ctx: *server.RequestContext, _: *const server.Request, response: *server.Response) !void {
    switch (context_call) {
        .values_type => _ = ctx.values(Other),
        .path_type => _ = ctx.path(Other),
        .query_type => _ = ctx.query(Other),
        .path_early => {},
    }
    try response.end();
}

const context_routes = .{
    .Values = Values,
    .middleware = .{Early},
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/who/:name", ask_other, .{ .path = Name, .query = Mark } },
    },
};
const ContextRouter = server.Router(void, context_routes, .{ .requests = 1 });
var context_router: ContextRouter align(@alignOf(ContextRouter)) = .{};

/// RFC 9110 §15.6.1: a route's function that fails answers 500 (Internal Server Error).
fn on_error(_: *void, _: *server.RequestContext, _: *const server.Request, _: anyerror, response: *server.Response) void {
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
/// The instant of each hosted `init`: no Unix time, and the host's first instant.
const started: server.Timestamp = .{ .unix_seconds = 0, .monotonic_ns = 0 };
/// An instant 1 s after `started`, and an `init` at it, for the cases of rule 6.
const later_ns: u64 = 1_000_000_000;
const later: server.Timestamp = .{ .unix_seconds = 0, .monotonic_ns = later_ns };

/// A CPU with no fast path, which each TLS configuration names.
const cpu: tls.Cpu = .{
    .probe = .{ .aes_clmul = .no, .dit = .not_known, .sha256 = .no, .sha512 = .no, .sha3 = .no, .ssse3 = .no, .sse4_1 = .no, .avx2 = .no, .vaes = .no },
    .timing = .not_stated,
};

/// The room of the operations that one turn writes.
var operations: [HostedServer.operations_max + HostedClient.operations_max]colibri.Operation align(@alignOf(colibri.Operation)) = undefined;

/// The room of the operations that a turn from inside a turn writes.
var inner_operations: [HostedServer.operations_max + HostedClient.operations_max]colibri.Operation align(@alignOf(colibri.Operation)) = undefined;

/// A client's handler that calls `turn` or `run` of its own client from `on_finished`, which
/// breaks decision 159's rule 4.
const TurnInHandler = struct {
    pub fn on_finished(_: *TurnInHandler, running: *HostedClient, _: client.Finished) void {
        _ = running.turn(0, &inner_operations);
    }
};
const CompleteInHandler = struct {
    pub fn on_finished(_: *CompleteInHandler, running: *HostedClient, _: client.Finished) void {
        running.complete(&.{ .id = stray_id, .result = .closed }, 0);
    }
};
const RunInHandler = struct {
    pub fn on_finished(_: *RunInHandler, running: *PrivateClient, _: client.Finished) void {
        running.run() catch {};
    }
};
/// A handler that calls `fetch` of its own client from `on_finished` (design §8 step 44h).
const FetchInHandler = struct {
    pub fn on_finished(_: *FetchInHandler, running: *PrivateClient, _: client.Finished) void {
        _ = running.fetch(&.{ .path = "/" }) catch {};
    }
};
var turn_in_handler: TurnInHandler align(@alignOf(TurnInHandler)) = .{};
var complete_in_handler: CompleteInHandler align(@alignOf(CompleteInHandler)) = .{};
var run_in_handler: RunInHandler align(@alignOf(RunInHandler)) = .{};
var fetch_in_handler: FetchInHandler align(@alignOf(FetchInHandler)) = .{};

/// One GET of `/` and the response it fills.
const get: client.Request = .{ .method = "GET", .path = "/" };
var answer_of_get: client.Response align(@alignOf(client.Response)) = .{};

/// RFC 9112 §3: a request of `/` with its Host field (RFC 9112 §3.2).
const request_head = "GET / HTTP/1.1\r\nhost: localhost\r\n\r\n";
/// A request of the context cases' route, with a path parameter and a query (RFC 3986 §3.4).
const context_head = "GET /who/ada?mark=x HTTP/1.1\r\nhost: localhost\r\n\r\n";

/// A port that no server of the check binds, so a connect to it on loopback is refused, or ends
/// at `connect_ns`.
const unserved_port: u16 = 1;
const connect_ns: u64 = 100_000_000;

/// 127.0.0.1 with port 0, as a destination names its addresses (RFC 791 §3.2), and the port of
/// "https" (RFC 9110 §4.2.2).
const loopback_word: u32 = 0x7f00_0001;
const loopback_addresses = [_]client.Address{.init(&@as([@sizeOf(u32)]u8, @bitCast(std.mem.nativeToBig(u32, loopback_word))), 0)};
const https_port: u16 = 443;

/// A destination of 127.0.0.1 on `port`.
fn loopback(port: u16) client.Destination {
    return .{ .addresses = &loopback_addresses, .port = port };
}

/// The first operation of `kind` among the first `count` that a turn wrote.
fn written(count: u32, comptime kind: std.meta.Tag(colibri.Operation.Kind)) !colibri.Operation {
    for (operations[0..count]) |operation| {
        if (operation.kind == kind) return operation;
    }
    return error.OperationMissing;
}

/// An id that no turn wrote: its slot is past every table (`operation_table.zig`).
const stray_id: colibri.OperationId = @enumFromInt(std.math.maxInt(u32));

const cases = struct {
    /// A hosted server and client that a host starts, turns and stops, with no socket.
    pub fn hosted_init() !void {
        try hosted_server.init(&.{ .cpu = cpu, .random = zero_source, .now = started }, &router, &context);
        const turned = hosted_server.turn(0, &operations);
        const accept = operations[0];
        if (turned.operations != 1 or accept.kind != .accept) return error.AcceptMissing;
        hosted_server.shutdown();
        _ = hosted_server.turn(0, &operations);
        hosted_server.complete(&.{ .id = accept.id, .result = .canceled }, 0);
        if (!hosted_server.stopped()) return error.NotStopped;
        hosted_server.deinit();
        try hosted_client.init(&.{ .destination = loopback(https_port), .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } }, .random = zero_source, .now = started }, null);
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

    pub fn hosted_client_fetch() !void {
        _ = try hosted_client.fetch(&.{ .path = "/" });
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
        try hosted_client.init(&.{ .destination = loopback(https_port), .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } }, .random = zero_source, .now = started }, null);
        _ = hosted_client.turn(0, &operations);
        hosted_client.complete(&.{ .id = stray_id, .result = .closed }, 0);
    }

    /// `deinit` while the server's accept is in flight: a halt (decision 159, rule 2).
    pub fn halt_deinit_early() !void {
        try hosted_server.init(&.{ .cpu = cpu, .random = zero_source, .now = started }, &router, &context);
        _ = hosted_server.turn(0, &operations);
        hosted_server.deinit();
    }
};

const halts = struct {
    /// A handler that calls `turn` from `on_finished`, which runs inside a turn.
    pub fn halt_client_turn_in_handler() !void {
        try refuse_inside_handler(&turn_in_handler);
    }

    /// A handler that calls `complete` from `on_finished`. Its id names no operation, so a
    /// complete that the flag does not refuse halts with rule 6's message instead.
    pub fn halt_client_complete_in_handler() !void {
        try refuse_inside_handler(&complete_in_handler);
    }

    /// Ends one exchange refused, so `handler`'s `on_finished` runs inside the last turn.
    fn refuse_inside_handler(handler: anytype) !void {
        try hosted_client.init(&.{ .destination = loopback(unserved_port), .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } }, .random = zero_source, .now = started }, handler);
        _ = try hosted_client.request(&get, &answer_of_get);
        const first = hosted_client.turn(0, &operations);
        const connect = try written(first.operations, .connect);
        // The connect fails, so the exchange ends refused at the next turn.
        hosted_client.complete(&.{ .id = connect.id, .result = .{ .failed = .refused } }, 0);
        _ = hosted_client.turn(0, &operations);
    }

    /// A route's function that calls `turn` of its server, which runs inside a turn.
    pub fn halt_server_turn_in_route() !void {
        try route_inside(.turn);
    }

    /// A route's function that calls `complete` of its server.
    pub fn halt_server_complete_in_route() !void {
        try route_inside(.complete);
    }

    /// A route's function that calls `run` of its `.private` server. A client on a thread of
    /// its own sends the request over loopback.
    pub fn halt_server_run_in_route() !void {
        route_call = .run;
        try private_server.init(&.{ .cpu = cpu, .unix_seconds = started.unix_seconds, .random = zero_source }, &reentrant_router, &context);
        const peer = try std.Thread.spawn(.{}, get_from, .{private_server.port()});
        peer.detach();
        try private_server.run();
    }

    /// Sends one GET of `/` to `port` on loopback from a `.private` client. The server halts
    /// before it answers.
    fn get_from(port: u16) void {
        private_client.init(&.{ .destination = loopback(port), .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } }, .random = zero_source, .unix_seconds = 0 }, null) catch return;
        _ = private_client.request(&get, &answer_of_get) catch return;
        private_client.run() catch return;
    }

    /// Gives a hosted server one request, so its route calls what `call` names inside a turn.
    fn route_inside(call: RouteCall) !void {
        route_call = call;
        try serve(&reentrant_router, request_head);
    }

    /// A route that asks its context for the values as a type the route table does not name.
    pub fn halt_context_values_type() !void {
        try context_inside(.values_type);
    }

    /// A route that asks its context for the path as a type the route does not name.
    pub fn halt_context_path_type() !void {
        try context_inside(.path_type);
    }

    /// A route that asks its context for the query as a type the route does not name.
    pub fn halt_context_query_type() !void {
        try context_inside(.query_type);
    }

    /// A middleware that asks its context for the path, before the route's first call.
    pub fn halt_context_path_early() !void {
        try context_inside(.path_early);
    }

    /// Gives a hosted server one request of the context cases' route.
    fn context_inside(call: ContextCall) !void {
        context_call = call;
        try serve(&context_router, context_head);
    }

    /// Gives a hosted server with `routed` the request `head`, so its route runs inside a turn.
    fn serve(routed: anytype, comptime head: []const u8) !void {
        try hosted_server.init(&.{ .cpu = cpu, .random = zero_source, .now = started }, routed, &context);
        const first = hosted_server.turn(0, &operations);
        const accept = try written(first.operations, .accept);
        hosted_server.complete(&.{ .id = accept.id, .result = .accepted }, 0);
        const second = hosted_server.turn(0, &operations);
        const receive = try written(second.operations, .receive);
        @memcpy(receive.kind.receive.buffer[0..head.len], head);
        hosted_server.complete(&.{ .id = receive.id, .result = .{ .received = head.len } }, 0);
        _ = hosted_server.turn(0, &operations);
    }

    /// A hosted server whose first turn names an instant before the `now` of `init`.
    pub fn halt_server_turn_before_init() !void {
        try hosted_server.init(&.{ .cpu = cpu, .random = zero_source, .now = later }, &router, &context);
        _ = hosted_server.turn(later_ns - 1, &operations);
    }

    /// The accept's completion at an instant before the turn that wrote it.
    pub fn halt_server_complete_back() !void {
        try hosted_server.init(&.{ .cpu = cpu, .random = zero_source, .now = started }, &router, &context);
        const first = hosted_server.turn(later_ns, &operations);
        const accept = try written(first.operations, .accept);
        hosted_server.complete(&.{ .id = accept.id, .result = .accepted }, later_ns - 1);
    }

    /// A hosted client whose first turn names an instant before the `now` of `init`.
    pub fn halt_client_turn_before_init() !void {
        try hosted_client.init(&.{ .destination = loopback(https_port), .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } }, .random = zero_source, .now = later }, null);
        _ = hosted_client.turn(later_ns - 1, &operations);
    }

    /// The connect's completion at an instant before the turn that wrote it.
    pub fn halt_client_complete_back() !void {
        try hosted_client.init(&.{ .destination = loopback(https_port), .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } }, .random = zero_source, .now = started }, null);
        _ = try hosted_client.request(&get, &answer_of_get);
        const first = hosted_client.turn(later_ns, &operations);
        const connect = try written(first.operations, .connect);
        hosted_client.complete(&.{ .id = connect.id, .result = .connected }, later_ns - 1);
    }

    /// A cancel at an instant before the last turn.
    pub fn halt_client_cancel_back() !void {
        try hosted_client.init(&.{ .destination = loopback(https_port), .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false } }, .random = zero_source, .now = started }, null);
        const id = try hosted_client.request(&get, &answer_of_get);
        _ = hosted_client.turn(later_ns, &operations);
        hosted_client.cancel(id, later_ns - 1);
    }

    /// A handler that calls `run` from `on_finished`, which runs inside a turn of `run`.
    pub fn halt_client_run_in_handler() !void {
        try private_inside_handler(&run_in_handler);
    }

    /// A handler that calls `fetch` from `on_finished`, which runs inside a turn of `run`.
    pub fn halt_client_fetch_in_handler() !void {
        try private_inside_handler(&fetch_in_handler);
    }

    /// Runs one exchange to a port that refuses it, so `handler`'s `on_finished` runs inside a
    /// turn of `run`.
    fn private_inside_handler(handler: anytype) !void {
        var pool: client.Config = .{ .authority = "localhost", .protocols = .{ .h3 = false } };
        pool.timeouts.connect_ns = connect_ns;
        try private_client.init(&.{ .destination = loopback(unserved_port), .pool = pool, .random = zero_source, .unix_seconds = 0 }, handler);
        _ = try private_client.request(&get, &answer_of_get);
        try private_client.run();
    }
};

pub fn main() !void {
    if (@hasDecl(halts, case)) try @field(halts, case)() else try @field(cases, case)();
    // A halt case that returns broke its rule with no halt.
    if (std.mem.startsWith(u8, case, "halt_")) return error.NoHalt;
}
