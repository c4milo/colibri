//! Example: a program runs a `colibri.Server` and a `colibri.Client` on its own Rotor loop, beside
//! a timer of its own. Each object is `.hosted` (decision 159), and the program writes the
//! adapter: about 140 lines that do each operation on the loop and give back each completion.
//! colibri exports no such adapter, because its API would then name `*rotor.Loop`.
//!
//! The adapter puts its own tag in the high 32 bits of each `user_data`: the owner, the kind and
//! the socket. The low 32 bits are colibri's `OperationId`. So each event of a tick goes to the
//! server, to the client or to the program's timer by that tag.
//!
//! The run goes in this order:
//! 1. The program binds a listener on `::` and port 0, which takes IPv4 and IPv6, before the
//!    server's `init`. The server serves h11 in cleartext.
//! 2. The client sends a GET to 127.0.0.1. The server's idle deadline is short, so the server
//!    closes the connection soon after its response.
//! 3. Once that connection closed, the program arms its timer. When the timer fires, it calls
//!    `set_destination` with ::1 and sends a second GET. That connection goes to ::1.
//! 4. The program calls `shutdown` on each object, turns each until `stopped()`, calls each
//!    `deinit`, and closes its listener.
//!
//! The program calls `turn` and `complete` on the loop's thread alone, never from the handler.
//! This example binds loopback sockets in its own adapter, as design §8 step 44l plans.
//!
//! Run it with `zig build example-colibri_shared_rotor`, or every example with `zig build
//! examples`.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const colibri = @import("colibri");
const server = colibri.server;
const client = colibri.client;
const tls = @import("tls");
const platform = @import("platform");
// chapulin's hook, which every program that links `tls` defines.
const program = @import("tls_program.zig");

comptime {
    _ = program;
}

const Server = colibri.Server(.{ .tcp_connections = 2, .quic_connections = 0 }, .hosted);
const Client = colibri.Client(.{ .quic = false, .tcp_connections = 1, .requests = 1 }, .hosted);
var hosted_server: Server align(@alignOf(Server)) = undefined;
var hosted_client: Client align(@alignOf(Client)) = undefined;
var server_adapter: Adapter(Server, .server) align(@alignOf(Adapter(Server, .server))) = .{ .object = &hosted_server };
var client_adapter: Adapter(Client, .client) align(@alignOf(Adapter(Client, .client))) = .{ .object = &hosted_client };

/// The program's loop: it holds every operation of both objects and the program's timer.
const loop_options: rotor.Loop.Options = .{ .operations = Server.operations_max + Client.operations_max + 1 };
var loop_memory: [rotor.Loop.memory_bytes(&loop_options)]u8 align(rotor.memory_alignment) = undefined;
var loop: rotor.Loop align(@alignOf(rotor.Loop)) = undefined;
var events: [loop_options.operations]rotor.Event align(@alignOf(rotor.Event)) = undefined;

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/greeting", greet },
    },
};
const Router = server.Router(void, routes, .{ .requests = 2 });
var router: Router align(@alignOf(Router)) = .{};
var router_context: void = {};

const greeting = "hello from a shared loop\n";
/// RFC 9110 §15.3.1: 200 (OK), and §15.6.1: 500 (Internal Server Error).
const ok: client.Status = .ok;
const internal_server_error: server.Status = .internal_server_error;
/// How long the server keeps an idle connection open. The default is 10 s (decision 110).
const idle_ns = 20 * std.time.ns_per_ms;

const ipv4_loopback = [_]u8{ 127, 0, 0, 1 };
const ipv6_loopback = [_]u8{0} ** 15 ++ [_]u8{1};
var ipv4_addresses: [1]client.Address align(@alignOf(client.Address)) = undefined;
var ipv6_addresses: [1]client.Address align(@alignOf(client.Address)) = undefined;
/// The port the system chose for the listener: the origin's port, which stays the same.
var server_port: u16 = 0;

/// How long the program's timer waits, and the longest wait of one tick.
const timer_ns = 10 * std.time.ns_per_ms;
const tick_wait_ns_max = 100 * std.time.ns_per_ms;
/// The passes of the run, at most.
const passes_max = 10_000;

/// The owner of an operation, in the high byte of its `user_data`.
const Owner = enum(u8) { server, client, timer };
/// The adapter's tag: the owner, the kind and the socket. It fills the high 32 bits.
const Tag = packed struct(u32) { socket: u16, kind: u8, owner: Owner };
const Kind = std.meta.Tag(colibri.Operation.Kind);

fn user_data(owner: Owner, kind: Kind, socket: u16, id: colibri.OperationId) u64 {
    const tag: Tag = .{ .socket = socket, .kind = @intFromEnum(kind), .owner = owner };
    return @as(u64, @as(u32, @bitCast(tag))) << 32 | @intFromEnum(id);
}

/// One object's adapter: the descriptor of each `SocketId`, and the handle of each operation that
/// a cancel can name. Its calls are the free functions below, which take it as `self`.
fn Adapter(comptime Object: type, comptime owner: Owner) type {
    return struct {
        pub const owner_tag = owner;
        pub const written_max = Object.operations_max + Object.sockets_max;
        object: *Object,
        descriptors: [Object.sockets_max]?rotor.Descriptor = @splat(null),
        addresses: [Object.sockets_max]rotor.Address = undefined,
        cancelable: [Object.sockets_max]?colibri.OperationId = @splat(null),
        handles: [Object.sockets_max]rotor.Handle = @splat(rotor.Handle.none),
        /// The length of each address that a connect named: 4 for IPv4, 16 for IPv6.
        connects: [2]u8 = @splat(0),
        connects_len: u32 = 0,

        pub const turn = adapter_turn;
        pub const complete = adapter_complete;
        pub const closed = adapter_closed;
    };
}

/// Turns the object and submits each operation that it wrote.
fn adapter_turn(self: anytype) colibri.Wait {
    var operations: [@TypeOf(self.*).written_max]colibri.Operation = undefined;
    const turned = self.object.turn(loop.now_ns(), &operations);
    for (operations[0..turned.operations]) |*operation| submit(self, operation);
    return turned.wait;
}

fn submit(self: anytype, operation: *const colibri.Operation) void {
    const owner = @TypeOf(self.*).owner_tag;
    const id = operation.id;
    switch (operation.kind) {
        .accept => |named| {
            const listener = @intFromEnum(named.listener);
            submit_one(self, rotor.Operation.accept(user_data(owner, .accept, @intFromEnum(named.into), id), self.descriptors[listener].?), listener, id);
        },
        .connect => |named| connect(self, id, named.socket, named.address),
        .receive => |named| {
            const socket = @intFromEnum(named.socket);
            submit_one(self, rotor.Operation.receive(user_data(owner, .receive, socket, id), self.descriptors[socket].?, named.buffer), null, id);
        },
        .send => |named| {
            const socket = @intFromEnum(named.socket);
            submit_one(self, rotor.Operation.send(user_data(owner, .send, socket, id), self.descriptors[socket].?, named.bytes), null, id);
        },
        // The write side closes, and the receive on the socket goes on.
        .shutdown_send => |named| {
            const socket = @intFromEnum(named.socket);
            submit_one(self, rotor.Operation.shutdown(user_data(owner, .shutdown_send, socket, id), self.descriptors[socket].?, .send), null, id);
        },
        .close => |named| {
            const socket = @intFromEnum(named.socket);
            // A connect whose socket the system refused opened nothing, so its close has nothing
            // to close.
            const descriptor = self.descriptors[socket] orelse {
                return self.object.complete(&.{ .id = id, .result = .closed }, loop.now_ns());
            };
            submit_one(self, rotor.Operation.close(user_data(owner, .close, socket, id), descriptor), null, id);
        },
        .cancel => |named| for (self.cancelable, self.handles) |held, handle| {
            if (held == named.target) loop.cancel(handle);
        },
        // The program opened no UDP socket, so no object writes a datagram.
        .receive_datagram, .send_datagram => unreachable,
    }
}

/// Submits one operation, and keeps its handle when a cancel can name it.
fn submit_one(self: anytype, operation: rotor.Operation, cancelable: ?u16, id: colibri.OperationId) void {
    var handles: [1]rotor.Handle = undefined;
    assert(loop.submit(&.{operation}, &handles) == 1);
    const socket = cancelable orelse return;
    self.cancelable[socket] = id;
    self.handles[socket] = handles[0];
}

/// Opens a TCP socket of the address's family, sets TCP_NODELAY, and connects it.
fn connect(self: anytype, id: colibri.OperationId, socket: colibri.SocketId, address: server.Address) void {
    const index = @intFromEnum(socket);
    self.connects[self.connects_len] = address.len;
    self.connects_len += 1;
    self.addresses[index] = if (address.len == 4) rotor.Address.ipv4(address.octets[0..4].*, address.port) else rotor.Address.ipv6(address.octets, address.port, address.scope_id);
    const opened = rotor.sync.open_socket(self.addresses[index].family) catch {
        return self.object.complete(&.{ .id = id, .result = .{ .failed = .family_unsupported } }, loop.now_ns());
    };
    rotor.sync.set_no_delay(opened, true) catch {};
    self.descriptors[index] = opened;
    submit_one(self, rotor.Operation.connect(user_data(@TypeOf(self.*).owner_tag, .connect, index, id), opened, &self.addresses[index]), index, id);
}

/// Gives the object the completion of one event.
fn adapter_complete(self: anytype, tag: Tag, id: colibri.OperationId, event: rotor.Event) void {
    const result: colibri.Completion.Result = if (event.outcome()) |count| succeeded(self, tag, count) else |failure| failed(self, tag, failure);
    self.object.complete(&.{ .id = id, .result = result }, loop.now_ns());
}

/// The result of an operation that failed. A close that failed and was not canceled frees its
/// descriptor all the same, so the socket is closed.
fn failed(self: anytype, tag: Tag, failure: rotor.Error) colibri.Completion.Result {
    const canceled = failure == error.Canceled or failure == error.Timeout;
    if (@as(Kind, @enumFromInt(tag.kind)) == .close and !canceled) self.descriptors[tag.socket] = null;
    return switch (failure) {
        error.Canceled, error.Timeout => .canceled,
        error.ConnectionRefused => .{ .failed = .refused },
        error.ConnectionReset, error.ConnectionAborted, error.BrokenPipe => .{ .failed = .reset },
        else => .{ .failed = .other },
    };
}

/// The result of an operation that succeeded. An accept gives a new socket, and a close frees
/// one.
fn succeeded(self: anytype, tag: Tag, count: u32) colibri.Completion.Result {
    switch (@as(Kind, @enumFromInt(tag.kind))) {
        .accept => {
            rotor.sync.set_no_delay(@intCast(count), true) catch {};
            self.descriptors[tag.socket] = @intCast(count);
            return .accepted;
        },
        .connect => return .connected,
        .receive => return .{ .received = count },
        .send => return .{ .sent = count },
        .shutdown_send => return .shut_down,
        .close => {
            self.descriptors[tag.socket] = null;
            return .closed;
        },
        else => unreachable,
    }
}

/// Whether the object holds no open socket.
fn adapter_closed(self: anytype) bool {
    for (self.descriptors) |descriptor| {
        if (descriptor != null) return false;
    }
    return true;
}

/// What the program keeps for its exchanges, and what its handler records.
const Exchanges = struct {
    request: client.Request = .{ .method = "GET", .path = "/greeting" },
    responses: [2]client.Response = undefined,
    bodies: [2][64]u8 = undefined,
    finished: u32 = 0,

    pub fn on_finished(self: *Exchanges, _: *Client, _: client.Finished) void {
        self.finished += 1;
    }
};
var exchanges: Exchanges align(@alignOf(Exchanges)) = .{};

/// The program's own timer: armed once the first connection closed.
const Timer = enum { idle, armed, fired };
var timer: Timer align(@alignOf(Timer)) = .idle;

pub fn main() !void {
    try loop.init(&loop_memory, &loop_options);
    defer loop.deinit();
    _ = try loop.tick(&events, 0);
    // The host opens the listener before `init` (decision 159, answer 2). `::` takes IPv4 too.
    const listener = try rotor.sync.listen(&rotor.Address.ipv6(@splat(0), 0, 0), .{ .backlog = 16, .reuse_port = false });
    defer rotor.sync.close_now(listener);
    server_adapter.descriptors[@intFromEnum(Server.listener)] = listener;
    server_port = (try rotor.sync.local_address(listener)).port;
    const port = server_port;
    ipv4_addresses = .{.of(&ipv4_loopback, 0)};
    ipv6_addresses = .{.of(&ipv6_loopback, 0)};

    const random = tls.Random.init(&generator, fill);
    const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
    // Each object starts at the loop's instant. A cleartext client judges no date, so the
    // example names a fixed second in place of a reading of the system's clock.
    const now: colibri.server.Timestamp = .{ .unix_seconds = 1_800_000_000, .monotonic_ns = loop.now_ns() };
    try hosted_server.init(&.{ .cpu = cpu, .random = random, .now = now, .engine = .{ .timeouts = .{ .idle_ns = idle_ns } } }, &router, &router_context);
    try hosted_client.init(&.{
        .destination = .{ .addresses = &ipv4_addresses, .port = port },
        .pool = .{ .authority = "localhost", .protocols = .{ .h2 = false, .h3 = false } },
        .random = random,
        .now = now,
    }, &exchanges);
    try request(0);
    try run_until(second_exchange_ended);
    hosted_client.shutdown();
    hosted_server.shutdown();
    try run_until(both_stopped);
    hosted_client.deinit();
    hosted_server.deinit();

    // The first connection went to 127.0.0.1 and the second, after the timer, to ::1.
    if (client_adapter.connects_len != 2) return error.ConnectsWrong;
    if (client_adapter.connects[0] != 4 or client_adapter.connects[1] != 16) return error.DestinationWrong;
    for (&exchanges.responses) |*response| {
        if (response.result != .response or response.status != ok) return error.ResponseWrong;
        if (!std.mem.eql(u8, greeting, response.body_received())) return error.ResponseWrong;
    }
    std.debug.print("colibri_shared_rotor: one GET to 127.0.0.1, then one to ::1, on port {d}\n", .{port});
}

/// The source of randomness: one seed, as `colibri_hosted.zig` uses. A real program passes its
/// operating system's entropy.
var generator: std.Random.DefaultPrng align(@alignOf(std.Random.DefaultPrng)) = .init(0x5eed);

fn fill(state: *std.Random.DefaultPrng, buffer: []u8) void {
    state.fill(buffer);
}

fn request(index: usize) !void {
    exchanges.responses[index] = .{ .body = &exchanges.bodies[index] };
    _ = try hosted_client.request(&exchanges.request, &exchanges.responses[index]);
}

fn second_exchange_ended() bool {
    return exchanges.finished == 2;
}

fn both_stopped() bool {
    return hosted_server.stopped() and hosted_client.stopped();
}

/// Runs passes of the loop until `ended()` holds.
fn run_until(comptime ended: fn () bool) !void {
    for (0..passes_max) |_| {
        if (ended()) return;
        try pass();
    }
    return error.PassesExhausted;
}

/// One pass: a turn of each object, the program's timer, a tick that waits as the turns asked,
/// and each event to its owner.
fn pass() !void {
    const waits = [_]colibri.Wait{
        if (hosted_server.stopped()) .none else server_adapter.turn(),
        if (hosted_client.stopped()) .none else client_adapter.turn(),
    };
    if (timer == .idle and exchanges.finished == 1 and client_adapter.closed()) {
        timer = .armed;
        // The timer's tag names its owner alone: the kind and the socket are colibri's words.
        assert(loop.submit(&.{rotor.Operation.timer(user_data(.timer, .close, 0, @enumFromInt(0)), timer_ns, 0)}, &.{}) == 1);
    }
    const count = try loop.tick(&events, wait_of(&waits));
    for (events[0..count]) |event| {
        const tag: Tag = @bitCast(@as(u32, @truncate(event.user_data >> 32)));
        const id: colibri.OperationId = @enumFromInt(@as(u32, @truncate(event.user_data)));
        switch (tag.owner) {
            .server => server_adapter.complete(tag, id, event),
            .client => client_adapter.complete(tag, id, event),
            .timer => on_timer(),
        }
    }
}

/// The program's timer fired: the client's next connection goes to ::1. The open connection, if
/// any, would keep its exchanges (decision 125).
fn on_timer() void {
    timer = .fired;
    hosted_client.set_destination(&.{ .addresses = &ipv6_addresses, .port = server_port });
    request(1) catch |failure| std.debug.panic("request failed: {t}", .{failure});
}

/// How long a tick waits: no time when a turn asks for one at once, until the earliest instant
/// that a turn named, and at most `tick_wait_ns_max`.
fn wait_of(waits: []const colibri.Wait) u64 {
    var wait_ns: u64 = tick_wait_ns_max;
    for (waits) |wait| {
        switch (wait) {
            .now => return 0,
            .none => {},
            .at_ns => |at_ns| wait_ns = @min(wait_ns, at_ns -| loop.now_ns()),
        }
    }
    return wait_ns;
}

fn greet(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.header("content-type", "text/plain");
    try response.body().writeAll(greeting);
    try response.end();
}

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}
