//! The tests of a `colibri.Client` TCP socket whose connect is in flight (design §8 step 42). A
//! listener on 127.0.0.1 accepts nothing, and connects of a loop of the test's own fill its
//! backlog, so the system answers no later connect to it. The tests drive the client's TCP calls
//! as the pool's `open` and `close` events do. Decision 150 ruling 7 lets these tests bind
//! loopback. Test-only.
const std = @import("std");
const rotor = @import("rotor");
const client = @import("client");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");
const client_loop = @import("client_loop.zig");
const client_tcp = @import("client_tcp.zig");
const datagram_socket = @import("datagram_socket.zig");
const socket_module = @import("socket.zig");
const server_loop = @import("server_loop.zig");

const testing = std.testing;
const test_client = &fixture.test_client;

/// The connects that fill a backlog at most, and how long a connect waits for its event before
/// the test takes the backlog as full. A backlog of 1 holds one connect on macOS and two on Linux.
const fillers_max = 8;
const filler_wait_ns: u64 = 200_000_000;
/// How long a slot may stay in use after its connect's close: far less than the system's own
/// connect timeout, which is about 75 s on macOS and 127 s on Linux.
const freed_within_ns: u64 = 2_000_000_000;
/// The turns a test runs at most while it waits for a slot. Each tick waits 50 ms at most.
const turns_max = 1000;
/// The connect deadline the test of a full backlog sets, and how long its run may last: less than
/// the default deadline of 10 s, and far less than the system's own connect timeout.
const connect_deadline_ns: u64 = 200_000_000;
const deadline_watchdog_ms: u64 = 3_000;

const filler_options: rotor.Loop.Options = .{ .operations = fillers_max };

/// The listener, its address, and the connects that fill its backlog, with the loop that runs
/// them. Placed outside any stack frame. Test-only.
const Unanswered = struct {
    listener: rotor.Descriptor,
    address: rotor.Address,
    fillers: [fillers_max]rotor.Descriptor,
    filler_count: usize,
    loop: rotor.Loop,
    loop_memory: [rotor.Loop.memory_bytes(filler_options)]u8 align(rotor.memory_alignment),
    events: [fillers_max]rotor.Event,

    /// Listens on 127.0.0.1 with a backlog of 1, and connects until a connect gets no event.
    fn fill(state: *Unanswered) !void {
        state.filler_count = 0;
        // 127.0.0.1, on a port the system chooses.
        const loopback = try server_loop.address_of("127.0.0.1", 0);
        state.listener = try rotor.sync.listen(&loopback, .{ .backlog = 1, .reuse_port = false });
        state.address = try rotor.sync.local_address(state.listener);
        try state.loop.init(&state.loop_memory, filler_options);
        for (0..fillers_max) |index| {
            const descriptor = try rotor.sync.open_socket(.ipv4);
            state.fillers[index] = descriptor;
            state.filler_count = index + 1;
            const operation = rotor.Operation.connect(index, descriptor, &state.address);
            try testing.expectEqual(1, state.loop.submit(&.{operation}, &.{}));
            if (try state.loop.tick(&state.events, filler_wait_ns) == 0) return;
        }
        return error.BacklogNotFull;
    }

    fn release(state: *Unanswered) void {
        state.loop.cancel_all();
        state.loop.drain(&state.events) catch {};
        state.loop.deinit();
        for (state.fillers[0..state.filler_count]) |descriptor| rotor.sync.close_now(descriptor);
        rotor.sync.close_now(state.listener);
    }
};
threadlocal var unanswered: Unanswered align(@alignOf(Unanswered)) = undefined;

/// What `run` passes the loop's turns: the client and the program's handler.
const Run = struct { client: *fixture.TestClient, handler: *fixture.Handler };

/// Starts the client over h11 in cleartext to the unanswered listener, and its loop.
fn start(counter: *support.Counter) !void {
    var pool = fixture.pool_config(.{ .h2 = false }, false);
    pool.protocols.h3 = false;
    try test_client.init(.{ .host = "127.0.0.1", .port = unanswered.address.port, .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds });
    try test_client.loop.init(&test_client.loop_memory, .{ .operations = test_client.events.len });
    try client_loop.begin(test_client);
}

/// The pool's `open` of the TCP connection `generation` holds in slot 0.
fn open(generation: u32) void {
    client_tcp.open(test_client, .{
        .connection = handle(generation),
        .transport = .tcp,
        .to = datagram_socket.peer_address(unanswered.address),
    });
}

fn handle(generation: u32) client.ConnectionHandle {
    return .{ .slot = 0, .generation = generation };
}

/// Runs turns until slot 0 holds no socket, and returns the nanoseconds that took.
fn turns_until_free(running: *Run) !u64 {
    const started_ns = test_client.loop.now_ns();
    for (0..turns_max) |_| {
        const elapsed_ns = test_client.loop.now_ns() - started_ns;
        if (!test_client.sockets[0].live or elapsed_ns > freed_within_ns) return elapsed_ns;
        try client_loop.turn(running);
    }
    return error.TurnsExhausted;
}

test "design §8 step 42: a connect the pool closes in flight frees its slot at once" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer client_loop.end(test_client);
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    open(1);
    for (0..3) |_| try client_loop.turn(&running);
    // The listener's backlog is full, so the connect waits for an answer.
    try testing.expect(test_client.connections[0].connecting);
    client_tcp.close(test_client, handle(1));
    // Rotor's close cancels the connect, so the slot does not wait for the system's timeout.
    try testing.expect(try turns_until_free(&running) <= freed_within_ns);
    try testing.expect(!test_client.sockets[0].live);
}

test "design §8 step 42: a close names one connection of a slot, and drops an open that waits" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer client_loop.end(test_client);
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    open(2);
    // A handle of the slot's earlier connection names nothing (decision 125).
    client_tcp.close(test_client, handle(1));
    try testing.expect(!test_client.sockets[0].closing);
    // The next connection's open waits for the slot's socket, and its close drops it.
    open(3);
    try testing.expectEqual(handle(3), test_client.connections[0].waiting.?.connection);
    client_tcp.close(test_client, handle(3));
    try testing.expectEqual(null, test_client.connections[0].waiting);
    client_tcp.close(test_client, handle(2));
    try testing.expect(try turns_until_free(&running) <= freed_within_ns);
    // No socket opened for the open the pool dropped.
    try testing.expect(!test_client.sockets[0].live);
}

test "design §8 step 42: the end of a run closes a socket whose close was never submitted" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    open(1);
    const descriptor = test_client.sockets[0].descriptor;
    // A run that fails, as a failed tick does, ends with the connect in flight.
    client_loop.end(test_client);
    try testing.expect(!test_client.sockets[0].live);
    // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
    try testing.expectError(error.Unexpected, rotor.sync.local_address(descriptor));
}

test "design §8 step 42: a slot whose close ended waits for its connect's final event" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer client_loop.end(test_client);
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    open(1);
    // The close's final event came first, as Rotor's rules allow, and the connect's is still owed.
    test_client.sockets[0].closing = true;
    test_client.sockets[0].closed = true;
    test_client.pending.set(0);
    client_tcp.serve(&running, test_client.loop.now_ns());
    try testing.expect(test_client.sockets[0].live);
}

test "design §8 step 42: a connect that succeeds after the pool's close starts no connection" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer client_loop.end(test_client);
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    open(1);
    client_tcp.close(test_client, handle(1));
    // The connect's event says it succeeded: it ended before Rotor's close cancelled it.
    const connected = rotor.Event.success(socket_module.user_data(0, .connect), 0);
    client_tcp.on_event(&running, connected, test_client.loop.now_ns());
    try testing.expect(!test_client.connections[0].started);
}

test "design §8 step 42: init leaves no TCP socket live, so a run that fails at once closes none" {
    var counter: support.Counter = .{};
    // A socket of the test's own, which an earlier run's entry still names.
    const descriptor = try rotor.sync.open_socket(.ipv4);
    defer rotor.sync.close_now(descriptor);
    test_client.sockets[0].descriptor = descriptor;
    test_client.sockets[0].close_submitted = false;
    test_client.sockets[0].live = true;
    try test_client.init(.{ .host = "127.0.0.1", .pool = .{ .authority = "localhost" }, .random = counter.random(), .unix_seconds = fixture.now_seconds });
    defer test_client.deinit();
    // The run's first tick failed, so no turn reset the sockets before its end.
    try test_client.loop.init(&test_client.loop_memory, .{ .operations = test_client.events.len });
    client_loop.end(test_client);
    // The end closed no descriptor the client does not hold.
    _ = try rotor.sync.local_address(descriptor);
}

test "decision 153 ruling 9: a connect past its deadline ends the exchange refused" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    var pool = fixture.pool_config(.{ .h2 = false }, false);
    pool.protocols.h3 = false;
    pool.timeouts.connect_ns = connect_deadline_ns;
    try test_client.init(.{ .host = "127.0.0.1", .port = unanswered.address.port, .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds });
    defer test_client.deinit();
    var handler: fixture.Handler = .{};
    try handler.request(1);
    test_client.shutdown();
    // The listener's backlog is full, so the system answers no connect. Rotor cancels the connect
    // at its deadline, and the run returns before the watchdog halts the test.
    try fixture.run_within(&handler, deadline_watchdog_ms);
    try testing.expectEqual(1, handler.finished);
    // The connection never started, so no request was written: the pool may send it again.
    try testing.expectEqual(client.Result.refused, handler.exchanges[0].response.result);
    try testing.expectEqual(null, handler.connected);
}

test "decision 153 ruling 9: a connect limit past Rotor's longest deadline connects with one day" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer client_loop.end(test_client);
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    // A program may write the largest value to mean no practical limit. Rotor halts on a deadline
    // past `timeout_ns_max` at the submit.
    test_client.pool_config.timeouts.connect_ns = std.math.maxInt(u64);
    open(1);
    for (0..3) |_| try client_loop.turn(&running);
    try testing.expect(test_client.connections[0].connecting);
    client_tcp.close(test_client, handle(1));
    try testing.expect(try turns_until_free(&running) <= freed_within_ns);
}

/// Reads the pool's events until its `open`, as the turn's drain does.
fn pool_open() !client.Open {
    for (0..fillers_max) |_| {
        const received = test_client.pool.receive(.none, test_client.loop.now_ns());
        const reported = received.event orelse return error.NoOpen;
        switch (reported) {
            .open => |asked| return asked,
            else => {},
        }
    }
    return error.NoOpen;
}

/// Opens the socket `asked` names while the process may open no descriptor, so the system
/// refuses the socket with EMFILE.
fn open_refused(asked: client.Open) !void {
    const limits = try std.posix.getrlimit(.NOFILE);
    try std.posix.setrlimit(.NOFILE, .{ .cur = 0, .max = limits.max });
    client_tcp.open(test_client, asked);
    try std.posix.setrlimit(.NOFILE, limits);
}

test "design §8 step 42: a socket the system refuses leaves the pool's events for the next tick" {
    var counter: support.Counter = .{};
    var pool = fixture.pool_config(.{ .h2 = false }, false);
    pool.protocols.h3 = false;
    // The system refuses the socket, so no connect names the port.
    try test_client.init(.{ .host = "127.0.0.1", .port = 1, .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds });
    defer test_client.deinit();
    try test_client.loop.init(&test_client.loop_memory, .{ .operations = test_client.events.len });
    try client_loop.begin(test_client);
    defer client_loop.end(test_client);
    var handler: fixture.Handler = .{};
    try handler.request(1);
    const asked = try pool_open();
    // The open waited for the slot, so `serve` makes it after the turn's drain read every event.
    test_client.undrained = false;
    try open_refused(asked);
    try testing.expect(!test_client.sockets[0].live);
    // The pool owes the exchange's end, so the next tick waits for nothing.
    try testing.expect(test_client.undrained);
}
