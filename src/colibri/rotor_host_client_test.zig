//! The tests of a `colibri.Client`'s sockets on colibri's own Rotor host (design §8 step 42,
//! decision 159), most of them on a TCP socket whose connect is in flight. A listener on 127.0.0.1
//! accepts nothing, and connects of a loop of the test's own fill its backlog, so the system
//! answers no later connect to it. The tests drive the client's TCP calls as the pool's `open` and
//! `close` events do, and run the host's passes. Decision 150 ruling 7 lets these tests bind
//! loopback. Test-only.
const std = @import("std");
const rotor = @import("rotor");
const client = @import("client");
const testdata = @import("testdata");
const tls = @import("tls");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");
const client_loop = @import("client_loop.zig");
const client_tcp = @import("client_tcp.zig");
const rotor_host = @import("rotor_host.zig");
const rotor_host_udp = @import("rotor_host_udp.zig");

const testing = std.testing;
const test_client = &fixture.test_client;
const socket_id: @import("host.zig").SocketId = @enumFromInt(0);

/// The connects that fill a backlog at most, and how long a connect waits for its event before
/// the test takes the backlog as full. A backlog of 1 holds one connect on macOS and two on Linux.
const fillers_max = 8;
const filler_wait_ns: u64 = 200_000_000;
/// How long a slot may stay in use after its connect's close: far less than the system's own
/// connect timeout, which is about 75 s on macOS and 127 s on Linux.
const freed_within_ns: u64 = 2_000_000_000;
/// The passes a test runs at most while it waits for a slot. Each tick waits 50 ms at most.
const passes_max = 1000;
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
    loop_memory: [rotor.Loop.memory_bytes(&filler_options)]u8 align(rotor.memory_alignment),
    events: [fillers_max]rotor.Event,

    /// Listens on 127.0.0.1 with a backlog of 1, and connects until a connect gets no event.
    fn fill(state: *Unanswered) !void {
        state.filler_count = 0;
        // 127.0.0.1, on a port the system chooses.
        const loopback = try rotor_host.address_of("127.0.0.1", 0);
        state.listener = try rotor.sync.listen(&loopback, .{ .backlog = 1, .reuse_port = false });
        state.address = try rotor.sync.local_address(state.listener);
        try state.loop.init(&state.loop_memory, &filler_options);
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

/// What a pass gives the driver's turns: the client and the program's handler.
const Run = struct { client: *fixture.TestClient, handler: *fixture.Handler };

/// Starts the client over h11 in cleartext to `port`, and its loop.
fn start_on(port: u16, counter: *support.Counter) !void {
    var pool = fixture.pool_config(.{ .h2 = false }, false);
    pool.protocols.h3 = false;
    try test_client.init(.{ .host = "127.0.0.1", .port = port, .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds });
    client_loop.start(test_client, try test_client.host.begin());
}

/// Starts the client over h11 in cleartext to the unanswered listener, and its loop.
fn start(counter: *support.Counter) !void {
    try start_on(unanswered.address.port, counter);
}

/// Ends a run as `run` does, whether it finished or failed.
fn end_run() void {
    test_client.host.end();
    test_client.host.close_open();
}

/// The pool's `open` of the TCP connection `generation` holds in slot 0.
fn open(generation: u32) void {
    client_tcp.open(test_client, .{
        .connection = handle(generation),
        .transport = .tcp,
        .to = rotor_host_udp.peer_address(unanswered.address),
    });
}

fn handle(generation: u32) client.ConnectionHandle {
    return .{ .slot = 0, .generation = generation };
}

/// Runs passes until slot 0 holds no socket, and returns the nanoseconds that took.
fn passes_until_free(running: *Run) !u64 {
    const started_ns = test_client.host.loop.now_ns();
    for (0..passes_max) |_| {
        const elapsed_ns = test_client.host.loop.now_ns() - started_ns;
        if (!test_client.sockets[0].live or elapsed_ns > freed_within_ns) return elapsed_ns;
        try test_client.host.pass(running, client_loop);
    }
    return error.PassesExhausted;
}

test "design §8 step 42: a connect the pool closes in flight frees its slot at once" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer end_run();
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    open(1);
    for (0..3) |_| try test_client.host.pass(&running, client_loop);
    // The listener's backlog is full, so the connect waits for an answer.
    try testing.expect(test_client.connections[0].connecting);
    client_tcp.close(test_client, handle(1));
    // The host's close cancels the connect, so the slot does not wait for the system's timeout.
    try testing.expect(try passes_until_free(&running) <= freed_within_ns);
    try testing.expect(!test_client.sockets[0].live);
}

test "design §8 step 42: a close names one connection of a slot, and drops an open that waits" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer end_run();
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    open(2);
    try test_client.host.pass(&running, client_loop);
    // A handle of the slot's earlier connection names nothing (decision 125).
    client_tcp.close(test_client, handle(1));
    try testing.expect(!test_client.sockets[0].closing);
    // The next connection's open waits for the slot's socket, and its close drops it.
    open(3);
    try testing.expectEqual(handle(3), test_client.connections[0].waiting.?.connection);
    client_tcp.close(test_client, handle(3));
    try testing.expectEqual(null, test_client.connections[0].waiting);
    client_tcp.close(test_client, handle(2));
    try testing.expect(try passes_until_free(&running) <= freed_within_ns);
    // No socket opened for the open the pool dropped.
    try testing.expect(!test_client.sockets[0].live);
}

test "design §8 step 42: the end of a run closes a socket whose close was never submitted" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    open(1);
    try test_client.host.pass(&running, client_loop);
    const descriptor = test_client.host.descriptor_of(socket_id);
    // A run that fails, as a failed tick does, ends with the connect in flight.
    end_run();
    try testing.expect(!test_client.host.open(socket_id));
    // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
    try testing.expectError(error.Unexpected, rotor.sync.local_address(descriptor));
}

test "design §8 step 42: a slot whose close ended waits for its connect's final event" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer end_run();
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    open(1);
    try test_client.host.pass(&running, client_loop);
    // The close's final completion came first, as decision 159 allows, and the connect's is
    // still owed.
    test_client.sockets[0].closing = true;
    test_client.sockets[0].closed = true;
    test_client.pending.set(0);
    client_tcp.serve(&running, test_client.host.loop.now_ns());
    try testing.expect(test_client.sockets[0].live);
}

test "design §8 step 42: a connect that succeeds after the pool's close starts no connection" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer end_run();
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    open(1);
    try test_client.host.pass(&running, client_loop);
    client_tcp.close(test_client, handle(1));
    // The connect's completion says it succeeded: it ended before the host's close cancelled it.
    client_tcp.complete(&running, 0, .connect, .connected, test_client.host.loop.now_ns());
    try testing.expect(!test_client.connections[0].started);
}

test "design §8 step 42: init leaves no TCP socket open, so a run that fails at once closes none" {
    var counter: support.Counter = .{};
    // A socket of the test's own, which an earlier run's table still names.
    const descriptor = try rotor.sync.open_socket(.ipv4);
    defer rotor.sync.close_now(descriptor);
    test_client.host.descriptors[0] = descriptor;
    test_client.host.states[0] = .open;
    try start_on(1, &counter);
    defer test_client.deinit();
    // The run's first pass failed, so no turn ran before its end.
    end_run();
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
    // The listener's backlog is full, so the system answers no connect. The driver cancels the
    // connect at its deadline, and the run returns before the watchdog halts the test.
    try fixture.run_within(&handler, deadline_watchdog_ms);
    try testing.expectEqual(1, handler.finished);
    // The connection never started, so no request was written: the pool may send it again.
    try testing.expectEqual(client.Result.refused, handler.exchanges[0].response.result);
    try testing.expectEqual(null, handler.connected);
}

test "decision 153 ruling 9: a connect limit of the largest value holds the connect until a close" {
    try unanswered.fill();
    defer unanswered.release();
    var counter: support.Counter = .{};
    try start(&counter);
    defer test_client.deinit();
    defer end_run();
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    // A program may write the largest value to mean no practical limit.
    test_client.pool_config.timeouts.connect_ns = std.math.maxInt(u64);
    open(1);
    for (0..3) |_| try test_client.host.pass(&running, client_loop);
    try testing.expect(test_client.connections[0].connecting);
    client_tcp.close(test_client, handle(1));
    try testing.expect(try passes_until_free(&running) <= freed_within_ns);
}

/// Runs one pass while the process may open no descriptor, so the system refuses the socket of
/// the connect the pass writes with EMFILE.
fn pass_refused(running: *Run) !void {
    const limits = try std.posix.getrlimit(.NOFILE);
    try std.posix.setrlimit(.NOFILE, .{ .cur = 0, .max = limits.max });
    const passed = test_client.host.pass(running, client_loop);
    try std.posix.setrlimit(.NOFILE, limits);
    try passed;
}

test "design §8 step 42: a socket the system refuses ends the exchange refused" {
    var counter: support.Counter = .{};
    // The system refuses the socket, so no connect names the port.
    try start_on(1, &counter);
    defer test_client.deinit();
    defer end_run();
    var handler: fixture.Handler = .{};
    var running: Run = .{ .client = test_client, .handler = &handler };
    try handler.request(1);
    try pass_refused(&running);
    // The host completed the connect at once, so the driver holds work and the next turn waits
    // for nothing.
    try testing.expect(test_client.pending.isSet(0));
    for (0..passes_max) |_| {
        if (handler.finished == 1 and !test_client.sockets[0].live) break;
        try test_client.host.pass(&running, client_loop);
    }
    try testing.expectEqual(client.Result.refused, handler.exchanges[0].response.result);
    try testing.expect(!test_client.sockets[0].live);
}

/// A pool configuration over TLS that trusts the test identity's root for `localhost`. Test-only.
const anchors = [_]tls.Anchor{.{ .subject = testdata.root_name, .spki = testdata.root_spki }};

test "design §8 step 42: a client over TLS opens a UDP socket of the host's family" {
    var counter: support.Counter = .{};
    const pool: client.Config = .{
        .authority = "localhost",
        .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "localhost" } }, .cpu = support.cpu() },
    };
    try test_client.init(.{ .host = "::1", .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds });
    try testing.expect(test_client.udp.served);
    const udp_socket = test_client.host.descriptor_of(client_loop.datagram_id(1));
    const local = try rotor.sync.local_address(udp_socket);
    try testing.expectEqual(rotor.Address.Family.ipv6, local.family);
    try testing.expect(local.port != 0);
    // The pool connects to the host, on the port the configuration names.
    try testing.expectEqual(16, test_client.addresses[0].len);
    try testing.expectEqual(1, test_client.addresses[0].octets[15]);
    try testing.expectEqual(443, test_client.pool.values.port);
    // `deinit` closes the UDP socket. getsockname(2) on a closed descriptor fails with EBADF, which
    // Rotor reports as unexpected.
    test_client.deinit();
    try testing.expectError(error.Unexpected, rotor.sync.local_address(udp_socket));
    try testing.expect(!test_client.host.open(client_loop.datagram_id(1)));
}
