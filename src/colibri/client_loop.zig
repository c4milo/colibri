//! The loop of a `colibri.Client` (design §8 step 42), on Rotor's own calls (decision 150 ruling
//! 6). One loop runs on the thread that calls `run` (ruling 7). Each turn:
//! 1. passes a `shutdown` to the pool once;
//! 2. ticks, and waits no longer than the pool's next deadline;
//! 3. hands each event to the socket it names, fires the pool's deadlines, and reads the pool's
//!    events;
//! 4. steps each TCP socket an event named (`client_tcp.zig`);
//! 5. submits what each socket needs next, and sends the datagrams the pool owes.
//!
//! The pool's events go to the program's handler: `on_finished` for each exchange that ends, and
//! `on_connected`, when the handler declares it, for the connection that takes the exchanges.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const client = @import("client");
const constants = @import("constants.zig");
const datagram_socket = @import("datagram_socket.zig");
const client_tcp = @import("client_tcp.zig");

/// Runs the client `state` names on the calling thread until its pool reports `closed` and every
/// socket has closed (`Client.run`). The UDP socket closes last, once the loop has had each
/// operation's final event.
pub fn run_loop(state: anytype, handler: anytype, comptime options: rotor.Loop.Options) !void {
    const Handler = @typeInfo(@TypeOf(handler)).pointer.child;
    comptime assert(@hasDecl(Handler, "on_finished"));
    assert(state.config.random != null);
    // The pool reports `closed` once, so a second run would wait for it without end.
    assert(!state.ran);
    state.ran = true;
    defer state.udp.close();
    try state.loop.init(&state.loop_memory, options);
    defer end(state);
    try begin(state);
    const Run = struct { client: @TypeOf(state), handler: @TypeOf(handler) };
    var running: Run = .{ .client = state, .handler = handler };
    while (!finished(state)) try turn(&running);
}

/// Starts a run on the loop `init` prepared: the first tick, which waits for nothing, reads the
/// clock, whose instant the run starts at.
pub fn begin(state: anytype) !void {
    assert(try state.loop.tick(&state.events, 0) == 0);
    reset(state);
    if (state.udp.open) try state.udp.start(&state.loop);
}

/// Ends a run, whether it finished or failed: it cancels what is in flight, waits for each final
/// event, closes each TCP socket whose close was never submitted, and frees the loop.
pub fn end(state: anytype) void {
    state.loop.cancel_all();
    state.loop.drain(&state.events) catch {};
    @import("socket.zig").close_left(&state.sockets);
    state.loop.deinit();
}

/// Empties what a run holds: no socket and no pending step. The caller has ticked the loop once,
/// so its instant is the run's first.
pub fn reset(state: anytype) void {
    for (&state.sockets) |*socket| socket.live = false;
    state.connections = @splat(client_tcp.Connection.empty);
    state.pending = .initEmpty();
    state.touched = .initEmpty();
    // A request made before `run` waits for the first drain, which this turn makes at once.
    state.undrained = true;
    state.shut_down = false;
    state.closed = false;
    state.started_ns = state.loop.now_ns();
}

/// The seconds since 1970 at `now_ns`: the program's instant at the start of `run`, and the time
/// the loop has run since. chapulin judges a chain's dates at it (RFC 5280 §4.1.2.5).
pub fn unix_seconds(state: anytype, now_ns: u64) u64 {
    return state.config.unix_seconds + (now_ns -| state.started_ns) / client.constants.nanoseconds_per_second;
}

/// One turn of the loop. See the header.
pub fn turn(run: anytype) !void {
    const state = run.client;
    pass_shutdown(state);
    const deadline_ns = state.pool.deadline_ns();
    const count = try state.loop.tick(&state.events, wait_ns(state, deadline_ns, state.loop.now_ns()));
    const now_ns = state.loop.now_ns();
    for (state.events[0..count]) |event| on_event(run, event, now_ns);
    const due = if (deadline_ns) |at_ns| at_ns <= now_ns else false;
    if (due) state.pool.on_instant(now_ns);
    drain(run, now_ns);
    client_tcp.serve(run, now_ns);
    client_tcp.arm(state);
    if (state.udp.open) state.udp.flush(&state.loop, &state.pool, now_ns);
}

/// Passes a `shutdown` to the pool once. A connection the shutdown ends owes its last octets, such
/// as h2's GOAWAY (RFC 9113 §6.8). The turn steps each running socket, because of a bug of the
/// pool: after `shutdown`, an idle h2 connection never sends its GOAWAY. Its last `send_stream`
/// wrote nothing and set `send_blocked`, and `shutdown` does not clear it, so the pool reports no
/// `send` event. The fix belongs in `src/client/pool/`, which design §8 step 39 changes.
pub fn pass_shutdown(state: anytype) void {
    if (!state.stopping.load(.acquire) or state.shut_down) return;
    state.shut_down = true;
    state.pool.shutdown();
    state.undrained = true;
    for (state.connections, 0..) |connection, slot| {
        if (connection.started) state.pending.set(slot);
    }
}

/// How long the tick after `now_ns` may wait: until `deadline_ns`, the pool's next deadline, and
/// never longer than `stop_wait_ns_max`, so a `shutdown` from another thread takes effect. No time
/// while work is left.
fn wait_ns(state: anytype, deadline_ns: ?u64, now_ns: u64) u64 {
    if (state.undrained or state.pending.count() > 0) return 0;
    const at_ns = deadline_ns orelse return constants.limits.stop_wait_ns_max;
    return @min(constants.limits.stop_wait_ns_max, at_ns -| now_ns);
}

fn on_event(run: anytype, event: rotor.Event, now_ns: u64) void {
    if (datagram_socket.owns(event.user_data)) return @import("client_udp.zig").on_event(run, event, now_ns);
    client_tcp.on_event(run, event, now_ns);
}

/// Reads the pool's events until it reports none, and does what each asks. A read that reaches
/// its bound leaves the rest for the next turn, which then waits for nothing.
pub fn drain(run: anytype, now_ns: u64) void {
    const state = run.client;
    for (0..constants.limits.events_per_step_max) |_| {
        const received = state.pool.receive(.none, now_ns);
        assert(received.consumed == 0);
        const reported = received.event orelse {
            state.undrained = false;
            return;
        };
        handle(run, reported, now_ns);
    }
    state.undrained = true;
}

/// Does what one of the pool's events asks.
pub fn handle(run: anytype, reported: client.Event, now_ns: u64) void {
    const state = run.client;
    switch (reported) {
        .open => |asked| switch (asked.transport) {
            .tcp => client_tcp.open(state, asked),
            .quic => @import("client_udp.zig").start(state, now_ns),
        },
        .send => |connection| client_tcp.owed(state, connection),
        .close => |connection| client_tcp.close(state, connection),
        .connected => |connected| on_connected(run, connected),
        // The client offers no ticket, so it keeps none it is given.
        .ticket => |connection| if (state.pool.take_ticket(connection)) |ticket| {
            var held = ticket;
            held.wipe();
        },
        .finished => |ended| run.handler.on_finished(state, ended),
        // The run's end cancels the UDP socket's receive (`end`).
        .closed => state.closed = true,
    }
}

/// Hands `on_connected` the connection that takes the exchanges, when the handler declares it.
fn on_connected(run: anytype, connected: client.Connected) void {
    const Handler = @typeInfo(@TypeOf(run.handler)).pointer.child;
    if (@hasDecl(Handler, "on_connected")) run.handler.on_connected(run.client, connected);
}

/// Whether the loop may end: the pool reported `closed`, and every TCP socket is free.
pub fn finished(state: anytype) bool {
    if (!state.closed) return false;
    for (&state.sockets) |*socket| {
        if (socket.live) return false;
    }
    return true;
}

const testing = std.testing;

/// The fields `unix_seconds` and `wait_ns` read, with nothing else of a client. Test-only.
const Clock = struct {
    config: struct { unix_seconds: u64 },
    started_ns: u64,
};
const Waits = struct {
    undrained: bool,
    pending: std.bit_set.IntegerBitSet(1),
};

test "design §8 step 42: a chain is judged at the program's instant plus the loop's time since" {
    const second_ns = client.constants.nanoseconds_per_second;
    const clock: Clock = .{ .config = .{ .unix_seconds = 1_000 }, .started_ns = 5 * second_ns };
    try testing.expectEqual(1_000, unix_seconds(&clock, 5 * second_ns));
    // Two and a half seconds of the loop count as two whole seconds.
    try testing.expectEqual(1_002, unix_seconds(&clock, 7 * second_ns + second_ns / 2));
}

test "design §8 step 42: a tick waits for the pool's deadline, and for nothing while work is left" {
    var waits: Waits = .{ .undrained = false, .pending = .initEmpty() };
    const limit_ns = constants.limits.stop_wait_ns_max;
    try testing.expectEqual(limit_ns, wait_ns(&waits, null, 0));
    try testing.expectEqual(limit_ns / 2, wait_ns(&waits, 3 * limit_ns / 2, limit_ns));
    try testing.expectEqual(limit_ns, wait_ns(&waits, 3 * limit_ns, 0));
    // A socket an event named waits for its step, and so do the pool's events left unread.
    waits.pending.set(0);
    try testing.expectEqual(0, wait_ns(&waits, null, 0));
    waits.pending = .initEmpty();
    waits.undrained = true;
    try testing.expectEqual(0, wait_ns(&waits, null, 0));
}
