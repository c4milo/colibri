//! The logged state of `spec/tla/h3_deadlines`'s model, computed from the h3 deadline trace run's
//! world after each of its actions (design §8 step 20d): the variables that map one to one onto
//! colibri and its client, and whether each of colibri's clocks runs. The model's variables keep
//! their names here, spelled the Zig way. Functions over the requests are arrays, request 0
//! first, and hold their initial values past the plan's requests.
//!
//! Each clock reads what colibri's own code reads (`quic_deadline.zig`, `quic_body.zig` and
//! `quic_sends.zig`): the idle instant and the drain's, a stream h3 holds in its head phase, a
//! body the server waits for, and the connection's send meter. The idle and head clocks wait
//! while colibri holds credit, which the run's wide windows never make it do.
const std = @import("std");
const sim = @import("sim");
const server = @import("server");
const world_module = @import("h3_deadline_trace_world.zig");
const plan_module = @import("h3_deadline_trace_plan.zig");

const limits = sim.constants.h3_deadline_trace;
const World = world_module.World;
const Plan = plan_module.Plan;
const stream_of = world_module.stream_of;
const request_stream_step = world_module.request_stream_step;

pub const Phase = world_module.Phase;
pub const Outcome = world_module.Outcome;
pub const TimedOut = enum { none, first_request, idle, drain };
pub const Closed = enum { open, drained, drain };

pub const Error = error{
    /// colibri closed for a reason the model has no name for.
    Unmapped,
};

const requests_max = limits.requests_max;

pub const State = struct {
    // The client.
    opened: u32 = 0,
    outcome: [requests_max]Outcome = @splat(.none),
    goaway_read: bool = false,
    close_read: bool = false,
    // colibri.
    taken: u64 = 0,
    phase: [requests_max]Phase = @splat(.unseen),
    processed: [requests_max]bool = @splat(false),
    body_waits: [requests_max]bool = @splat(false),
    written: [requests_max]u32 = @splat(0),
    aborted: [requests_max]bool = @splat(false),
    goaway_id: u64 = 0,
    first_request_read: bool = false,
    shutting_down: bool = false,
    timed_out: TimedOut = .none,
    closed: Closed = .open,
    // colibri's clocks.
    first_request_runs: bool = false,
    idle_runs: bool = false,
    head_runs: [requests_max]bool = @splat(false),
    body_runs: [requests_max]bool = @splat(false),
    send_runs: bool = false,
    drain_runs: bool = false,
};

pub fn compute(world: *const World, plan: *const Plan) Error!State {
    const connection = world.connection();
    const clock = &connection.clock;
    const runs = world.server_runs();
    const takes = runs and !connection.shutting_down;
    const held = clock.credit_held_since_ns != null;
    var state: State = .{
        .opened = @intCast(world.peer.fetches_len),
        .goaway_read = world.peer.goaway_ms != null,
        .close_read = world.peer.close != null,
        .taken = connection.h3.requests.next_index,
        // The model's NoGoaway is one past its last request stream.
        .goaway_id = if (connection.h3.goaway_sent) |id| id / request_stream_step else plan.requests + 1,
        .first_request_read = clock.first_request_read,
        .shutting_down = connection.shutting_down,
        .timed_out = try timed_out_of(clock.timed_out),
        .closed = if (runs) .open else if (clock.timed_out == .drain) .drain else .drained,
        .first_request_runs = takes and !clock.first_request_read,
        .idle_runs = takes and clock.idle_since_ns != null and !held,
        .send_runs = runs and connection.sends.meter.running(),
        .drain_runs = runs and clock.drain_since_ns != null,
    };
    for (0..plan.requests) |index| {
        state.outcome[index] = world.outcome[index];
        state.phase[index] = world.phase_of(index);
        state.processed[index] = world.processed[index];
        state.written[index] = world.written[index];
        state.aborted[index] = world.aborted[index];
        state.body_waits[index] = body_waits(connection, index);
        state.body_runs[index] = runs and state.body_waits[index];
        state.head_runs[index] = runs and !held and head_waits(connection, index);
    }
    return state;
}

fn timed_out_of(passed: ?server.Deadline) Error!TimedOut {
    const deadline = passed orelse return .none;
    return switch (deadline) {
        .first_request => .first_request,
        .idle => .idle,
        .drain => .drain,
        else => error.Unmapped,
    };
}

/// Whether the server waits for the content of request `index` (`quic_body.zig`).
fn body_waits(connection: *server.QuicConnection, index: usize) bool {
    const record = connection.requests.of(stream_of(index)) orelse return false;
    return connection.bodies.entries[connection.requests.index_of(record)].waiting;
}

/// Whether h3 waits for the head of request `index`, which the server's head deadline judges
/// (`oldest_head_wait`).
fn head_waits(connection: *server.QuicConnection, index: usize) bool {
    if (!connection.started or !connection.h3.requests.head_wait_possible) return false;
    const request = connection.h3.requests.find(stream_of(index)) orelse return false;
    return request.phase == .head;
}
