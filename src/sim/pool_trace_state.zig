//! The state of spec/tla/client_exchanges's model in a pool trace run (decision 105 as decision 125
//! extends it): what the run logs after each instant, computed from the caller's record, the pool,
//! its connections and the server's count of what it processed. The pool holds no QUIC, so no
//! stream holds an exchange's octets, QUIC's phase stays "none", and nothing falls back or learns.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const sim = @import("sim");
const world_module = @import("pool_trace_world.zig");

const limits = sim.constants.pool_trace;
const World = world_module.World;
const requests_max = limits.requests_max;
const slots_max = limits.slots_max;

pub const Stage = enum { unmade, waiting, queued, sent, ended, reported, cancelled };
pub const Outcome = enum { pending, response, refused, closed, failed };
pub const Phase = client.Phase;
/// An entry of `ConnectionPool.entries`, named through that field: the root exports no such type.
const Entry = std.meta.Elem(@FieldType(world_module.ConnectionPool, "entries"));

pub const State = struct {
    stage: [requests_max]Stage,
    /// The slot of the connection that carries each exchange, or null for none.
    carrier: [requests_max]?u32,
    outcome: [requests_max]Outcome,
    moved: [requests_max]u8,
    seen: [requests_max]bool,
    processed: [requests_max]u8,
    /// Whether the connection of a cancelled exchange still reads its response to drop it.
    drops: [requests_max]bool,
    /// Each TCP slot's, in order.
    phase: [slots_max]Phase,
    opens: [slots_max]u64,
    tried: [slots_max]bool,
    shut: bool,
};

/// What the run remembers of each exchange, which the pool forgets once the exchange is reported
/// or cancelled: the connection that carried it last, its id there, and the times it moved.
pub const Tracker = struct {
    carrier: [requests_max]?client.ConnectionHandle,
    carried_id: [requests_max]client.RequestId,
    moved: [requests_max]u8,

    pub fn init(tracker: *Tracker) void {
        tracker.carrier = @splat(null);
        tracker.carried_id = @splat(0);
        tracker.moved = @splat(0);
    }

    /// Notes where each exchange the pool holds is.
    pub fn update(tracker: *Tracker, world: *World) void {
        for (world.pool.entries) |entry| {
            if (entry.stage == .free) continue;
            const index = world.index_of(entry.response);
            tracker.moved[index] = entry.moves;
            switch (entry.stage) {
                .waiting => tracker.carrier[index] = null,
                .carried => {
                    tracker.carrier[index] = .{ .slot = entry.carrier, .generation = world.pool.tcp_links[entry.carrier].generation };
                    tracker.carried_id[index] = entry.carried_id;
                },
                .ended, .free => {},
            }
        }
    }
};

/// The model's state now.
pub fn compute(world: *World, tracker: *const Tracker) State {
    var state: State = undefined;
    for (0..requests_max) |index| compute_exchange(world, tracker, &state, index);
    for (0..slots_max) |slot| {
        const held = slot < world.plan.slots;
        state.phase[slot] = if (held) world.pool.phase(@intCast(slot)) else .none;
        state.opens[slot] = if (held) world.pool.tcp_links[slot].opens else 0;
        state.tried[slot] = held and world.pool.tcp_links[slot].tried;
    }
    state.shut = world.shut;
    return state;
}

/// Exchange `index`'s part of the model's state.
fn compute_exchange(world: *World, tracker: *const Tracker, state: *State, index: usize) void {
    const made = index < world.plan.requests;
    state.stage[index] = if (made) stage_of(world, index) else .unmade;
    state.carrier[index] = if (tracker.carrier[index]) |connection| connection.slot else null;
    state.outcome[index] = if (world.ids[index] == null) .pending else outcome_of(world.responses[index].result);
    state.moved[index] = tracker.moved[index];
    state.seen[index] = seen(world, tracker, index);
    state.processed[index] = world.processed[index];
    state.drops[index] = made and world.cancelled[index] and drops(world, tracker, index);
}

fn stage_of(world: *World, index: usize) Stage {
    if (world.cancelled[index]) return .cancelled;
    if (world.reported[index]) return .reported;
    if (world.ids[index] == null) return .unmade;
    const entry = entry_of(world, index) orelse unreachable;
    return switch (entry.stage) {
        .waiting => .waiting,
        // The pool reports an exchange it ended itself before the run logs again.
        .ended => .reported,
        .carried => carried_stage(world, entry),
        .free => unreachable,
    };
}

fn carried_stage(world: *World, entry: Entry) Stage {
    const held = world.pool.tcp[entry.carrier].slots.of_id(entry.carried_id) orelse unreachable;
    return switch (held.stage) {
        .queued => .queued,
        .sent, .dropping => .sent,
        .ended => .ended,
        .free => unreachable,
    };
}

fn entry_of(world: *World, index: usize) ?Entry {
    for (world.pool.entries) |entry| {
        if (entry.stage != .free and entry.response == &world.responses[index]) return entry;
    }
    return null;
}

fn outcome_of(outcome: client.Result) Outcome {
    return switch (outcome) {
        .pending => .pending,
        .response => .response,
        .refused => .refused,
        // The connection ended before the response was whole: the model's "closed". An idempotent
        // request that got none of its response moves after it (decision 124).
        .closed => .closed,
        // The server may have processed the request: the model's "failed".
        .reset, .malformed, .invalid, .too_large => .failed,
    };
}

/// Whether the connection that carried cancelled exchange `index` still reads its response, which
/// h11 drops: the slot holds the same connection, and the exchange's id there drops a response.
fn drops(world: *World, tracker: *const Tracker, index: usize) bool {
    const carrier = tracker.carrier[index] orelse return false;
    const link = &world.pool.tcp_links[carrier.slot];
    if (link.generation != carrier.generation or world.pool.phase(carrier.slot) == .closed) return false;
    const held = world.pool.tcp[carrier.slot].slots.of_id(tracker.carried_id[index]) orelse return false;
    return held.stage == .dropping;
}

/// Whether the server of the connection that carries exchange `index` processed it.
fn seen(world: *const World, tracker: *const Tracker, index: usize) bool {
    const carrier = tracker.carrier[index] orelse return false;
    const processed_on = world.processed_on[index] orelse return false;
    return carrier == processed_on;
}
