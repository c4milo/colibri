//! The state of spec/tla/client_exchanges's model in a client trace run (decision 105): what the
//! run logs after each instant, computed from the caller's record, the pool, its connections
//! and the servers' ledger.
//!
//! Whether a QUIC stream holds an exchange's octets is read from the stream itself, not from the
//! client's own flag: the stream holds them while its connection is active and its sending part
//! may still send (RFC 9000 §3.1). A client that freed an exchange whose stream still sends shows
//! as a state the model cannot reach.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const quic = @import("quic");
const sim = @import("sim");
const world_module = @import("client_trace_world.zig");
const ledger_module = @import("client_trace_ledger.zig");

const limits = sim.constants.client_trace;
const World = world_module.World;
const Transport = client.Transport;
const requests_max = limits.requests_max;
/// QUIC and TCP.
const transports: usize = 2;

pub const Stage = enum { unmade, waiting, queued, sent, ended, reported, cancelled };
pub const Carrier = enum { none, quic, tcp };
pub const Outcome = enum { pending, response, refused, closed, failed };
pub const Phase = client.Phase;
/// An entry of `Pool.entries`, named through that field: the root exports no such type.
const Entry = std.meta.Elem(@FieldType(client.Pool, "entries"));

pub const State = struct {
    stage: [requests_max]Stage,
    carrier: [requests_max]Carrier,
    holds: [requests_max]bool,
    outcome: [requests_max]Outcome,
    moved: [requests_max]u8,
    seen: [requests_max]bool,
    processed: [requests_max]u8,
    /// Each transport's, QUIC first.
    phase: [transports]Phase,
    opens: [transports]u64,
    tried: [transports]bool,
    fallback: bool,
    learned: bool,
    shut: bool,
    /// The running QUIC connection sat idle until near its idle timeout, and retired (RFC 9114
    /// §5.1).
    stale: bool,
};

/// What the run remembers of each exchange across instants, which the pool forgets once the
/// exchange is reported: the connection that carried it last, the times it moved, whether the
/// pool sent it again after a close (decision 124), and its QUIC stream.
pub const Tracker = struct {
    carrier: [requests_max]Carrier,
    generation: [requests_max]u64,
    moved: [requests_max]u8,
    resent: [requests_max]bool,
    stream_id: [requests_max]?u64,
    stream_generation: [requests_max]u64,

    pub fn init(tracker: *Tracker) void {
        tracker.carrier = @splat(.none);
        tracker.generation = @splat(0);
        tracker.moved = @splat(0);
        tracker.resent = @splat(false);
        tracker.stream_id = @splat(null);
        tracker.stream_generation = @splat(0);
    }

    /// Notes where each exchange the pool holds is.
    pub fn update(tracker: *Tracker, world: *World) void {
        for (world.pool.entries) |entry| {
            if (entry.stage == .free) continue;
            const index = world.index_of(entry.response);
            tracker.moved[index] = entry.moves;
            tracker.resent[index] = entry.resent;
            switch (entry.stage) {
                .waiting => tracker.carrier[index] = .none,
                .carried => tracker.note_carried(world, index, entry),
                .ended, .free => {},
            }
        }
    }

    fn note_carried(tracker: *Tracker, world: *World, index: usize, entry: Entry) void {
        const on_quic = entry.carrier == quic_slot(world);
        tracker.carrier[index] = if (on_quic) .quic else .tcp;
        tracker.generation[index] = if (on_quic) world.pool.quic_link.opens else world.pool.tcp_links[entry.carrier].opens;
        if (!on_quic) return;
        const slot = world.pool.quic.slots.of_id(entry.carried_id) orelse return;
        if (slot.stage == .queued) return;
        tracker.stream_id[index] = slot.stream_id;
        tracker.stream_generation[index] = world.pool.quic_link.opens;
    }
};

/// The model's state now.
pub fn compute(world: *World, tracker: *const Tracker) State {
    var state: State = undefined;
    for (0..requests_max) |index| {
        state.stage[index] = stage_of(world, index);
        state.carrier[index] = tracker.carrier[index];
        state.holds[index] = holds(world, tracker, index);
        state.outcome[index] = if (world.ids[index] == null) .pending else outcome_of(world.responses[index].outcome);
        state.moved[index] = tracker.moved[index];
        state.seen[index] = seen(world, tracker, index);
        state.processed[index] = world.ledger.processed[index];
    }
    const pool = &world.pool;
    // Decision 125: the run's pool holds one TCP slot, the model's "tcp".
    state.phase = .{ pool.phase(quic_slot(world)), pool.phase(0) };
    state.opens = .{ pool.quic_link.opens, pool.tcp_links[0].opens };
    state.tried = .{ pool.quic_link.tried, pool.tcp_links[0].tried };
    state.fallback = pool.fallback;
    // The model learns only under its "learn" policy, and no run makes the pool forget.
    state.learned = world.plan.policy == .learn and pool.alternative() != null;
    state.shut = pool.shut;
    // The model forgets a QUIC connection's idleness once it closes, and the pool keeps the
    // connection's memory until the next one starts in it.
    state.stale = pool.quic_link.state == .running and pool.quic.retired;
    return state;
}

/// The pool's QUIC slot: the one after its TCP slots (decision 125).
fn quic_slot(world: *const World) u32 {
    return @intCast(world.pool.tcp.len);
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
    const found = if (entry.carrier == quic_slot(world))
        world.pool.quic.slots.of_id(entry.carried_id)
    else
        world.pool.tcp[entry.carrier].slots.of_id(entry.carried_id);
    const slot = found orelse unreachable;
    return switch (slot.stage) {
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

fn outcome_of(outcome: client.Outcome) Outcome {
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

/// Whether exchange `index`'s QUIC stream may still read its octets: its connection is the one
/// running and active, and the stream's sending part may still send (RFC 9000 §3.1).
fn holds(world: *World, tracker: *const Tracker, index: usize) bool {
    const stream_id = tracker.stream_id[index] orelse return false;
    const link = world.pool.quic_link;
    if (link.state != .running or tracker.stream_generation[index] != link.opens) return false;
    const transport = &world.pool.quic.transport;
    // RFC 9000 §10.2: a closing or draining connection sends no stream data.
    if (transport.termination.state != .active) return false;
    const stream = switch (transport.streams.lookup(.{ .value = stream_id })) {
        .live => |live| live,
        else => return false,
    };
    return switch (stream.sending.state) {
        .ready, .send, .data_sent => true,
        .data_recvd, .reset_sent, .reset_recvd => false,
    };
}

/// Whether the server of the connection that carries exchange `index` processed it.
fn seen(world: *const World, tracker: *const Tracker, index: usize) bool {
    const transport: ledger_module.Transport = switch (tracker.carrier[index]) {
        .none => return false,
        .quic => .quic,
        .tcp => .tcp,
    };
    return world.ledger.processed_on(index, .{ .transport = transport, .generation = tracker.generation[index] });
}
