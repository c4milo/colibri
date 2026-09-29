//! The state of spec/tla/client_exchanges's model in a client trace run (decision 105): what the
//! run logs after each instant, computed from the caller's record, the channel, its connections
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
const Transport = client.channel.Transport;
const exchanges_max = limits.exchanges_max;
/// QUIC and TCP.
const transports: usize = 2;

pub const Stage = enum { unmade, waiting, queued, sent, ended, reported, cancelled };
pub const Carrier = enum { none, quic, tcp };
pub const Outcome = enum { pending, response, refused, failed };
pub const Phase = client.channel.Phase;

pub const State = struct {
    stage: [exchanges_max]Stage,
    carrier: [exchanges_max]Carrier,
    holds: [exchanges_max]bool,
    outcome: [exchanges_max]Outcome,
    moved: [exchanges_max]u8,
    seen: [exchanges_max]bool,
    processed: [exchanges_max]u8,
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

/// What the run remembers of each exchange across instants, which the channel forgets once the
/// exchange is reported: the connection that carried it last, the times it moved, and its QUIC
/// stream.
pub const Tracker = struct {
    carrier: [exchanges_max]Carrier,
    generation: [exchanges_max]u64,
    moved: [exchanges_max]u8,
    stream_id: [exchanges_max]?u64,
    stream_generation: [exchanges_max]u64,

    pub fn init(tracker: *Tracker) void {
        tracker.carrier = @splat(.none);
        tracker.generation = @splat(0);
        tracker.moved = @splat(0);
        tracker.stream_id = @splat(null);
        tracker.stream_generation = @splat(0);
    }

    /// Notes where each exchange the channel holds is.
    pub fn update(tracker: *Tracker, world: *World) void {
        for (world.channel.entries) |entry| {
            if (entry.stage == .free) continue;
            const index = world.index_of(entry.exchange);
            tracker.moved[index] = entry.moves;
            switch (entry.stage) {
                .waiting => tracker.carrier[index] = .none,
                .carried => tracker.note_carried(world, index, entry),
                .ended, .free => {},
            }
        }
    }

    fn note_carried(tracker: *Tracker, world: *World, index: usize, entry: client.channel.Entry) void {
        tracker.carrier[index] = if (entry.carrier == .quic) .quic else .tcp;
        tracker.generation[index] = world.channel.links.get(entry.carrier).opens;
        if (entry.carrier != .quic) return;
        const slot = world.channel.quic.slots.of_id(entry.carried_id) orelse return;
        if (slot.stage == .queued) return;
        tracker.stream_id[index] = slot.stream_id;
        tracker.stream_generation[index] = world.channel.links.get(.quic).opens;
    }
};

/// The model's state now.
pub fn compute(world: *World, tracker: *const Tracker) State {
    var state: State = undefined;
    for (0..exchanges_max) |index| {
        state.stage[index] = stage_of(world, index);
        state.carrier[index] = tracker.carrier[index];
        state.holds[index] = holds(world, tracker, index);
        state.outcome[index] = if (world.ids[index] == null) .pending else outcome_of(world.exchanges[index].outcome);
        state.moved[index] = tracker.moved[index];
        state.seen[index] = seen(world, tracker, index);
        state.processed[index] = world.ledger.processed[index];
    }
    const channel = &world.channel;
    state.phase = .{ channel.phase(.quic), channel.phase(.tcp) };
    state.opens = .{ channel.links.get(.quic).opens, channel.links.get(.tcp).opens };
    state.tried = .{ channel.tried.get(.quic), channel.tried.get(.tcp) };
    state.fallback = channel.fallback;
    // The model learns only under its "learn" policy, and no run makes the channel forget.
    state.learned = world.plan.policy == .learn and channel.alternative() != null;
    state.shut = channel.shut;
    // The model forgets a QUIC connection's idleness once it closes, and the channel keeps the
    // connection's memory until the next one starts in it.
    state.stale = channel.links.get(.quic).state == .running and channel.quic.retired;
    return state;
}

fn stage_of(world: *World, index: usize) Stage {
    if (world.cancelled[index]) return .cancelled;
    if (world.reported[index]) return .reported;
    if (world.ids[index] == null) return .unmade;
    const entry = entry_of(world, index) orelse unreachable;
    return switch (entry.stage) {
        .waiting => .waiting,
        // The channel reports an exchange it ended itself before the run logs again.
        .ended => .reported,
        .carried => carried_stage(world, entry),
        .free => unreachable,
    };
}

fn carried_stage(world: *World, entry: client.channel.Entry) Stage {
    const slot = switch (entry.carrier) {
        .quic => world.channel.quic.slots.of_id(entry.carried_id),
        .tcp => world.channel.tcp.slots.of_id(entry.carried_id),
    } orelse unreachable;
    return switch (slot.stage) {
        .queued => .queued,
        .sent, .dropping => .sent,
        .ended => .ended,
        .free => unreachable,
    };
}

fn entry_of(world: *World, index: usize) ?client.channel.Entry {
    for (world.channel.entries) |entry| {
        if (entry.stage != .free and entry.exchange == &world.exchanges[index]) return entry;
    }
    return null;
}

fn outcome_of(outcome: client.Outcome) Outcome {
    return switch (outcome) {
        .pending => .pending,
        .response => .response,
        .refused => .refused,
        // The server may have processed the request: the model's "failed".
        .reset, .closed, .malformed, .invalid, .too_large => .failed,
    };
}

/// Whether exchange `index`'s QUIC stream may still read its octets: its connection is the one
/// running and active, and the stream's sending part may still send (RFC 9000 §3.1).
fn holds(world: *World, tracker: *const Tracker, index: usize) bool {
    const stream_id = tracker.stream_id[index] orelse return false;
    const link = world.channel.links.get(.quic);
    if (link.state != .running or tracker.stream_generation[index] != link.opens) return false;
    const transport = &world.channel.quic.transport;
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
