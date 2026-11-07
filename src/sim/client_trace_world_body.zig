//! The request and response bodies of the client trace run, split from `client_trace_world.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md). A POST sends
//! content cut from one source, and a GET sends none. A streamed exchange (decision 153) is a PUT,
//! which hands its content in pieces, the next one once the pool reports the one before taken.
//! The caller holds each piece of its response for the plan's delay, then releases it. What the
//! caller records gives the model's `taken` and `pieces`. A request with content carries a trailer
//! section after its last octet (decision 152).
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const sim = @import("sim");
const world_module = @import("client_trace_world.zig");
const quic_server = @import("client_trace_quic_server.zig");

const limits = sim.constants.client_trace;
const requests_max = limits.requests_max;
const ledger_module = @import("client_trace_ledger.zig");
const World = world_module.World;
/// The `body` event's payload, named through the event: the root exports no such type.
const Piece = @FieldType(client.Event, "body");

/// The octets every POST's content is cut from, which a streamed request's pieces stay in.
var content_source: [limits.content_len_max]u8 = @splat(content_octet);
const content_octet: u8 = 'c';

pub const Error = error{
    /// A piece of a streamed response differs from the content its server sent, or a response
    /// ended `response` before all of its content arrived.
    BodyDiffers,
    BodyShort,
};

/// What the caller did with each streamed exchange's pieces.
pub const Pieces = struct {
    /// Request pieces handed, and whether the pool takes no more of the content.
    handed: [requests_max]u32,
    stopped: [requests_max]bool,
    /// A piece of the request was taken: the model's `taken`.
    taken: [requests_max]bool,
    /// Pieces of the response the caller holds: the model's `pieces`. The instant it releases
    /// them, and the octets of the response it read.
    held: [requests_max]u8,
    release_at_ns: [requests_max]?u64,
    received: [requests_max]usize,
    /// The `body_taken` and `body` events the run heard.
    taken_events: u64,
    body_events: u64,

    pub fn init(pieces: *Pieces) void {
        pieces.handed = @splat(0);
        pieces.stopped = @splat(false);
        pieces.taken = @splat(false);
        pieces.held = @splat(0);
        pieces.release_at_ns = @splat(null);
        pieces.received = @splat(0);
        pieces.taken_events = 0;
        pieces.body_events = 0;
    }

    /// The caller has every piece of exchange `index` back: it cancelled the exchange, or heard
    /// its `finished` event. It hands and releases nothing more of it.
    pub fn returned(pieces: *Pieces, index: usize) void {
        pieces.stopped[index] = true;
        pieces.held[index] = 0;
        pieces.release_at_ns[index] = null;
    }

    /// The next instant a held response piece is released, or null.
    pub fn due_ns(pieces: *const Pieces) ?u64 {
        var at: ?u64 = null;
        for (pieces.release_at_ns) |release_at_ns| {
            const held = release_at_ns orelse continue;
            at = @min(at orelse held, held);
        }
        return at;
    }
};

/// Hands streamed exchange `index` its next request piece, the last one with `end`. A body the
/// pool takes no more of is stopped.
pub fn hand_next(world: *World, index: usize) world_module.Error!void {
    const pieces = &world.pieces;
    const count = world.plan.request_pieces[index];
    if (pieces.stopped[index] or pieces.handed[index] == count) return;
    const content = content_source[0..world.plan.content_len[index]];
    const from = content.len * pieces.handed[index] / count;
    const to = content.len * (pieces.handed[index] + 1) / count;
    const end: client.PieceEnd = if (pieces.handed[index] + 1 == count) .last else .more;
    world.pool.write_body(world.ids[index].?, content[from..to], end) catch |failure| switch (failure) {
        // RFC 9113 §8.1 and RFC 9114 §4.1: the exchange ended, or its server stopped the body.
        error.BodyStopped => {
            pieces.stopped[index] = true;
            return;
        },
        else => return failure,
    };
    pieces.handed[index] += 1;
    assert(pieces.handed[index] <= count);
}

/// A connection read the last request piece of exchange `id` no more: the next one goes.
pub fn on_taken(world: *World, id: client.RequestId) world_module.Error!void {
    const index = index_of_id(world, id);
    world.pieces.taken[index] = true;
    world.pieces.taken_events += 1;
    try hand_next(world, index);
}

/// A piece of exchange `piece.id`'s response is in its `Response.body`: the caller checks it
/// against the content its server sent, and holds it for the plan's delay.
pub fn on_body(world: *World, piece: Piece) Error!void {
    const index = index_of_id(world, piece.id);
    const pieces = &world.pieces;
    const response = &world.responses[index];
    assert(piece.len == response.body_len and piece.len > 0);
    const content = quic_server.contents[index];
    const from = pieces.received[index];
    if (from + piece.len > content.len) return error.BodyDiffers;
    if (!std.mem.eql(u8, content[from..][0..piece.len], response.body[0..piece.len])) return error.BodyDiffers;
    pieces.received[index] += piece.len;
    // A second piece before the release shows as the model's `pieces` of 2, which Safe forbids.
    pieces.held[index] += 1;
    pieces.release_at_ns[index] = world.now_ns + world.plan.release_delay_ns[index];
    pieces.body_events += 1;
}

/// Releases each held response piece whose instant came.
pub fn release_due(world: *World) void {
    const pieces = &world.pieces;
    for (0..world.plan.requests) |index| {
        const release_at_ns = pieces.release_at_ns[index] orelse continue;
        if (release_at_ns > world.now_ns) continue;
        world.pool.release_body(world.ids[index].?);
        pieces.held[index] = 0;
        pieces.release_at_ns[index] = null;
    }
}

/// Exchange `index` finished: the caller hands nothing more of it. A piece of the response it
/// still holds stays in the state, which Safe forbids (decision 153 ruling 7). A streamed
/// exchange that ended in a response read all of its content.
pub fn on_finished(world: *World, index: usize) Error!void {
    world.pieces.stopped[index] = true;
    if (!world.plan.streamed[index] or world.responses[index].result != .response) return;
    if (world.pieces.received[index] != quic_server.contents[index].len) return error.BodyShort;
}

/// The caller makes exchange `index`. A streamed one's content goes through `write_body`, its
/// first piece at once, and each piece of its response fills `response_piece_len` octets.
pub fn make(world: *World, index: usize) world_module.Error!void {
    const path = ledger_module.path_of(index, &world.paths[index]);
    const content = content_source[0..world.plan.content_len[index]];
    const streamed = world.plan.streamed[index];
    world.requests[index] = .{
        .method = if (streamed) "PUT" else if (world.plan.idempotent(index)) "GET" else "POST",
        .path = path,
        .body = if (streamed) "" else content,
        .streamed = .{ .request = streamed, .response = streamed },
        .trailers = if (world.plan.carries_trailers(index)) &ledger_module.request_trailers else &.{},
    };
    const response_len = if (streamed) limits.response_piece_len else world_module.body_len;
    world.responses[index] = .{ .body = world.bodies[index][0..response_len] };
    world.ids[index] = try world.pool.request(&world.requests[index], &world.responses[index]);
    if (streamed) try hand_next(world, index);
}

fn index_of_id(world: *const World, id: client.RequestId) usize {
    for (world.ids[0..world.plan.requests], 0..) |held, index| {
        if (held == id) return index;
    }
    unreachable;
}
