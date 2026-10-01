//! The endpoints of the TCP trace run (https://github.com/c4milo/colibri/issues/79): a
//! `client.Connection` and a `server.Connection` over h2 in cleartext, every octet each has handed
//! the other, and the server's caller, which answers each request as the plan says.
//!
//! The h2 trace drives two `h2.Connection` endpoints a frame at a time. Here each side is what a
//! caller holds: the client takes whole requests, and each side writes into its own output until
//! its caller hands that output to the socket with `send`. A delivery gives the reader every octet
//! in flight at once, as one read from a socket does, and the reader takes them in as many calls
//! as it needs.
//!
//! A cancel or a shutdown decides a RST_STREAM or a GOAWAY that h2 owes and writes later, at the
//! caller's next `send`. The model sends either frame in the step that decides it, so after each
//! the run has the connection write what it owes into its output at once, with `write_owed`, as
//! that `send` would first.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const client = @import("client");
const server = @import("server");
const sim = @import("sim");
const h2_trace_state = @import("h2_trace_state.zig");
const h2_trace_pair = @import("h2_trace_pair.zig");
const plan_module = @import("tcp_trace_plan.zig");

const Random = sim.Random;
const limits = sim.constants.tcp_trace;
const Plan = plan_module.Plan;
const Action = plan_module.Action;
const Target = plan_module.Target;
pub const RequestPhase = h2_trace_state.RequestPhase;
pub const HeadKind = h2_trace_state.HeadKind;

/// Every octet one side handed the other, in order. The reader has consumed the first `consumed`.
pub const Direction = struct {
    octets: [limits.stream_len_max]u8 = undefined,
    handed: usize = 0,
    consumed: usize = 0,
    /// The kind of each HEADERS frame the server wrote, in order, which its caller's calls decide.
    /// The client writes request heads alone.
    heads: [limits.headers_max]HeadKind = undefined,
    heads_written: usize = 0,

    pub fn handed_out(direction: *const Direction) []const u8 {
        return direction.octets[0..direction.handed];
    }

    pub fn unread(direction: *Direction) []u8 {
        return direction.octets[direction.consumed..direction.handed];
    }

    fn room(direction: *Direction) []u8 {
        return direction.octets[direction.handed..];
    }

    fn note_head(direction: *Direction, kind: HeadKind) void {
        assert(direction.heads_written < direction.heads.len);
        direction.heads[direction.heads_written] = kind;
        direction.heads_written += 1;
    }
};

/// What the server's caller holds of the exchange on one stream.
pub const Answer = struct {
    /// The request's identifier, once the server reported its head.
    id: ?server.Id = null,
    interims: u32 = 0,
    final_sent: bool = false,
    data: u32 = 0,
    ended: bool = false,
    cancelled: bool = false,
};

/// The trailer section each response that has one ends with, and the interim and final statuses
/// (RFC 9110 §15.2.4, §15.3.1).
const trailers = [_]server.Field{.{ .name = "grpc-status", .value = "0" }};
const interim_status: u16 = 103;
const final_status: u16 = 200;
/// The octets of every request's content and of every piece of a response's.
const content: [limits.request_content_len]u8 = @splat('x');
/// The octets of a response's content the client keeps: every piece a plan writes.
const body_len_max: usize = limits.content_max * limits.piece_len;

pub const World = struct {
    server_config: server.Config,
    client_config: client.Config,
    server: server.Connection,
    client: client.Connection,
    to_server: Direction,
    to_client: Direction,
    exchanges: [limits.streams_max]client.HttpExchange,
    bodies: [limits.streams_max][body_len_max]u8,
    /// The client's identifier of each request it made: stream index i is its i-th request.
    client_ids: [limits.streams_max]?client.Id,
    answers: [limits.streams_max]Answer,
    /// What the server read of each request, from the events it reported (RFC 9113 §8.1).
    request_read: [limits.streams_max]RequestPhase,
    requested: u32,
    shut_down: bool,
    /// The client's streams that were open when it first read a GOAWAY.
    open_at_goaway: ?u32,
    /// A receiver read a message out of §8.1's order, and an event two colibri endpoints never
    /// cause: a call that failed, or a request cancelled for another reason than its peer's reset.
    malformed: bool,
    broken: bool,
    /// Calls a connection refused, which two honest callers seldom make.
    refused: u32,
    tls_random: Random,
    /// The instant every call passes: the run needs no clock, and no deadline passes.
    now_ns: u64,

    /// Both endpoints over h2 in cleartext, with nothing written or read.
    pub fn init(world: *World, seed: u64) !void {
        world.now_ns = 0;
        world.server_config = .{ .cleartext = .h2 };
        world.client_config = .{ .authority = "a.example", .cleartext = .h2 };
        world.tls_random = Random.init(seed);
        const source = tls.Random.init(&world.tls_random, fill);
        try world.server.init(&world.server_config, source, 0, world.now_ns);
        try world.client.init(&world.client_config, source, 0, null);
        world.to_server = .{};
        world.to_client = .{};
        world.client_ids = @splat(null);
        world.answers = @splat(.{});
        world.request_read = @splat(.none);
        world.requested = 0;
        world.shut_down = false;
        world.open_at_goaway = null;
        world.malformed = false;
        world.broken = false;
        world.refused = 0;
    }

    /// Acts out one action. One the plan's constants leave out, or that finds nothing to do,
    /// changes nothing.
    pub fn act(world: *World, action: Action, plan: *const Plan) void {
        switch (action) {
            .request => world.request(plan),
            .client_cancel => |stream| if (plan.resets) world.client_cancel(stream),
            .server_interim => |stream| world.server_interim(stream, plan),
            .server_final => |target| world.server_final(target),
            .server_data => |target| world.server_data(target, plan),
            .server_trailers => |stream| world.server_trailers(stream),
            .server_cancel => |stream| if (plan.resets) world.server_cancel(stream),
            .server_shutdown => if (plan.goaways > 0) world.server_shutdown(),
            .client_send => world.to_server.handed += world.client.send(world.to_server.room(), world.now_ns),
            .server_send => world.to_client.handed += world.server.send(world.to_client.room(), world.now_ns),
            .deliver_to_server => world.deliver_to_server(plan),
            .deliver_to_client => world.deliver_to_client(),
        }
    }

    fn request(world: *World, plan: *const Plan) void {
        if (world.requested == plan.streams) return;
        const index = world.requested;
        const carries = plan.request_content[index];
        world.exchanges[index] = .{
            .method = if (carries) "POST" else "GET",
            .path = "/",
            .content = if (carries) &content else "",
            .body = &world.bodies[index],
        };
        // RFC 9113 §6.8: a client that read a GOAWAY makes no new request on the connection.
        world.client_ids[index] = world.client.request(&world.exchanges[index]) catch {
            world.refused += 1;
            return;
        };
        world.requested += 1;
    }

    fn client_cancel(world: *World, stream: u32) void {
        const id = world.client_ids[stream - 1] orelse return;
        if (world.exchanges[stream - 1].outcome != .pending) return;
        world.client.cancel(id);
        world.client_ids[stream - 1] = null;
        _ = world.client.write_owed(world.now_ns);
    }

    /// The answer the server's caller holds for `stream`, while it may still write.
    fn answer_of(world: *World, stream: u32) ?*Answer {
        const answer = &world.answers[stream - 1];
        if (answer.id == null or answer.cancelled or answer.ended) return null;
        return answer;
    }

    fn server_interim(world: *World, stream: u32, plan: *const Plan) void {
        const answer = world.answer_of(stream) orelse return;
        if (answer.final_sent or answer.interims == plan.interims) return;
        world.server.respond(answer.id.?, .{ .status = interim_status, .end = false }) catch {
            world.refused += 1;
            return;
        };
        world.to_client.note_head(.interim);
        answer.interims += 1;
    }

    fn server_final(world: *World, target: Target) void {
        const answer = world.answer_of(target.stream) orelse return;
        if (answer.final_sent) return;
        world.server.respond(answer.id.?, .{ .status = final_status, .end = target.end }) catch {
            world.refused += 1;
            return;
        };
        world.to_client.note_head(.head);
        answer.final_sent = true;
        answer.ended = target.end;
    }

    fn server_data(world: *World, target: Target, plan: *const Plan) void {
        const answer = world.answer_of(target.stream) orelse return;
        if (!answer.final_sent or answer.data == plan.content) return;
        const piece = content[0..limits.piece_len];
        const taken = world.server.write_body(answer.id.?, .{ .octets = piece, .end = target.end }) catch {
            world.refused += 1;
            return;
        };
        // One piece is one DATA frame, which the windows of an honest peer always take whole.
        if (taken != piece.len) {
            world.broken = true;
            return;
        }
        answer.data += 1;
        answer.ended = target.end;
    }

    fn server_trailers(world: *World, stream: u32) void {
        const answer = world.answer_of(stream) orelse return;
        if (!answer.final_sent) return;
        world.server.write_trailers(answer.id.?, &trailers) catch {
            world.refused += 1;
            return;
        };
        world.to_client.note_head(.trailers);
        answer.ended = true;
    }

    fn server_cancel(world: *World, stream: u32) void {
        const answer = world.answer_of(stream) orelse return;
        world.server.cancel(answer.id.?);
        answer.cancelled = true;
        _ = world.server.write_owed(world.now_ns);
    }

    fn server_shutdown(world: *World) void {
        if (world.shut_down) return;
        world.server.shutdown();
        world.shut_down = true;
        _ = world.server.write_owed(world.now_ns);
    }

    /// The server reads every octet the client handed out, and its caller notes each request.
    fn deliver_to_server(world: *World, plan: *const Plan) void {
        for (0..limits.receives_per_delivery_max) |_| {
            const received = world.server.receive(world.to_server.unread(), world.now_ns) catch {
                world.broken = true;
                return;
            };
            world.to_server.consumed += received.consumed;
            if (received.event) |event| world.on_server_event(event, plan);
            if (received.consumed == 0 and received.event == null) return;
        }
        world.broken = true;
    }

    fn on_server_event(world: *World, event: server.Event, plan: *const Plan) void {
        switch (event) {
            .request => |head| {
                const index = h2_trace_pair.index_of(@intCast(head.id));
                world.answers[index].id = head.id;
                world.request_read[index] = if (head.end) .ended else .head;
                // A caller may answer a request the moment it reads it, before the server reads
                // on, which is when e3126a9's server wrote a response ahead of its SETTINGS.
                if (plan.answer_at_once[index]) world.server_final(.{ .stream = @intCast(index + 1), .end = true });
            },
            .body => |body| if (body.end) {
                world.request_read[h2_trace_pair.index_of(@intCast(body.id))] = .ended;
            },
            .trailers => |section| world.request_read[h2_trace_pair.index_of(@intCast(section.id))] = .ended,
            .cancelled => |cancelled| {
                world.answers[h2_trace_pair.index_of(@intCast(cancelled.id))].cancelled = true;
                // RFC 9113 §8.1.1: colibri refuses a malformed request, which an honest client
                // never sends; a client's reset is the one cancel the run expects.
                if (cancelled.reason != .peer_reset) world.malformed = true;
            },
            .done => {},
        }
    }

    /// The client reads every octet the server handed out.
    fn deliver_to_client(world: *World) void {
        for (0..limits.receives_per_delivery_max) |_| {
            const received = world.client.receive(world.to_client.unread(), world.now_ns);
            world.to_client.consumed += received.consumed;
            if (received.consumed == 0 and received.event == null) break;
        } else world.broken = true;
        for (world.exchanges[0..world.requested]) |*exchange| {
            if (exchange.outcome == .malformed) world.malformed = true;
        }
        const h2_client = &world.client.session.h2;
        if (world.open_at_goaway == null and h2_client.streams.goaway_received_last_id != null) {
            world.open_at_goaway = world.client_streams_open();
        }
    }

    /// The client's streams that are not idle, its requests' streams in order.
    pub fn client_streams_open(world: *World) u32 {
        var open: u32 = 0;
        for (0..world.requested) |index| {
            const state, _ = h2_trace_state.stream_of(&world.client.session.h2, h2_trace_pair.id_of(@intCast(index + 1)));
            open += @intFromBool(state != .idle);
        }
        return open;
    }
};

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}
