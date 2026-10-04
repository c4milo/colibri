//! The endpoints of the TCP trace run (https://github.com/c4milo/colibri/issues/79): a
//! `client.Connection` and a `server.Connection` over h2, in cleartext or over TLS, every octet
//! each has handed the other, and the server's caller, which answers each request as the plan says.
//!
//! The h2 trace drives two `h2.Connection` endpoints a frame at a time. Here each side is what a
//! caller holds: the client takes whole requests, and each side writes into its own output until
//! its caller hands that output to the socket with `send`. A delivery gives the reader every octet
//! in flight at once, as one read from a socket does, and the reader takes them in as many calls
//! as it needs.
//!
//! A cancel or a shutdown decides a RST_STREAM or a GOAWAY that h2 owes and writes later, at the
//! caller's next `send`. The model sends either frame in the step that decides it, so after each
//! the run calls `send` with no room: the connection writes what it owes into its output at once
//! and hands out nothing. The client's call also writes the requests that wait, as any `send` of
//! its does.
//!
//! Over TLS a send seals the protocol's octets into records, so the run calls `send` twice. The
//! first, with no room, writes what the connection owes and seals nothing; the run copies the
//! plaintext the connection then holds, and the second call seals it (`tcp_trace_direction.zig`).
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const h2 = @import("h2");
const client = @import("client");
const server = @import("server");
const sim = @import("sim");
const h2_trace_state = @import("h2_trace_state.zig");
const h2_trace_pair = @import("h2_trace_pair.zig");
const plan_module = @import("tcp_trace_plan.zig");
const direction_module = @import("tcp_trace_direction.zig");
const identity = @import("client_trace_identity.zig");

const Random = sim.Random;
const limits = sim.constants.tcp_trace;
const Plan = plan_module.Plan;
const Action = plan_module.Action;
const Target = plan_module.Target;
pub const Direction = direction_module.Direction;
pub const RequestPhase = h2_trace_state.RequestPhase;
pub const HeadKind = h2_trace_state.HeadKind;

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
/// RFC 9113 §3.2: over TLS both sides offer h2 alone, which ALPN selects.
const alpn_h2 = [_][]const u8{"h2"};

pub const World = struct {
    server_tls: tls.record.ServerConfig,
    client_tls: tls.record.ClientConfig,
    server_config: server.Config,
    client_config: client.Config,
    tls: bool,
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

    /// Both endpoints over h2, in cleartext or over TLS, with nothing written or read.
    pub fn init(world: *World, seed: u64, over_tls: bool) !void {
        world.now_ns = 0;
        world.tls = over_tls;
        if (over_tls) try world.configure_tls() else {
            world.server_config = .{ .cleartext = .h2 };
            world.client_config = .{ .authority = identity.authority, .cleartext = .h2 };
        }
        world.tls_random = Random.init(seed);
        const source = tls.Random.init(&world.tls_random, fill);
        // Every handshake judges the chain at the identity's instant, so no run reads a clock.
        try world.server.init(&world.server_config, source, identity.now_seconds, world.now_ns);
        try world.client.init(&world.client_config, source, identity.now_seconds, null);
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

    /// The server presents the test identity of `src/testing/testdata/`, and the client trusts its
    /// root and names the host it covers.
    fn configure_tls(world: *World) !void {
        try world.server_tls.init(.{
            .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
            .cookie_key = &identity.cookie_key,
            .ticket_key = null,
            .alpn = &alpn_h2,
            .cpu = identity.cpu,
        });
        try world.client_tls.init(.{
            .trust = .{ .web_pki = .{ .anchors = &identity.anchors, .server_name = identity.authority } },
            .alpn = &alpn_h2,
            .cpu = identity.cpu,
        });
        world.server_config = .{ .tls = &world.server_tls };
        world.client_config = .{ .authority = identity.authority, .tls = &world.client_tls };
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
            .client_send => world.client_send(),
            .server_send => world.server_send(),
            .deliver_to_server => world.deliver_to_server(plan),
            .deliver_to_client => world.deliver_to_client(),
        }
    }

    /// The client's caller hands the socket what the client wrote, the protocol's octets sealed
    /// over TLS.
    fn client_send(world: *World) void {
        const connection = &world.client;
        _ = connection.send(&.{}, world.now_ns);
        const staged = connection.output[connection.records_len..connection.output_len];
        world.to_server.stage(staged);
        const written = connection.send(world.to_server.room(), world.now_ns);
        world.to_server.note_send(staged.len, written, connection.output[connection.records_len..connection.output_len]);
    }

    /// The server's caller hands the socket what the server wrote, as `client_send` does.
    fn server_send(world: *World) void {
        const connection = &world.server;
        _ = connection.send(&.{}, world.now_ns);
        const staged = connection.output[connection.records_len..connection.output_len];
        world.to_client.stage(staged);
        const written = connection.send(world.to_client.room(), world.now_ns);
        world.to_client.note_send(staged.len, written, connection.output[connection.records_len..connection.output_len]);
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
        _ = world.client.send(&.{}, world.now_ns);
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
        _ = world.server.send(&.{}, world.now_ns);
    }

    fn server_shutdown(world: *World) void {
        if (world.shut_down) return;
        world.server.shutdown();
        world.shut_down = true;
        _ = world.server.send(&.{}, world.now_ns);
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
        const h2_client = h2_of(&world.client.session) orelse return;
        if (world.open_at_goaway == null and h2_client.streams.goaway_received_last_id != null) {
            world.open_at_goaway = world.client_streams_open();
        }
    }

    /// The client's streams that are not idle, its requests' streams in order.
    pub fn client_streams_open(world: *World) u32 {
        const h2_client = h2_of(&world.client.session) orelse return 0;
        var open: u32 = 0;
        for (0..world.requested) |index| {
            const state, _ = h2_trace_state.stream_of(h2_client, h2_trace_pair.id_of(@intCast(index + 1)));
            open += @intFromBool(state != .idle);
        }
        return open;
    }
};

/// The h2 connection a session holds, or null while none serves it: before its TLS handshake
/// completes.
pub fn h2_of(session: anytype) ?*h2.Connection {
    return switch (session.*) {
        .h2 => |*connection| connection,
        .none, .h11 => null,
    };
}

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}
