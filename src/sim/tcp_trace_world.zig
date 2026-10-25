//! The endpoints of the TCP trace run (https://github.com/c4milo/colibri/issues/79): a
//! `client.ConnectionPool` with TCP alone (design §8 step 21c) and a `server.Endpoint` that holds one
//! connection (step 21b.6), over h2, in cleartext or over TLS, every octet each has handed the
//! other, and the server's caller, which answers each request as the plan says.
//!
//! The h2 trace drives two `h2.Connection` endpoints a frame at a time. Here each side is what a
//! caller holds: the client takes whole requests, and each side writes into its own output until
//! its caller hands that output to the socket with `send`. A delivery gives the reader every octet
//! in flight at once, as one read from a socket does, and the reader takes them in as many calls
//! as it needs.
//!
//! A cancel or a shutdown decides a RST_STREAM or a GOAWAY that h2 owes and writes later, at the
//! caller's next `send`. The model sends either frame in the step that decides it, so after each
//! the run calls `send` with no room, the server's through the endpoint's `send_stream`: the
//! connection writes what it owes into its output at once and hands out nothing. The client's call
//! also writes the requests that wait, as any `send` of its does.
//!
//! Over TLS a send seals the protocol's octets into records, so the run calls `send` twice. The
//! first, with no room, writes what the connection owes and seals nothing; the run copies the
//! plaintext the connection then holds, and the second call seals it (`tcp_trace_direction.zig`).
//!
//! The endpoint reports nothing of a request once its response is `done` (decision 119), so
//! `tcp_trace_state.zig` reads the end of such a request from h2's stream table. After its
//! shutdown the endpoint closes the connection once no request is open, and reads nothing more.
//!
//! The run reads the pool only in `deliver_to_client` and at the first request: a read may end
//! a draining connection and queue h2's GOAWAY, which a read elsewhere moves to another action.
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
    id: ?server.RequestId = null,
    interims: u32 = 0,
    final_sent: bool = false,
    data: u32 = 0,
    ended: bool = false,
    cancelled: bool = false,
};

/// The trailer section each response that has one ends with, and the interim and final statuses
/// (RFC 9110 §15.2.4, §15.3.1).
const trailers = [_]server.Header{.{ .name = "grpc-status", .value = "0" }};
const interim_status: u16 = 103;
const final_status: u16 = 200;
/// The octets of every request's content and of every piece of a response's.
const content: [limits.request_content_len]u8 = @splat('x');
/// The octets of a response's content the client keeps: every piece a plan writes.
const body_len_max: usize = limits.content_max * limits.piece_len;

/// The server: one connection, in cleartext or over TLS, and no QUIC.
const Endpoint = server.EndpointOf(.{ .tcp_connections = 1, .quic_connections = 0 });
/// The connection a TCP slot holds, whose fields the run and its state read.
pub const Connection = std.meta.Elem(@FieldType(Endpoint, "tcp"));

pub const World = struct {
    endpoint_config: server.Config,
    client_config: client.Config,
    tls: bool,
    endpoint: Endpoint,
    /// The one connection the endpoint holds.
    accepted: server.ConnectionHandle,
    addresses: [1]client.Address,
    pool: client.ConnectionPool,
    pool_memory: [client.ConnectionPool.memory_bytes(.{})]u8 align(client.ConnectionPool.memory_alignment),
    /// The connection the pool's `open` named (decision 125).
    connection: client.ConnectionHandle,
    /// Whether the first request started the pool's connection, whose memory the run reads
    /// from then on, and whether the pool said to close its socket, which then reads nothing.
    started: bool,
    socket_closed: bool,
    to_server: Direction,
    to_client: Direction,
    /// Each exchange's request and response, by stream index (decision 124).
    requests: [limits.streams_max]client.Request,
    responses: [limits.streams_max]client.Response,
    bodies: [limits.streams_max][body_len_max]u8,
    /// The client's identifier of each request it made: stream index i is its i-th request.
    client_ids: [limits.streams_max]?client.RequestId,
    answers: [limits.streams_max]Answer,
    /// What the server read of each request, from the events it reported (RFC 9113 §8.1).
    request_read: [limits.streams_max]RequestPhase,
    /// The requests whose response the endpoint reported `done`.
    done: [limits.streams_max]bool,
    requested: u32,
    shut_down: bool,
    /// The client's streams that were open when it first read a GOAWAY.
    open_at_goaway: ?u32,
    /// A receiver read a message out of §8.1's order, or a request was cancelled for another
    /// reason than its peer's reset or its caller's own cancel. And an event two colibri endpoints
    /// never cause: a failed connection, a `close` before the shutdown, or an end with a reason or
    /// a failure.
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
        if (over_tls) world.configure_tls() else {
            // Decision 117: h2 alone, which each side speaks from the start.
            world.endpoint_config = .{ .protocols = .{ .h11 = false } };
            world.client_config = .{ .authority = identity.authority, .protocols = .{ .h11 = false } };
        }
        world.tls_random = Random.init(seed);
        const source = tls.Random.init(&world.tls_random, fill);
        // Every handshake judges the chain at the identity's instant, so no run reads a clock. The
        // server's connection starts here, and the client's at the first request, which every plan
        // makes before any other action, so each draws what it drew before.
        try world.endpoint.init(&world.endpoint_config, source, identity.now_seconds, world.now_ns);
        world.accepted = world.endpoint.accept(.{ .tls = over_tls }, world.now_ns) orelse return error.StartRefused;
        const octets: [limits.ipv4_len]u8 = @splat(limits.address_octet);
        world.addresses = .{client.Address.of(&octets, 0)};
        const port = if (over_tls) limits.https_port else limits.http_port;
        // No receive pool, so the pool offers TCP alone.
        try world.pool.init(&world.pool_memory, &world.client_config, .{ .addresses = &world.addresses, .port = port }, null);
        world.started = false;
        world.socket_closed = false;
        world.connection = .{ .slot = 0, .generation = 0 };
        world.to_server = .{};
        world.to_client = .{};
        world.client_ids = @splat(null);
        world.answers = @splat(.{});
        world.request_read = @splat(.none);
        world.done = @splat(false);
        world.requested = 0;
        world.shut_down = false;
        world.open_at_goaway = null;
        world.malformed = false;
        world.broken = false;
        world.refused = 0;
    }

    /// The server presents the test identity of `src/testing/testdata/`, and the client trusts its
    /// root and names the host it covers. RFC 9113 §3.2: both sides offer h2 alone, which ALPN
    /// selects, and each names it from `versions`.
    fn configure_tls(world: *World) void {
        world.endpoint_config = .{
            .tls = .{
                .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
                .cookie_key = &identity.cookie_key,
                .ticket_key = null,
                .cpu = identity.cpu,
            },
            // Decision 117: h2 alone, the one protocol the server's ALPN list then names.
            .protocols = .{ .h11 = false },
        };
        world.client_config = .{
            .authority = identity.authority,
            .protocols = .{ .h11 = false },
            .tls = .{
                .trust = .{ .web_pki = .{ .anchors = &identity.anchors, .server_name = identity.authority } },
                .cpu = identity.cpu,
            },
        };
    }

    /// The client's h2 connection, or null before the first request started it, and while none
    /// serves it: before its TLS handshake completes.
    pub fn client_h2(world: *World) ?*h2.Connection {
        if (!world.started) return null;
        return direction_module.h2_of(&world.pool.tcp[0].session);
    }

    /// The protocol's octets the client's connection wrote that its caller has not handed out:
    /// what `output` holds after the records of the handshake. None before it started.
    pub fn client_pending(world: *const World) []const u8 {
        if (!world.started) return "";
        const connection = &world.pool.tcp[0];
        return connection.output[connection.records_len..connection.output_len];
    }

    /// The connection the endpoint holds, for the fields a program has no call for.
    pub fn server_connection(world: *World) *Connection {
        return &world.endpoint.tcp[world.accepted.slot];
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
        // Every plan requests before any other action, and the first request starts the
        // connection.
        assert(world.started);
        _ = world.pool.send_stream(world.connection, &.{}, world.now_ns);
        const staged = world.client_pending();
        world.to_server.stage(staged);
        const written = world.pool.send_stream(world.connection, world.to_server.room(), world.now_ns);
        world.to_server.note_send(staged.len, written, world.client_pending());
    }

    /// The server's caller hands the socket what the server wrote, as `client_send` does.
    fn server_send(world: *World) void {
        const connection = world.server_connection();
        _ = world.endpoint.send_stream(world.accepted, &.{}, world.now_ns);
        const staged = connection.output[connection.records_len..connection.output_len];
        world.to_client.stage(staged);
        const written = world.endpoint.send_stream(world.accepted, world.to_client.room(), world.now_ns);
        world.to_client.note_send(staged.len, written, connection.output[connection.records_len..connection.output_len]);
    }

    fn request(world: *World, plan: *const Plan) void {
        if (world.requested == plan.streams) return;
        if (world.takes_no_request()) {
            world.refused += 1;
            return;
        }
        const index = world.requested;
        const carries = plan.request_content[index];
        world.requests[index] = .{
            .method = if (carries) "POST" else "GET",
            .path = "/",
            .body = if (carries) &content else "",
        };
        world.responses[index] = .{ .body = &world.bodies[index] };
        world.client_ids[index] = world.pool.request(&world.requests[index], &world.responses[index]) catch {
            world.refused += 1;
            return;
        };
        world.requested += 1;
        if (!world.started) world.start_client();
    }

    /// Whether the client's connection takes no new request. RFC 9113 §6.8: a client that read a
    /// GOAWAY makes no new request on the connection. A pool would hold the request for another
    /// connection, which the run never opens, so the run refuses it itself.
    fn takes_no_request(world: *const World) bool {
        return switch (world.pool.phase(0)) {
            .none, .handshake, .open => false,
            .draining, .failed, .closed => true,
        };
    }

    /// Starts the pool's connection at the first request: the pool asks for a socket, and the
    /// run starts the connection on it. In cleartext the connection owes `connected` from its
    /// start, and the pool hands it the request as it reports it. Over TLS the read that
    /// completes the handshake reports it, in `deliver_to_client`.
    fn start_client(world: *World) void {
        const asked = world.pool.receive(.none, world.now_ns).event orelse unreachable;
        assert(asked.open.transport == .tcp);
        world.connection = asked.open.connection;
        world.pool.start_tcp(world.connection, tls.Random.init(&world.tls_random, fill), identity.now_seconds, null) catch {
            world.broken = true;
            return;
        };
        world.started = true;
        // Over TLS the pool asks for the ClientHello's `send` (decision 125), which the run's own
        // sends write.
        const reported = world.pool.receive(.none, world.now_ns).event;
        assert(if (world.tls) reported.? == .send else reported.? == .connected);
    }

    fn client_cancel(world: *World, stream: u32) void {
        const id = world.client_ids[stream - 1] orelse return;
        if (world.responses[stream - 1].result != .pending or world.moved(id)) return;
        world.pool.cancel(id);
        world.client_ids[stream - 1] = null;
        _ = world.pool.send_stream(world.connection, &.{}, world.now_ns);
    }

    /// Whether exchange `id` moved off the connection: a GOAWAY refused it unprocessed, and it
    /// waits at the pool for another connection, which the run never opens (RFC 9113 §8.7).
    fn moved(world: *const World, id: client.RequestId) bool {
        for (world.pool.entries) |entry| {
            if (entry.stage != .free and entry.id == id) return entry.moves > 0;
        }
        return false;
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
        world.endpoint.respond(answer.id.?, .{ .status = interim_status, .end = false }) catch {
            world.refused += 1;
            return;
        };
        world.to_client.note_head(.interim);
        answer.interims += 1;
    }

    fn server_final(world: *World, target: Target) void {
        const answer = world.answer_of(target.stream) orelse return;
        if (answer.final_sent) return;
        world.endpoint.respond(answer.id.?, .{ .status = final_status, .end = target.end }) catch {
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
        const taken = world.endpoint.write_body(answer.id.?, .{ .bytes = piece, .end = target.end }) catch {
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
        world.endpoint.write_trailers(answer.id.?, &trailers) catch {
            world.refused += 1;
            return;
        };
        world.to_client.note_head(.trailers);
        answer.ended = true;
    }

    fn server_cancel(world: *World, stream: u32) void {
        const answer = world.answer_of(stream) orelse return;
        world.endpoint.cancel(answer.id.?);
        answer.cancelled = true;
        _ = world.endpoint.send_stream(world.accepted, &.{}, world.now_ns);
    }

    fn server_shutdown(world: *World) void {
        if (world.shut_down) return;
        world.endpoint.shutdown(world.now_ns);
        world.shut_down = true;
        _ = world.endpoint.send_stream(world.accepted, &.{}, world.now_ns);
    }

    /// The server reads every octet the client handed out, and its caller notes each request.
    fn deliver_to_server(world: *World, plan: *const Plan) void {
        for (0..limits.receives_per_delivery_max) |_| {
            const received = world.endpoint.receive(.{ .stream = .{ .connection = world.accepted, .bytes = world.to_server.unread() } }, world.now_ns);
            if (world.endpoint.failed[world.accepted.slot]) {
                world.broken = true;
                return;
            }
            world.to_server.consumed += received.consumed;
            if (received.event) |event| world.on_server_event(event, plan);
            if (received.consumed == 0 and received.event == null) return;
        }
        world.broken = true;
    }

    fn on_server_event(world: *World, event: server.Event, plan: *const Plan) void {
        switch (event) {
            .request => |head| {
                const index = h2_trace_pair.index_of(@intCast(head.id.number));
                world.answers[index].id = head.id;
                world.request_read[index] = if (head.end) .ended else .head;
                // A caller may answer a request the moment it reads it, before the server reads
                // on, which is when e3126a9's server wrote a response ahead of its SETTINGS.
                if (plan.answer_at_once[index]) world.server_final(.{ .stream = @intCast(index + 1), .end = true });
            },
            .body => |body| if (body.end) {
                world.request_read[h2_trace_pair.index_of(@intCast(body.id.number))] = .ended;
            },
            .trailers => |section| world.request_read[h2_trace_pair.index_of(@intCast(section.id.number))] = .ended,
            .cancelled => |cancelled| {
                world.answers[h2_trace_pair.index_of(@intCast(cancelled.id.number))].cancelled = true;
                // RFC 9113 §8.1.1: colibri refuses a malformed request, which an honest client
                // never sends; a client's reset and the caller's own cancel are the cancels the
                // run expects.
                if (cancelled.reason != .peer_reset and cancelled.reason != .program) world.malformed = true;
            },
            .done => |done| world.done[h2_trace_pair.index_of(@intCast(done.id.number))] = true,
            // The run hands octets out and writes each response in actions of its own.
            .send, .writable => {},
            // The endpoint closes the connection once its caller shut it down and no request is
            // open, and not before.
            .close => world.broken = world.broken or !world.shut_down,
            .ended => |over| world.broken = world.broken or over.failed or over.reason != null,
            .closed => {},
        }
    }

    /// The client reads every octet the server handed out.
    fn deliver_to_client(world: *World) void {
        world.read_client();
        for (world.responses[0..world.requested]) |*response| {
            if (response.result == .malformed) world.malformed = true;
        }
        const h2_client = world.client_h2() orelse return;
        if (world.open_at_goaway == null and h2_client.streams.goaway_received_last_id != null) {
            world.open_at_goaway = world.client_streams_open();
        }
    }

    /// Passes the pool what the socket holds, and does what each event asks. It stops after two
    /// calls in a row that consume nothing and report nothing: a call that read the connection's
    /// `draining`, which the pool keeps, reports nothing, and the call after it reads all the
    /// connection owes.
    fn read_client(world: *World) void {
        var quiet: u32 = 0;
        for (0..limits.receives_per_delivery_max) |_| {
            // A closed socket reads nothing more, and the octets in flight stay there.
            const input: client.Input = if (world.socket_closed) .none else .{ .stream = .{ .connection = world.connection, .bytes = world.to_client.unread() } };
            const received = world.pool.receive(input, world.now_ns);
            world.to_client.consumed += received.consumed;
            if (received.event) |reported| world.on_client_event(reported);
            quiet = if (received.consumed == 0 and received.event == null) quiet + 1 else 0;
            if (quiet == limits.quiet_receives) return;
        }
        world.broken = true;
    }

    /// What an event of the pool's means to the run. A second `open` gets no socket, so the
    /// exchanges that wait for it end refused, and a `close` closes the one socket. The run reads
    /// the outcomes, and ignores the rest.
    fn on_client_event(world: *World, reported: client.Event) void {
        switch (reported) {
            .open => |asked| {
                assert(asked.transport == .tcp);
                world.pool.transport_closed(asked.connection);
            },
            .close => world.socket_closed = true,
            // The run sends at its own actions, the model's.
            .send, .connected, .ticket, .finished => {},
            // The run never shuts the pool down.
            .closed => unreachable,
        }
    }

    /// The client's streams that are not idle, its requests' streams in order.
    pub fn client_streams_open(world: *World) u32 {
        const h2_client = world.client_h2() orelse return 0;
        var open: u32 = 0;
        for (0..world.requested) |index| {
            const state, _ = h2_trace_state.stream_of(h2_client, h2_trace_pair.id_of(@intCast(index + 1)));
            open += @intFromBool(state != .idle);
        }
        return open;
    }
};

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}
