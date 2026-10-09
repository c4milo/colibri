//! The endpoints of the h3 deadline trace run (design §8 step 20d): a server `Endpoint` under the
//! run's deadlines, the h3 deadline run's peer as an honest client, one queue of datagrams each
//! way that loses and reorders nothing, and an application that answers each request a unit at a
//! time.
//!
//! The client sends each unit of a request in a datagram of its own: its head in `head_units`
//! pieces, and its content in `content_units`, the last with the stream's end. colibri reads what
//! a datagram brings and writes what it owes in the action that delivers it, as the model's
//! colibri takes its own steps at once. Time moves only while no datagram is in flight, to the
//! instant the endpoint or the client is next due at, which `deadline_ns` and the client's QUIC
//! timer name: the run adds no timer of its own.
//!
//! The world keeps what the model needs once colibri forgets it: whether the server reported each
//! request's end, since h3 forgets a request stream in the call that reads its end, whether
//! colibri reset its response, which a closed stream forgets, and what the client learned.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const server = @import("server");
const sim = @import("sim");
const identity = @import("client_trace_identity.zig");
const deadline_plan = @import("h3_deadline_plan.zig");
const peer_module = @import("h3_deadline_peer.zig");
const plan_module = @import("h3_deadline_trace_plan.zig");

const Random = sim.Random;
const limits = sim.constants.h3_deadline_trace;
const run_limits = sim.constants.h3_deadline;
const Plan = plan_module.Plan;
const Action = plan_module.Action;
const Peer = peer_module.Peer;

pub const Error = peer_module.Error || error{
    /// chapulin refused the server's identity, or the endpoint the run's limits.
    ServerRefused,
    /// The handshake did not complete, or a queue or a call's bound was full: a harness defect.
    Stalled,
};

pub const Phase = enum { unseen, head, content, ended, abandoned };
pub const Outcome = enum { none, response, timeout, rejected, cancelled };

/// The actions `allowed` lists at most: a unit and a write for each request, and one open, two
/// deliveries, the shutdown and a wait.
const actions_per_request: usize = 2;
const actions_besides_requests: usize = 5;
pub const allowed_max: usize = actions_per_request * limits.requests_max + actions_besides_requests;

const Endpoint = server.EndpointOf(.{ .tcp_connections = 0, .quic_connections = 1 });
const datagram_len = limits.datagram_len;
/// Where the client sends from, which the endpoint reads off each datagram (decision 72).
const ipv4_len: usize = 4;
const client_octet: u8 = 0xc1;
const client_octets: [ipv4_len]u8 = @splat(client_octet);
const client_port: u16 = 50_000;
/// Client-initiated bidirectional stream identifiers step by 4 (RFC 9000 §2.1).
pub const request_stream_step: u64 = 4;
/// RFC 9110 §15.3.1: 200 (OK), and §15.5.9: 408 (Request Timeout).
const ok_status: u16 = 200;
const timeout_status: u16 = 408;
/// Rounds of deliveries the handshake takes at most.
const handshake_rounds_max: usize = 16;

/// One direction's datagrams, oldest first.
const Queue = struct {
    datagrams: [limits.queue_len_max][datagram_len]u8,
    lens: [limits.queue_len_max]usize,
    first: usize,
    len: usize,

    fn push(queue: *Queue, octets: []const u8) Error!void {
        if (queue.len == queue.datagrams.len) return error.Stalled;
        const slot = (queue.first + queue.len) % queue.datagrams.len;
        @memcpy(queue.datagrams[slot][0..octets.len], octets);
        queue.lens[slot] = octets.len;
        queue.len += 1;
    }

    /// Copies the oldest datagram into `output` and drops it from the queue.
    fn pop(queue: *Queue, output: []u8) []u8 {
        assert(queue.len > 0);
        const len = queue.lens[queue.first];
        @memcpy(output[0..len], queue.datagrams[queue.first][0..len]);
        queue.first = (queue.first + 1) % queue.datagrams.len;
        queue.len -= 1;
        return output[0..len];
    }
};

pub const World = struct {
    endpoint_config: server.EndpointConfig,
    endpoint: Endpoint,
    /// The endpoint's one QUIC connection, read as a program does not, and the handle naming it.
    served: ?*server.QuicConnection,
    handle: ?server.ConnectionHandle,
    peer: Peer,
    peer_plan: deadline_plan.Plan,
    to_server: Queue,
    to_client: Queue,
    datagram: [datagram_len]u8,
    now_ns: u64,
    server_random: Random,
    peer_random: Random,
    /// The units of each request the client sent, and the octets of its HEADERS frame.
    sent_units: [limits.requests_max]u32,
    headers_len: [limits.requests_max]usize,
    /// The application: the requests it heard of, those whose content it heard end, those the
    /// server cancelled, and the units of its answer to each that it wrote.
    processed: [limits.requests_max]bool,
    content_ended: [limits.requests_max]bool,
    cancelled: [limits.requests_max]bool,
    written: [limits.requests_max]u32,
    /// Whether colibri reset its side of each request's stream.
    aborted: [limits.requests_max]bool,
    outcome: [limits.requests_max]Outcome,
    /// What an honest exchange never does: the server failed the connection, refused an answer,
    /// or the client could not open a request within the server's limits.
    broken: bool,
    response_content: [limits.response_unit_len]u8,

    /// Starts both endpoints at the run's first instant and completes the handshake, with no
    /// request yet.
    pub fn init(world: *World, seed: u64) Error!void {
        world.endpoint_config = .{
            .tls = .{
                .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
                .cookie_key = &identity.cookie_key,
                .ticket_key = null,
                .cpu = identity.cpu,
            },
            .idle_timeout_ms = run_limits.quic_idle_timeout_ms,
            .deadlines = deadlines(),
        };
        world.server_random = Random.init(seed);
        world.peer_random = Random.init(~seed);
        world.now_ns = limits.start_ns;
        world.endpoint.init(&world.endpoint_config, tls.Random.init(&world.server_random, fill), identity.now_seconds, world.now_ns) catch return error.ServerRefused;
        world.served = null;
        world.handle = null;
        world.peer_plan = honest_plan();
        try world.peer.start(&world.peer_plan, tls.Random.init(&world.peer_random, fill), world.now_ns);
        world.to_server.first = 0;
        world.to_server.len = 0;
        world.to_client.first = 0;
        world.to_client.len = 0;
        world.sent_units = @splat(0);
        world.headers_len = @splat(0);
        world.processed = @splat(false);
        world.content_ended = @splat(false);
        world.cancelled = @splat(false);
        world.written = @splat(0);
        world.aborted = @splat(false);
        world.outcome = @splat(.none);
        world.broken = false;
        world.response_content = @splat('r');
        try world.handshake();
    }

    /// Delivers both ways until nothing moves, which completes the handshake and starts h3 at both
    /// endpoints.
    fn handshake(world: *World) Error!void {
        for (0..handshake_rounds_max) |_| {
            try world.client_sends();
            if (world.to_server.len == 0 and world.to_client.len == 0) break;
            try world.deliver_all();
        } else return error.Stalled;
        const held = world.served orelse return error.Stalled;
        if (!world.peer.h3_started or !held.started) return error.Stalled;
    }

    /// Delivers every datagram toward the server, then every one toward the client.
    fn deliver_all(world: *World) Error!void {
        for (0..limits.queue_len_max) |_| {
            if (world.to_server.len == 0) break;
            try world.deliver_to_server();
        }
        for (0..limits.queue_len_max) |_| {
            if (world.to_client.len == 0) break;
            try world.deliver_to_client();
        }
    }

    /// The actions the world allows now, written into `list`.
    pub fn allowed(world: *World, plan: *const Plan, list: *[allowed_max]Action) []const Action {
        var len: usize = 0;
        if (world.can_open(plan)) push(list, &len, .open);
        for (0..plan.requests) |index| {
            if (world.can_send(plan, index)) push(list, &len, .{ .unit = @intCast(index) });
            if (world.can_write(plan, index)) push(list, &len, .{ .write = @intCast(index) });
        }
        if (world.to_server.len > 0) push(list, &len, .to_server);
        if (world.to_client.len > 0) push(list, &len, .to_client);
        if (world.server_runs() and !world.connection().shutting_down) push(list, &len, .shutdown);
        if (world.can_wait()) push(list, &len, .wait);
        return list[0..len];
    }

    /// Takes `action`, then notes what colibri may forget of each request.
    pub fn act(world: *World, plan: *const Plan, action: Action) Error!void {
        switch (action) {
            .open => try world.open(plan),
            .unit => |index| try world.send_unit(plan, index),
            .to_server => try world.deliver_to_server(),
            .to_client => try world.deliver_to_client(),
            .write => |index| try world.write(plan, index),
            .shutdown => {
                world.endpoint.shutdown(world.now_ns);
                try world.server_step(.none);
            },
            .wait => try world.wait(),
        }
        world.note(plan);
    }

    pub fn connection(world: *const World) *server.QuicConnection {
        return world.served.?;
    }

    /// Whether colibri's connection runs: neither stopped nor closed, nor closing at QUIC.
    pub fn server_runs(world: *const World) bool {
        const held = world.connection();
        if (held.stopped or held.closed) return false;
        return held.transport.termination.state == .active;
    }

    fn client_runs(world: *World) bool {
        return world.peer.close == null and world.peer.active();
    }

    fn can_open(world: *World, plan: *const Plan) bool {
        if (!world.client_runs() or world.peer.goaway_ms != null) return false;
        return world.peer.fetches_len < plan.requests;
    }

    fn can_send(world: *World, plan: *const Plan, index: usize) bool {
        if (!world.client_runs() or index >= world.peer.fetches_len) return false;
        if (world.sent_units[index] == plan.client_units[index]) return false;
        // RFC 9000 §3.5: a client asked to stop resets its sending part, which takes no more.
        return switch (world.peer.connection.streams.lookup(.{ .value = stream_of(index) })) {
            .live => |stream| stream.sending.state != .reset_sent and stream.sending.state != .reset_recvd,
            else => false,
        };
    }

    fn can_write(world: *World, plan: *const Plan, index: usize) bool {
        if (!world.server_runs() or !world.processed[index] or world.cancelled[index]) return false;
        return world.written[index] < plan.answer_units[index] and !world.server_reset(index);
    }

    fn can_wait(world: *World) bool {
        if (!world.client_runs() or world.to_server.len > 0 or world.to_client.len > 0) return false;
        const at_ns = world.next_instant() orelse return false;
        return at_ns <= world.now_ns + limits.wait_seconds_max * server.constants.nanoseconds_per_second;
    }

    /// The instant the endpoint or the client is next due at: a deadline or a timer of colibri's,
    /// or a timer of the client's QUIC.
    fn next_instant(world: *World) ?u64 {
        const server_ns = world.endpoint.deadline_ns();
        const client_ns = world.peer.timer_ns();
        if (server_ns) |at| return @min(at, client_ns orelse at);
        return client_ns;
    }

    fn open(world: *World, plan: *const Plan) Error!void {
        const index = world.peer.fetches_len;
        const content_len = plan.content_units * limits.content_unit_len;
        const method = if (content_len > 0) "POST" else "GET";
        const fetch = try world.peer.stage(method, content_len, world.now_ns) orelse {
            world.broken = true;
            return;
        };
        assert(fetch.id == stream_of(index));
        world.headers_len[index] = headers_len_of(fetch.prefix[0..fetch.prefix_len]) orelse return error.Stalled;
        world.sent_units[index] = 0;
        try world.send_unit(plan, index);
    }

    /// The client supplies its stream up to the end of the next unit, and sends it.
    fn send_unit(world: *World, plan: *const Plan, index: usize) Error!void {
        const fetch = &world.peer.fetches[index];
        const unit = world.sent_units[index] + 1;
        assert(unit <= plan.units());
        const headers_len = world.headers_len[index];
        if (unit <= plan.head_units) {
            const last = unit == plan.head_units;
            const end = if (last) headers_len else headers_len * unit / plan.head_units;
            world.peer.supply(fetch, end, last and plan.content_units == 0);
        } else {
            const content = unit - plan.head_units;
            world.peer.supply(fetch, fetch.prefix_len + content * limits.content_unit_len, content == plan.content_units);
        }
        world.sent_units[index] = unit;
        try world.client_sends();
    }

    fn write(world: *World, plan: *const Plan, index: usize) Error!void {
        const id: server.Id = .{ .connection = world.handle.?, .number = stream_of(index) };
        const unit = world.written[index] + 1;
        const last = unit == plan.response_units;
        if (unit == 1) {
            world.endpoint.respond(id, .{ .status = ok_status, .end = last }) catch {
                world.broken = true;
                return;
            };
        } else {
            const taken = world.endpoint.write_body(id, .{ .octets = &world.response_content, .end = last }) catch 0;
            if (taken != world.response_content.len) {
                world.broken = true;
                return;
            }
        }
        world.written[index] = unit;
        try world.server_step(.none);
    }

    /// Time moves on to the next instant either side is due at, and each fires what is due.
    fn wait(world: *World) Error!void {
        const at_ns = world.next_instant() orelse return;
        world.now_ns = @max(world.now_ns, at_ns);
        world.endpoint.on_instant(world.now_ns);
        world.peer.on_instant(world.now_ns);
        try world.server_step(.none);
        try world.client_sends();
    }

    fn deliver_to_server(world: *World) Error!void {
        const octets = world.to_server.pop(&world.datagram);
        try world.server_step(.{ .datagram = .{ .octets = octets, .from = .of(&client_octets, client_port) } });
        if (world.served == null and world.endpoint.live[0]) world.served = &world.endpoint.quic[0];
    }

    fn deliver_to_client(world: *World) Error!void {
        const octets = world.to_client.pop(&world.datagram);
        const now_ms = world.now_ns / run_limits.ns_per_ms;
        try world.peer.receive(octets, world.now_ns, now_ms);
        _ = try world.peer.read(&world.peer_plan, world.now_ns, now_ms);
        try world.client_sends();
    }

    /// colibri takes `input`, reports every event it owes to the application, and sends.
    fn server_step(world: *World, input: server.Input) Error!void {
        var rest = input;
        for (0..limits.events_per_call_max) |_| {
            const reported = world.endpoint.receive(rest, world.now_ns).event;
            rest = .none;
            world.note_event(reported orelse break);
        } else return error.Stalled;
        if (world.endpoint.failed[0]) world.broken = true; // colibri failed it; `ended` comes later
        for (0..limits.sends_per_call_max) |_| {
            const sent = world.endpoint.send_datagram(&world.datagram, world.now_ns) orelse return;
            try world.to_client.push(sent.octets);
        }
        return error.Stalled;
    }

    fn client_sends(world: *World) Error!void {
        for (0..limits.sends_per_call_max) |_| {
            const len = try world.peer.send(&world.datagram, world.now_ns) orelse return;
            try world.to_server.push(world.datagram[0..len]);
        }
        return error.Stalled;
    }

    fn note_event(world: *World, reported: server.Event) void {
        switch (reported) {
            .request => |request| if (index_of(request.id.number)) |index| {
                world.handle = request.id.connection;
                world.processed[index] = true;
                world.content_ended[index] = request.end;
            },
            .body => |body| if (index_of(body.id.number)) |index| {
                if (body.end) world.content_ended[index] = true;
            },
            .trailers => |trailers| if (index_of(trailers.id.number)) |index| {
                world.content_ended[index] = true;
            },
            .cancelled => |cancelled| if (index_of(cancelled.id.number)) |index| {
                world.cancelled[index] = true;
            },
            .ended => |over| world.broken = world.broken or over.failed,
            else => {},
        }
    }

    /// Whether colibri's side of request `index`'s stream was reset.
    fn server_reset(world: *const World, index: usize) bool {
        if (world.aborted[index]) return true;
        return switch (world.connection().transport.streams.lookup(.{ .value = stream_of(index) })) {
            .live => |stream| stream.sending.state == .reset_sent or stream.sending.state == .reset_recvd,
            else => false,
        };
    }

    /// Keeps what colibri may forget of each request the client opened.
    fn note(world: *World, plan: *const Plan) void {
        for (0..@min(world.peer.fetches_len, plan.requests)) |index| {
            world.aborted[index] = world.server_reset(index);
            if (world.outcome[index] == .none) world.outcome[index] = world.learned(index);
        }
    }

    /// Request `index`'s phase at colibri. h3 holds a slot for each stream it reads, and forgets
    /// it in the call that reads the request's end, or once it abandoned the stream. It keeps no
    /// slot for a stream it refused at or above the GOAWAY's identifier (RFC 9114 §5.2).
    pub fn phase_of(world: *const World, index: usize) Phase {
        const held = world.connection();
        if (stream_of(index) / request_stream_step >= held.h3.requests.next_index) return .unseen;
        if (held.h3.requests.find(stream_of(index))) |request| return switch (request.phase) {
            .head => .head,
            .content, .trailers_read => .content,
            .abandoned => .abandoned,
        };
        return if (world.content_ended[index]) .ended else .abandoned;
    }

    /// What the client learned of request `index`: a reset and its code, a 408, or a whole
    /// response.
    fn learned(world: *World, index: usize) Outcome {
        const fetch = &world.peer.fetches[index];
        if (fetch.reset) |code| {
            if (code == h3.constants.error_request_rejected) return .rejected;
            if (code == h3.constants.error_request_cancelled) return .cancelled;
            world.broken = true;
            return .none;
        }
        const status = fetch.status orelse return .none;
        if (status == timeout_status) return .timeout;
        if (status == ok_status and fetch.ended_ms != null) return .response;
        return .none;
    }
};

fn push(list: *[allowed_max]Action, len: *usize, action: Action) void {
    assert(len.* < list.len);
    list[len.*] = action;
    len.* += 1;
}

pub fn stream_of(index: usize) u64 {
    return @as(u64, index) * request_stream_step;
}

fn index_of(number: u64) ?usize {
    if (number % request_stream_step != 0) return null;
    const index = number / request_stream_step;
    return if (index < limits.requests_max) @intCast(index) else null;
}

/// The octets of the HEADERS frame at the front of `prefix` (RFC 9114 §7.1): its type, its length
/// and its payload.
fn headers_len_of(prefix: []const u8) ?usize {
    var reader = quic.core.Reader.init(prefix);
    _ = quic.wire.varint.decode(&reader) catch return null;
    const length = quic.wire.varint.decode(&reader) catch return null;
    const len = prefix.len - reader.remaining_len() + length.value;
    return if (len <= prefix.len) @intCast(len) else null;
}

/// The run's limits: decision 110's first-request deadline, shorter idle, head, body and drain
/// deadlines, and no body rate.
fn deadlines() server.Deadlines {
    const second = server.constants.nanoseconds_per_second;
    return .{
        .first_request_ns = limits.first_request_seconds * second,
        .idle_ns = limits.idle_seconds * second,
        .head_ns = limits.head_seconds * second,
        .body_rate_min = null,
        .body_ns = limits.body_seconds * second,
        .drain_ns = limits.drain_seconds * second,
    };
}

/// The h3 deadline run's plan for a peer that reads at once and grants wide windows.
fn honest_plan() deadline_plan.Plan {
    return .{
        .peer = .honest,
        .base_ms = 0,
        .deadlines = .{},
        .exchanges_len = 0,
        .gap_ms = 0,
        .piece_len = 0,
        .flood_batch_len = 0,
        .upload_len = @splat(0),
        .read_gap_ms = 0,
        .read_len = 0,
        .link_rate = 0,
        .answer_delay_ms = @splat(0),
        .answer_gap_ms = @splat(0),
        .content_len = @splat(0),
    };
}

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}
