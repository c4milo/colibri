//! The endpoints of the deadline trace run (https://github.com/c4milo/colibri/issues/86): a colibri
//! server connection over h2 in cleartext, with decision 110's deadlines, a colibri h2 client, a
//! queue of octets each way, and an application that answers each request. The run keeps what
//! each side wrote and read in the model's terms, which `deadline_trace_state.zig` reads.
//!
//! Only whole frames move between the endpoints, as the model's frames do: an arrival hands colibri
//! the oldest one, and a hand-out gives the socket the oldest one colibri's output holds. colibri
//! writes what it owes, and takes content write_body offered, in the calls the model's colibri
//! steps stand for. After each action write_body is offered what the application offered and
//! colibri has not taken, until colibri takes no more, as the model's colibri takes content the
//! moment it can. Then colibri is called once more with the instant, so its clocks see what the
//! action changed.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const tls = @import("tls");
const server = @import("server");
const sim = @import("sim");
const plan_module = @import("deadline_trace_plan.zig");

const Random = sim.Random;
const limits = sim.constants.deadline_trace;
const Plan = plan_module.Plan;
const Action = plan_module.Action;

pub const Part = enum { none, head, ended };

/// One direction's octets, written at the back and read from the front.
pub const Queue = struct {
    octets: [limits.channel_len_max]u8 = undefined,
    len: usize = 0,
    /// Octets at the front that are the client's connection preface and its SETTINGS, which the
    /// model counts as one frame.
    preface_len: usize = 0,

    pub fn held(queue: *const Queue) []const u8 {
        return queue.octets[0..queue.len];
    }

    /// The room left under `capacity` octets.
    fn room(queue: *Queue, capacity: u32) []u8 {
        const end = @min(capacity, queue.octets.len);
        return queue.octets[queue.len..@max(queue.len, end)];
    }

    fn take(queue: *Queue, consumed: usize) void {
        assert(consumed <= queue.len);
        std.mem.copyForwards(u8, &queue.octets, queue.octets[consumed..queue.len]);
        queue.len -= consumed;
        queue.preface_len -= @min(queue.preface_len, consumed);
    }

    /// The octets of the oldest frame, the preface counting as one, or 0 when none is whole.
    pub fn first_len(queue: *const Queue) usize {
        if (queue.preface_len > 0) return queue.preface_len;
        return frame_len(queue.held());
    }
};

/// The octets of the whole frame at the front of `octets`, or 0 when it is not whole (RFC 9113
/// §4.1).
pub fn frame_len(octets: []const u8) usize {
    var reader = h2.core.Reader.init(octets);
    const header = h2.frame.read_header(&reader) catch return 0;
    const len = h2.constants.frame_header_len + header.length;
    return if (len <= octets.len) len else 0;
}

/// The request each stream carries, its pseudo-header fields written without indexing so every
/// request's HEADERS is the same length (RFC 7541 §6.2.2).
const request: h2.connection.Request_ = .{ .method = "POST", .scheme = "http", .path = "/", .authority = "example.test" };
/// RFC 9110 §15.3.1: 200 (OK).
const ok_status: u16 = 200;
/// The octets every body is made of.
const content: [limits.body_len_max]u8 = @splat('x');

comptime {
    // One offer can write a DATA frame of one octet into every part of colibri's output.
    assert(limits.writes_per_offer_max * (h2.constants.frame_header_len + 1) >= server.constants.output_len);
}

pub const World = struct {
    server_config: server.Config,
    server: server.Connection,
    client: h2.Connection,
    to_server: Queue,
    to_client: Queue,
    tls_random: Random,
    now_ns: u64,
    /// What colibri read of each request and wrote of each response, what the application offered
    /// write_body, and what the client sent and read, in the model's terms. Index 0 is stream 1.
    req_read: [limits.streams_max]Part,
    resp: [limits.streams_max]Part,
    resp_written: [limits.streams_max]u32,
    produced: [limits.streams_max]u32,
    cli_req: [limits.streams_max]Part,
    cli_sent: [limits.streams_max]u32,
    cli_resp: [limits.streams_max]Part,
    opened: u32,
    /// The payload octets of a request's HEADERS and of a response's, once one is written.
    request_head_len: ?u32,
    response_head_len: ?u32,
    /// Octets of the client's preface with its SETTINGS, and payload octets of colibri's SETTINGS.
    preface_len: u32,
    settings_len: u32,
    /// The frames that arrived at colibri, the preface counting as one, and those it handed out:
    /// with what each queue holds, they count every frame each side has written and read.
    arrived: u32,
    handed_out: u32,
    /// An event two honest endpoints never cause: a cancelled request, or a failed connection.
    broken: bool,

    /// Both endpoints with their prefaces written and nothing read.
    pub fn init(world: *World, seed: u64) !void {
        world.now_ns = limits.start_ns;
        // Decision 117: h2 alone, which the server speaks from the start.
        world.server_config = .{ .versions = .{ .h11 = false } };
        world.tls_random = Random.init(seed);
        const source = tls.Random.init(&world.tls_random, fill);
        try world.server.init(&world.server_config, source, 0, world.now_ns);
        world.client.init(.client);
        world.to_server = .{};
        world.to_client = .{};
        world.req_read = @splat(.none);
        world.resp = @splat(.none);
        world.resp_written = @splat(0);
        world.produced = @splat(0);
        world.cli_req = @splat(.none);
        world.cli_sent = @splat(0);
        world.cli_resp = @splat(.none);
        world.opened = 0;
        world.request_head_len = null;
        world.response_head_len = null;
        world.arrived = 0;
        world.handed_out = 0;
        world.broken = false;
        // RFC 9113 §3.4: the client's preface, then its SETTINGS, and the server's SETTINGS, which
        // colibri writes into its output at its first call.
        world.to_server.len = world.client.write_pending(world.to_server.room(limits.channel_len_max), world.now_ns);
        world.to_server.preface_len = world.to_server.len;
        world.preface_len = @intCast(world.to_server.len);
        var none: [0]u8 = .{};
        assert(world.server.send(&none, world.now_ns) == 0);
        const settings_frame_len = frame_len(world.server.output[0..world.server.output_len]);
        assert(settings_frame_len == world.server.output_len);
        world.settings_len = @intCast(settings_frame_len - h2.constants.frame_header_len);
    }

    /// Acts out one action, then lets colibri take what the windows held back and see the instant.
    pub fn act(world: *World, action: Action, plan: *const Plan) void {
        world.now_ns += limits.action_ns;
        switch (action) {
            .open => world.open(plan),
            .upload => |stream| world.upload(stream, plan),
            .settle => world.settle(plan),
            .read => world.read(),
            .arrive => world.arrive(),
            .hand_out => world.hand_out(plan),
            .respond => |stream| world.respond(stream, plan),
            .produce => |stream| world.produce(stream, plan),
        }
        world.offer_all(plan);
        world.server.on_instant(world.now_ns);
    }

    /// Whether the client owes the server a frame it has not written (RFC 9113 §6.5.3, §6.9).
    pub fn client_owes(world: *const World) bool {
        return world.client.has_pending();
    }

    fn settle(world: *World, plan: *const Plan) void {
        world.to_server.len += world.client.write_pending(world.to_server.room(plan.channel_len), world.now_ns);
    }

    fn open(world: *World, plan: *const Plan) void {
        world.settle(plan);
        if (world.client_owes() or world.opened == plan.streams) return;
        const index = world.opened;
        // The model's honest client opens a stream once it has read every response before it,
        // unless it pipelines.
        if (!plan.pipelining and !world.earlier_read(index)) return;
        const end = plan.request_body == 0;
        const sent = world.client.write_request(world.to_server.room(plan.channel_len), request, &.{}, &.{}, end) catch return;
        assert(sent.stream_id == id_of(index));
        world.note_head_len(&world.request_head_len, sent.written);
        world.to_server.len += sent.written;
        world.cli_req[index] = if (end) .ended else .head;
        world.opened += 1;
    }

    fn earlier_read(world: *const World, index: u32) bool {
        for (world.cli_resp[0..index]) |part| {
            if (part != .ended) return false;
        }
        return true;
    }

    fn upload(world: *World, stream: u32, plan: *const Plan) void {
        world.settle(plan);
        const index = stream - 1;
        if (world.client_owes() or world.cli_req[index] != .head) return;
        const payload = content[world.cli_sent[index]..plan.request_body];
        const sent = world.client.write_data(world.to_server.room(plan.channel_len), id_of(index), payload, true) catch return;
        if (sent.written == 0) return;
        world.to_server.len += sent.written;
        world.cli_sent[index] += @intCast(sent.consumed);
        if (world.cli_sent[index] == plan.request_body) world.cli_req[index] = .ended;
    }

    /// The client reads the oldest frame toward it.
    fn read(world: *World) void {
        const len = world.to_client.first_len();
        if (len == 0) return;
        var taken: usize = 0;
        for (0..limits.receives_per_frame_max) |_| {
            if (taken == len) break;
            const received = world.client.receive(world.to_client.octets[taken..len], world.now_ns) catch {
                world.broken = true;
                return;
            };
            if (received.event) |event| world.on_client_event(event);
            if (received.consumed == 0) break;
            taken += received.consumed;
        }
        assert(taken == len);
        world.to_client.take(len);
    }

    fn on_client_event(world: *World, event: h2.Event) void {
        switch (event) {
            .response => |arrived| world.cli_resp[index_of(arrived.stream_id)] = if (arrived.end_stream) .ended else .head,
            .data => |data| if (data.end_stream) {
                world.cli_resp[index_of(data.stream_id)] = .ended;
            },
            .settings_acknowledged, .settings_applied => {},
            .request, .trailers, .stream_reset, .stream_refused, .goaway, .ping_acknowledged, .alt_svc => world.broken = true,
        }
    }

    /// The oldest frame toward colibri arrives, and colibri reads it.
    fn arrive(world: *World) void {
        const len = world.to_server.first_len();
        if (len == 0) return;
        var taken: usize = 0;
        for (0..limits.receives_per_frame_max) |_| {
            if (taken == len) break;
            const received = world.server.receive(world.to_server.octets[taken..len], world.now_ns) catch {
                world.broken = true;
                return;
            };
            if (received.event) |event| world.on_server_event(event);
            if (received.consumed == 0 and received.event == null) break;
            taken += received.consumed;
        }
        // colibri reads a frame whole once it has room for what it owes, which a hand-out makes.
        if (taken < len) {
            assert(taken == 0);
            return;
        }
        world.to_server.take(len);
        world.arrived += 1;
    }

    fn on_server_event(world: *World, event: server.Event) void {
        switch (event) {
            .request => |arrived| world.req_read[index_of(@intCast(arrived.id))] = if (arrived.end) .ended else .head,
            .body => |body| if (body.end) {
                world.req_read[index_of(@intCast(body.id))] = .ended;
            },
            .done => {},
            .trailers, .cancelled => world.broken = true,
        }
    }

    /// colibri's caller hands the socket the oldest frame colibri's output holds, once the socket
    /// has room for it. colibri writes what it owes into its output first.
    fn hand_out(world: *World, plan: *const Plan) void {
        const output = world.server.output[0..world.server.output_len];
        const len = frame_len(output);
        const room = world.to_client.room(plan.channel_len);
        const given = if (len > 0 and len <= room.len) len else 0;
        const written = world.server.send(room[0..given], world.now_ns);
        assert(written == given);
        world.to_client.len += written;
        world.handed_out += @intFromBool(written > 0);
    }

    fn respond(world: *World, stream: u32, plan: *const Plan) void {
        const index = stream - 1;
        if (world.req_read[index] == .none or world.resp[index] != .none) return;
        const before = world.server.output_len;
        const end = plan.response_body == 0;
        world.server.respond(id_of(index), .{ .status = ok_status, .end = end }) catch return;
        world.note_head_len(&world.response_head_len, world.server.output_len - before);
        world.resp[index] = if (end) .ended else .head;
    }

    fn produce(world: *World, stream: u32, plan: *const Plan) void {
        const index = stream - 1;
        if (world.resp[index] != .head or world.produced[index] == plan.response_body) return;
        world.produced[index] += @min(plan.produce_step, plan.response_body - world.produced[index]);
    }

    /// Offers write_body what each response's application offered and colibri has not taken, again
    /// while it takes some: one call writes one DATA frame.
    fn offer_all(world: *World, plan: *const Plan) void {
        for (0..plan.streams) |index| {
            for (0..limits.writes_per_offer_max) |_| {
                if (!world.offer(@intCast(index), plan)) break;
            }
        }
    }

    /// Offers write_body the rest of one response's content, and returns whether colibri took any.
    fn offer(world: *World, index: u32, plan: *const Plan) bool {
        if (world.resp[index] != .head or world.resp_written[index] == world.produced[index]) return false;
        const offered = content[world.resp_written[index]..world.produced[index]];
        const end = world.produced[index] == plan.response_body;
        const taken = world.server.write_body(id_of(index), .{ .octets = offered, .end = end }) catch 0;
        world.resp_written[index] += @intCast(taken);
        if (end and taken == offered.len) world.resp[index] = .ended;
        return taken > 0;
    }

    /// Notes a HEADERS frame's payload octets, which every request, or every response, repeats.
    fn note_head_len(world: *World, head_len: *?u32, written: usize) void {
        const payload_len: u32 = @intCast(written - h2.constants.frame_header_len);
        if (head_len.*) |known| {
            if (known != payload_len) world.broken = true;
        } else {
            head_len.* = payload_len;
        }
    }
};

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}

/// RFC 9113 §5.1.1: the client's streams are the odd identifiers, the model's stream index i being
/// 2i + 1.
pub fn id_of(index: u32) u32 {
    return h2.constants.stream_id_client_first + h2.constants.stream_id_step * index;
}

/// The index of the stream `id` names into the per-stream arrays: stream 1 at 0.
pub fn index_of(id: u32) usize {
    assert(id % h2.constants.stream_id_step == h2.constants.stream_id_client_first);
    return (id - h2.constants.stream_id_client_first) / h2.constants.stream_id_step;
}
