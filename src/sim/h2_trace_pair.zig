//! The two endpoints of the h2 trace run (https://github.com/c4milo/colibri/issues/75): a colibri
//! client and a colibri server, a queue of octets in each direction, and what the run saw each
//! connection take, in `spec/tla/h2_connection`'s terms.
//!
//! An action makes one write call, or delivers every whole frame one direction holds. After each,
//! the endpoint writes every frame it owes, such as a RST_STREAM or a GOAWAY, into its queue at
//! once, as the model's actions send a frame in the step that decides it. A call the connection
//! refuses changes nothing, and the run carries on. A call it takes moves the model's written
//! state, so a call it should have refused shows as a state the model cannot reach.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const sim = @import("sim");
const h2_trace_plan = @import("h2_trace_plan.zig");

const limits = sim.constants.h2_trace;
const Connection = h2.Connection;
const Action = h2_trace_plan.Action;
const Target = h2_trace_plan.Target;

/// How far a request is written or read: nothing, its head, or ended by END_STREAM.
pub const RequestPhase = enum { none, head, ended };
/// How far a response is written or read: nothing, interim heads, the final head, or ended.
pub const ResponsePhase = enum { none, interim, final, ended };
/// The kinds of HEADERS frame the model tells apart.
pub const HeadKind = enum { head, interim, trailers };

/// One direction's octets, written at the back and read from the front.
pub const Queue = struct {
    octets: [limits.queue_len_max]u8 = undefined,
    len: usize = 0,
    /// The kind of every HEADERS frame written into the queue, in order, and how many of them the
    /// reader has taken. The ones in flight are the last ones written.
    heads: [limits.headers_max]HeadKind = undefined,
    heads_written: usize = 0,
    /// Octets of the writer's connection preface still at the queue's front (RFC 9113 §3.4): the
    /// client's 24 octets and its SETTINGS frame, or the server's SETTINGS frame, which the model
    /// carries as one frame.
    preface_left: usize = 0,

    pub fn held(queue: *const Queue) []const u8 {
        return queue.octets[0..queue.len];
    }

    fn room(queue: *Queue) []u8 {
        return queue.octets[queue.len..];
    }

    fn take(queue: *Queue, consumed: usize) void {
        assert(consumed <= queue.len);
        std.mem.copyForwards(u8, &queue.octets, queue.octets[consumed..queue.len]);
        queue.len -= consumed;
        queue.preface_left -= @min(queue.preface_left, consumed);
    }

    fn note_head(queue: *Queue, kind: HeadKind) void {
        assert(queue.heads_written < queue.heads.len);
        queue.heads[queue.heads_written] = kind;
        queue.heads_written += 1;
    }
};

/// What the run saw the connections take, per stream, in the model's terms. Index 0 is stream 1.
pub const Seen = struct {
    request: [limits.streams_max]RequestPhase = @splat(.none),
    request_data: [limits.streams_max]u32 = @splat(0),
    response: [limits.streams_max]ResponsePhase = @splat(.none),
    response_interims: [limits.streams_max]u32 = @splat(0),
    response_data: [limits.streams_max]u32 = @splat(0),
    request_read: [limits.streams_max]RequestPhase = @splat(.none),
    response_read: [limits.streams_max]ResponsePhase = @splat(.none),
    goaways_sent: u32 = 0,
    /// A receiver reset a stream for a stream error (RFC 9113 §5.4.2), or read a message out of
    /// §8.1's order: two colibri endpoints never cause one.
    malformed: bool = false,
    /// The client opened a stream after it read a GOAWAY (RFC 9113 §6.8).
    late_open: bool = false,
    /// Streams the client opened, and write calls a connection refused.
    opened: u32 = 0,
    refused: u32 = 0,
};

/// The field lines each request, interim response and trailer section carries.
const request: h2.connection.Request_ = .{ .method = "POST", .scheme = "https", .path = "/", .authority = "example.test" };
const trailers = [_]h2.hpack.Field{.{ .name = "grpc-status", .value = "0" }};
/// RFC 9110 §15.2.4: 103 Early Hints, an interim response, and §15.3.1: 200 OK, a final one.
const interim_status: u16 = 103;
const final_status: u16 = 200;
/// One octet of content a DATA frame carries.
const content_octet = "x";

/// Receive calls one delivery makes at most: every frame a direction holds, and the replies they
/// owe.
const receives_per_delivery_max: usize = limits.receives_per_frame_max * limits.frames_max;

pub const Pair = struct {
    client: Connection,
    server: Connection,
    to_server: Queue,
    to_client: Queue,
    seen: Seen,
    now_ns: u64,

    /// Both endpoints with nothing written or read.
    pub fn init(pair: *Pair, now_ns: u64) void {
        pair.client.init(.client);
        pair.server.init(.server);
        pair.to_server = .{};
        pair.to_client = .{};
        pair.seen = .{};
        pair.now_ns = now_ns;
    }

    /// Each endpoint writes its preface, which h2 asks of its caller before any other call.
    pub fn start(pair: *Pair) void {
        pair.flush(.client);
        pair.flush(.server);
        // RFC 9113 §3.4: the client's preface is 24 octets that are no frame and its SETTINGS
        // frame, and the server's is its SETTINGS frame.
        pair.to_server.preface_left = h2.constants.client_preface_len + settings_len(pair.to_server.held()[h2.constants.client_preface_len..]);
        pair.to_client.preface_left = settings_len(pair.to_client.held());
    }

    /// Whether the connection at `side` failed.
    pub fn failed(pair: *const Pair, side: sim.network.Endpoint) bool {
        return switch (side) {
            .client => pair.client.has_failed(),
            .server => pair.server.has_failed(),
        };
    }

    /// Acts out one action. A call the connection refuses changes nothing.
    pub fn act(pair: *Pair, action: Action, plan: *const h2_trace_plan.Plan) void {
        switch (action) {
            .open => |end| pair.open(end, plan),
            .client_data => |target| pair.client_data(target, plan),
            .client_trailers => |stream| pair.client_trailers(stream),
            .client_reset => |stream| if (plan.resets) pair.reset(.client, stream),
            .server_interim => |target| pair.server_interim(target, plan),
            .server_final => |target| pair.server_final(target),
            .server_data => |target| pair.server_data(target, plan),
            .server_trailers => |stream| pair.server_trailers(stream),
            .server_reset => |stream| if (plan.resets) pair.reset(.server, stream),
            .server_goaway => pair.goaway(plan),
            .deliver_to_server => pair.deliver(.server),
            .deliver_to_client => pair.deliver(.client),
        }
    }

    fn open(pair: *Pair, end: bool, plan: *const h2_trace_plan.Plan) void {
        // The model's client opens `N` streams at most.
        if (pair.seen.opened == plan.streams) return;
        const sent = pair.client.write_request(pair.to_server.room(), request, &.{}, &.{}, end) catch return pair.note_refused();
        pair.to_server.len += sent.written;
        pair.to_server.note_head(.head);
        const index = index_of(sent.stream_id);
        pair.seen.opened += 1;
        assert(index == pair.seen.opened - 1);
        pair.seen.request[index] = if (end) .ended else .head;
        if (pair.client.streams.goaway_received_last_id != null) pair.seen.late_open = true;
        pair.flush(.client);
    }

    fn client_data(pair: *Pair, target: Target, plan: *const h2_trace_plan.Plan) void {
        const index = target.stream - 1;
        // The model's messages carry `Content` DATA frames at most.
        if (pair.seen.request_data[index] == plan.content) return;
        const sent = pair.client.write_data(pair.to_server.room(), id_of(target.stream), content_octet, target.end) catch return pair.note_refused();
        if (sent.written == 0) return;
        pair.to_server.len += sent.written;
        pair.seen.request_data[index] += 1;
        if (target.end) pair.seen.request[index] = .ended;
        pair.flush(.client);
    }

    fn client_trailers(pair: *Pair, stream: u32) void {
        const written = pair.client.write_trailers(pair.to_server.room(), id_of(stream), &trailers) catch return pair.note_refused();
        pair.to_server.len += written;
        pair.to_server.note_head(.trailers);
        pair.seen.request[stream - 1] = .ended;
        pair.flush(.client);
    }

    fn server_interim(pair: *Pair, target: Target, plan: *const h2_trace_plan.Plan) void {
        const index = target.stream - 1;
        // The model's responses carry `Interims` interim heads at most.
        if (pair.seen.response_interims[index] == plan.interims) return;
        const written = pair.server.write_response(pair.to_client.room(), id_of(target.stream), interim_status, &.{}, target.end) catch return pair.note_refused();
        pair.to_client.len += written;
        pair.to_client.note_head(.interim);
        pair.seen.response_interims[index] += 1;
        pair.seen.response[index] = if (target.end) .ended else if (pair.seen.response[index] == .none) .interim else pair.seen.response[index];
        pair.flush(.server);
    }

    fn server_final(pair: *Pair, target: Target) void {
        const written = pair.server.write_response(pair.to_client.room(), id_of(target.stream), final_status, &.{}, target.end) catch return pair.note_refused();
        pair.to_client.len += written;
        pair.to_client.note_head(.head);
        pair.seen.response[target.stream - 1] = if (target.end) .ended else .final;
        pair.flush(.server);
    }

    fn server_data(pair: *Pair, target: Target, plan: *const h2_trace_plan.Plan) void {
        const index = target.stream - 1;
        if (pair.seen.response_data[index] == plan.content) return;
        const sent = pair.server.write_data(pair.to_client.room(), id_of(target.stream), content_octet, target.end) catch return pair.note_refused();
        if (sent.written == 0) return;
        pair.to_client.len += sent.written;
        pair.seen.response_data[index] += 1;
        if (target.end) pair.seen.response[index] = .ended;
        pair.flush(.server);
    }

    fn server_trailers(pair: *Pair, stream: u32) void {
        const written = pair.server.write_trailers(pair.to_client.room(), id_of(stream), &trailers) catch return pair.note_refused();
        pair.to_client.len += written;
        pair.to_client.note_head(.trailers);
        pair.seen.response[stream - 1] = .ended;
        pair.flush(.server);
    }

    fn reset(pair: *Pair, side: sim.network.Endpoint, stream: u32) void {
        const connection = pair.endpoint(side);
        connection.reset_stream(id_of(stream), h2.constants.error_cancel) catch return pair.note_refused();
        pair.flush(side);
    }

    fn goaway(pair: *Pair, plan: *const h2_trace_plan.Plan) void {
        // The model's server sends `MaxGoaways` GOAWAY frames at most.
        if (pair.seen.goaways_sent == plan.goaways) return;
        pair.server.shutdown(h2.constants.error_no_error);
        pair.seen.goaways_sent += 1;
        pair.flush(.server);
    }

    /// The endpoint at `side` reads every whole frame its queue holds, writing what it owes as
    /// it goes.
    fn deliver(pair: *Pair, side: sim.network.Endpoint) void {
        const connection = pair.endpoint(side);
        const queue = pair.incoming(side);
        for (0..receives_per_delivery_max) |_| {
            if (connection.has_failed()) return;
            const received = connection.receive(queue.held(), pair.now_ns) catch return;
            if (received.consumed == 0) {
                // RFC 9113 §6.5.3: what the connection owes goes out before it reads on.
                if (!connection.has_pending()) return;
                pair.flush(side);
                continue;
            }
            if (received.event) |event| pair.on_event(side, event);
            queue.take(received.consumed);
            pair.flush(side);
        }
    }

    fn on_event(pair: *Pair, side: sim.network.Endpoint, event: h2.Event) void {
        switch (side) {
            .server => pair.on_server_event(event),
            .client => pair.on_client_event(event),
        }
    }

    fn on_server_event(pair: *Pair, event: h2.Event) void {
        const seen = &pair.seen;
        switch (event) {
            .request => |arrived| seen.request_read[index_of(arrived.stream_id)] = if (arrived.end_stream) .ended else .head,
            .data => |data| if (data.end_stream) {
                seen.request_read[index_of(data.stream_id)] = .ended;
            },
            .trailers => |held| seen.request_read[index_of(held.stream_id)] = .ended,
            .stream_refused => seen.malformed = true,
            .settings_acknowledged, .settings_applied, .ping_acknowledged, .stream_reset, .goaway, .response, .alt_svc => {},
        }
    }

    fn on_client_event(pair: *Pair, event: h2.Event) void {
        const seen = &pair.seen;
        switch (event) {
            .response => |arrived| {
                const index = index_of(arrived.stream_id);
                const interim = arrived.response.status.is_interim();
                seen.response_read[index] = if (arrived.end_stream) .ended else if (interim) .interim else .final;
            },
            .data => |data| if (data.end_stream) {
                seen.response_read[index_of(data.stream_id)] = .ended;
            },
            .trailers => |held| seen.response_read[index_of(held.stream_id)] = .ended,
            .stream_refused => seen.malformed = true,
            .settings_acknowledged, .settings_applied, .ping_acknowledged, .stream_reset, .goaway, .request, .alt_svc => {},
        }
    }

    fn note_refused(pair: *Pair) void {
        pair.seen.refused += 1;
    }

    /// Writes every frame the endpoint at `side` owes into its queue.
    fn flush(pair: *Pair, side: sim.network.Endpoint) void {
        const connection = pair.endpoint(side);
        const queue = pair.outgoing(side);
        queue.len += connection.write_pending(queue.room(), pair.now_ns);
        assert(!connection.has_pending() or connection.has_failed());
    }

    fn endpoint(pair: *Pair, side: sim.network.Endpoint) *Connection {
        return switch (side) {
            .client => &pair.client,
            .server => &pair.server,
        };
    }

    fn outgoing(pair: *Pair, side: sim.network.Endpoint) *Queue {
        return switch (side) {
            .client => &pair.to_server,
            .server => &pair.to_client,
        };
    }

    fn incoming(pair: *Pair, side: sim.network.Endpoint) *Queue {
        return switch (side) {
            .client => &pair.to_client,
            .server => &pair.to_server,
        };
    }
};

/// The octets of the SETTINGS frame that `octets` starts with (RFC 9113 §4.1, §6.5).
fn settings_len(octets: []const u8) usize {
    var reader = h2.core.Reader.init(octets);
    const header = h2.frame.read_header(&reader) catch unreachable;
    const len = h2.constants.frame_header_len + header.length;
    assert(header.type == h2.constants.frame_type_settings and len <= octets.len);
    return len;
}

/// RFC 9113 §5.1.1: the client's streams are the odd identifiers, the model's stream i being 2i - 1.
pub fn id_of(stream: u32) u32 {
    assert(stream >= 1);
    return h2.constants.stream_id_client_first + h2.constants.stream_id_step * (stream - 1);
}

/// The index of the stream `id` names into the per-stream arrays: stream 1 at 0.
pub fn index_of(id: u32) usize {
    assert(id % h2.constants.stream_id_step == h2.constants.stream_id_client_first);
    return (id - h2.constants.stream_id_client_first) / h2.constants.stream_id_step;
}
