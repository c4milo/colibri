//! One run of the h2 stall check (https://github.com/c4milo/colibri/issues/85): a colibri client
//! and a colibri server exchange a seed's messages over a transport that holds the plan's
//! `capacity` octets each way. Each endpoint is driven the way a caller drives h2 (decision 39):
//!   - its reading takes frames while `receive` consumes them. When `receive` consumes nothing and
//!     the connection owes frames, the reading writes them, and reads on only if they fit;
//!   - its writing writes what the connection owes, then the client's requests and bodies, or the
//!     server's responses and bodies, in turn over the streams as the windows and the room allow.
//! The server answers a request as soon as it reads the head, so both directions carry DATA at
//! once.
//!
//! Each round takes one reading turn and one writing turn of each endpoint, in an order the seed
//! draws. A round in which nothing moves ends the run: every turn saw the state no turn changed,
//! so no later round moves either. The run finished if every message arrived whole, and stalled if
//! not, and a stall records what each endpoint held.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const sim = @import("sim");
const h2_stall_plan = @import("h2_stall_plan.zig");

const Random = sim.Random;
const limits = sim.constants.h2_stall;
const Connection = h2.Connection;
const Plan = h2_stall_plan.Plan;

pub const Error = error{
    /// An endpoint found a connection error in what the other sent, which two colibri endpoints
    /// never cause.
    ConnectionFailed,
    /// An endpoint reported a reset, a refusal, a GOAWAY or a message the run never sends.
    EventUnexpected,
    /// A write call failed for a reason other than room or window.
    WriteRefused,
    /// A body arrived with other than the octets its sender sent.
    BodyMismatch,
    /// The run took `rounds_max` rounds and neither finished nor stopped moving.
    RunTooLong,
};

pub const Outcome = enum { finished, stalled };

/// What one run did.
pub const Record = struct {
    outcome: Outcome,
    rounds: u64,
    /// Body octets that arrived, both ways.
    octets: u64,
    /// Whether each endpoint's reply queue was full when the run stopped: at a stall, whether
    /// `receive` refused to read for want of a slot.
    client_queue_full: bool,
    server_queue_full: bool,
    /// Octets each direction of the transport held when the run stopped.
    to_server_len: u32,
    to_client_len: u32,
    /// The most replies about single streams each endpoint held at once, and the times `receive`
    /// took no frame because a reply queue was full.
    client_replies_most: u32,
    server_replies_most: u32,
    reads_stopped_full: u64,
};

/// One direction of the transport: octets written at the back and read from the front, at most
/// the plan's capacity.
const Queue = struct {
    octets: [limits.capacity_max]u8,
    len: u32,
    capacity: u32,

    fn held(queue: *const Queue) []const u8 {
        return queue.octets[0..queue.len];
    }

    fn room(queue: *Queue) []u8 {
        return queue.octets[queue.len..queue.capacity];
    }

    fn put(queue: *Queue, written: usize) void {
        assert(written <= queue.capacity - queue.len);
        queue.len += @intCast(written);
    }

    fn take(queue: *Queue, consumed: usize) void {
        assert(consumed <= queue.len);
        std.mem.copyForwards(u8, &queue.octets, queue.octets[consumed..queue.len]);
        queue.len -= @intCast(consumed);
    }
};

/// How far one direction's messages went, per stream: index 0 is stream 1.
const Messages = struct {
    /// The sender wrote the head, and wrote this many body octets.
    headed: [limits.streams_max]bool,
    sent: [limits.streams_max]u32,
    /// The receiver read the head, this many body octets, and END_STREAM.
    head_read: [limits.streams_max]bool,
    read: [limits.streams_max]u32,
    ended: [limits.streams_max]bool,
    /// The stream the sender's next DATA goes on first.
    cursor: u32,

    fn init(messages: *Messages) void {
        messages.headed = @splat(false);
        messages.sent = @splat(0);
        messages.head_read = @splat(false);
        messages.read = @splat(0);
        messages.ended = @splat(false);
        messages.cursor = 0;
    }
};

const Side = enum { client, server };

/// One endpoint's connection, the direction it reads and the direction it writes.
const End = struct {
    connection: *Connection,
    input: *Queue,
    output: *Queue,
};

/// What an endpoint sends bodies with: its connection, the direction it writes, how far its
/// messages went, and each body's length.
const Sender = struct {
    connection: *Connection,
    output: *Queue,
    messages: *Messages,
    body_len: *const [limits.streams_max]u32,
};
const Turn = enum { client_read, client_write, server_read, server_write };

/// The request each stream carries, a POST whose body the plan sizes (RFC 9113 §8.3.1).
const request: h2.connection.Request_ = .{ .method = "POST", .scheme = "https", .path = "/", .authority = "example.test" };
/// RFC 9110 §15.3.1: 200 OK.
const status_ok: u16 = 200;
/// The octets every DATA frame carries: their value does not matter, only their count.
const payload: [limits.chunk_len_max]u8 = @splat('x');
/// The instant every call is given: nothing in a run waits on a clock.
const now_ns: u64 = 1_000_000;

/// The endpoints, the transport and the messages of one run, outside any stack frame.
pub const Storage = struct {
    client: Connection,
    server: Connection,
    to_server: Queue,
    to_client: Queue,
    requests: Messages,
    responses: Messages,
    /// What `Record` reports of the reply queues, gathered as the run goes.
    client_replies_most: u32,
    server_replies_most: u32,
    reads_stopped_full: u64,

    /// Runs `plan`, taking each round's order of turns from `random`.
    pub fn run(storage: *Storage, plan: *const Plan, random: *Random) Error!Record {
        storage.init(plan);
        for (0..limits.rounds_max) |index| {
            const moved = try storage.round(plan, random);
            if (try storage.finished(plan)) return storage.record(.finished, index + 1, plan);
            if (!moved) return storage.record(.stalled, index + 1, plan);
        }
        return error.RunTooLong;
    }

    fn init(storage: *Storage, plan: *const Plan) void {
        storage.client.init(.client);
        storage.server.init(.server);
        storage.to_server.len = 0;
        storage.to_server.capacity = plan.capacity;
        storage.to_client.len = 0;
        storage.to_client.capacity = plan.capacity;
        storage.requests.init();
        storage.responses.init();
        storage.client_replies_most = 0;
        storage.server_replies_most = 0;
        storage.reads_stopped_full = 0;
        // RFC 9113 §3.4: each endpoint's preface goes first, before any frame of its caller's, as
        // `server.Connection` writes it before it reads a frame. The smallest transport holds both.
        _ = write_owed(&storage.client, &storage.to_server);
        _ = write_owed(&storage.server, &storage.to_client);
        assert(storage.client.preface_done() and storage.server.preface_done());
    }

    /// One turn of each kind, in an order `random` draws, and whether any of them moved an octet.
    fn round(storage: *Storage, plan: *const Plan, random: *Random) Error!bool {
        var turns = [_]Turn{ .client_read, .client_write, .server_read, .server_write };
        // Fisher-Yates: each order of the four turns is equally likely.
        var left: usize = turns.len;
        while (left > 1) : (left -= 1) {
            const chosen: usize = @intCast(random.below(left));
            std.mem.swap(Turn, &turns[chosen], &turns[left - 1]);
        }
        var moved = false;
        for (turns) |turn| {
            const turn_moved = switch (turn) {
                .client_read => try storage.read(.client, plan),
                .client_write => try storage.client_write(plan),
                .server_read => try storage.read(.server, plan),
                .server_write => try storage.server_write(plan),
            };
            moved = moved or turn_moved;
        }
        return moved;
    }

    /// One reading turn: frames while `receive` takes them, and what the connection owes whenever
    /// it takes none, which is decision 39's loop.
    fn read(storage: *Storage, side: Side, plan: *const Plan) Error!bool {
        const end = storage.end_of(side);
        var consumed: usize = 0;
        var moved = false;
        for (0..plan.frames_per_turn) |_| {
            const received = end.connection.receive(end.input.held()[consumed..], now_ns) catch return error.ConnectionFailed;
            storage.note_replies(side);
            if (received.consumed == 0) {
                if (!storage.write_when_stopped(end)) break;
                moved = true;
                continue;
            }
            consumed += received.consumed;
            moved = true;
            if (received.event) |event| try storage.take_event(side, event, plan);
        }
        // The events' payloads point into the input, so it is taken only after the last one.
        end.input.take(consumed);
        return moved;
    }

    /// `side`'s connection and the two directions of the transport, as it reads and writes them.
    fn end_of(storage: *Storage, side: Side) End {
        return switch (side) {
            .client => .{ .connection = &storage.client, .input = &storage.to_client, .output = &storage.to_server },
            .server => .{ .connection = &storage.server, .input = &storage.to_server, .output = &storage.to_client },
        };
    }

    /// After `receive` took no frame, writes what the connection owes, counting a stop for a full
    /// reply queue. Whether the reading goes on: decision 39 has it write what it owes, and read on
    /// only if that fits.
    fn write_when_stopped(storage: *Storage, end: End) bool {
        if (end.connection.replies.is_full()) storage.reads_stopped_full += 1;
        return end.connection.has_pending() and write_owed(end.connection, end.output);
    }

    /// Raises the most replies about single streams `side`'s connection held at once.
    fn note_replies(storage: *Storage, side: Side) void {
        switch (side) {
            .client => storage.client_replies_most = @max(storage.client_replies_most, storage.client.replies.stream_reply_count),
            .server => storage.server_replies_most = @max(storage.server_replies_most, storage.server.replies.stream_reply_count),
        }
    }

    fn take_event(storage: *Storage, side: Side, event: h2.Event, plan: *const Plan) Error!void {
        switch (event) {
            .settings_applied, .settings_acknowledged => {},
            .request => |head| if (side == .server) {
                try note_head(&storage.requests, head.stream_id, head.end_stream, plan);
            } else return error.EventUnexpected,
            .response => |head| if (side == .client) {
                try note_head(&storage.responses, head.stream_id, head.end_stream, plan);
            } else return error.EventUnexpected,
            .data => |data| {
                const messages = if (side == .server) &storage.requests else &storage.responses;
                try note_data(messages, data, plan);
            },
            .trailers, .stream_reset, .stream_refused, .goaway, .alt_svc, .ping_acknowledged => return error.EventUnexpected,
        }
    }

    /// One writing turn of the client: what its connection owes, before or after its requests and
    /// their bodies as the plan says.
    fn client_write(storage: *Storage, plan: *const Plan) Error!bool {
        var moved = plan.client_owed_first and write_owed(&storage.client, &storage.to_server);
        for (0..plan.writes_per_turn) |_| {
            const wrote = try storage.open_next(plan) or try send_body(.{
                .connection = &storage.client,
                .output = &storage.to_server,
                .messages = &storage.requests,
                .body_len = &plan.request_len,
            }, plan);
            if (!wrote) break;
            moved = true;
        }
        if (!plan.client_owed_first and write_owed(&storage.client, &storage.to_server)) moved = true;
        return moved;
    }

    /// One writing turn of the server: what its connection owes, before or after its responses and
    /// their bodies as the plan says.
    fn server_write(storage: *Storage, plan: *const Plan) Error!bool {
        var moved = plan.server_owed_first and write_owed(&storage.server, &storage.to_client);
        for (0..plan.writes_per_turn) |_| {
            const wrote = try storage.respond_next(plan) or try send_body(.{
                .connection = &storage.server,
                .output = &storage.to_client,
                .messages = &storage.responses,
                .body_len = &plan.response_len,
            }, plan);
            if (!wrote) break;
            moved = true;
        }
        if (!plan.server_owed_first and write_owed(&storage.server, &storage.to_client)) moved = true;
        return moved;
    }

    /// Opens the next stream with its request's head, when a stream is left and the room holds it.
    fn open_next(storage: *Storage, plan: *const Plan) Error!bool {
        const index = std.mem.indexOfScalar(bool, storage.requests.headed[0..plan.streams], false) orelse return false;
        const end = plan.request_len[index] == 0;
        const sent = storage.client.write_request(storage.to_server.room(), request, &.{}, &.{}, end) catch |failure| {
            return if (failure == error.OutputTooSmall) false else error.WriteRefused;
        };
        // RFC 9113 §5.1.1: the client's streams take the odd identifiers in order.
        if (sent.stream_id != stream_id_of(index)) return error.WriteRefused;
        storage.to_server.put(sent.written);
        storage.requests.headed[index] = true;
        return true;
    }

    /// Writes the response head of the first stream whose request head arrived and that has none.
    fn respond_next(storage: *Storage, plan: *const Plan) Error!bool {
        for (0..plan.streams) |index| {
            if (!storage.requests.head_read[index] or storage.responses.headed[index]) continue;
            const end = plan.response_len[index] == 0;
            const written = storage.server.write_response(storage.to_client.room(), stream_id_of(index), status_ok, &.{}, end) catch |failure| {
                return if (failure == error.OutputTooSmall) false else error.WriteRefused;
            };
            storage.to_client.put(written);
            storage.responses.headed[index] = true;
            return true;
        }
        return false;
    }

    /// Whether every message arrived whole, and nothing is left in the transport or owed.
    fn finished(storage: *Storage, plan: *const Plan) Error!bool {
        for (0..plan.streams) |index| {
            if (!storage.requests.ended[index] or !storage.responses.ended[index]) return false;
            const request_whole = storage.requests.read[index] == plan.request_len[index];
            const response_whole = storage.responses.read[index] == plan.response_len[index];
            if (!request_whole or !response_whole) return error.BodyMismatch;
        }
        if (storage.to_server.len > 0 or storage.to_client.len > 0) return false;
        return !storage.client.has_pending() and !storage.server.has_pending();
    }

    fn record(storage: *const Storage, outcome: Outcome, rounds: u64, plan: *const Plan) Record {
        var octets: u64 = 0;
        for (0..plan.streams) |index| octets += storage.requests.read[index] + storage.responses.read[index];
        return .{
            .outcome = outcome,
            .rounds = rounds,
            .octets = octets,
            .client_queue_full = storage.client.replies.is_full(),
            .server_queue_full = storage.server.replies.is_full(),
            .to_server_len = storage.to_server.len,
            .to_client_len = storage.to_client.len,
            .client_replies_most = storage.client_replies_most,
            .server_replies_most = storage.server_replies_most,
            .reads_stopped_full = storage.reads_stopped_full,
        };
    }
};

/// Writes what `connection` owes into `output`, and whether any of it fit.
fn write_owed(connection: *Connection, output: *Queue) bool {
    const written = connection.write_pending(output.room(), now_ns);
    output.put(written);
    return written > 0;
}

/// Writes one DATA frame on the first stream, from the cursor on, that has body octets to send and
/// the window and room to send some: the whole body in a random seed, and in an aligned seed the
/// first part until every stream has sent it, then the rest.
fn send_body(sender: Sender, plan: *const Plan) Error!bool {
    const second_parts = every_first_part_sent(sender.messages, sender.body_len, plan);
    for (0..plan.streams) |step| {
        const index = (sender.messages.cursor + step) % plan.streams;
        if (!try send_chunk(sender, plan, index, second_parts)) continue;
        sender.messages.cursor = @intCast((index + 1) % plan.streams);
        return true;
    }
    return false;
}

/// Writes one DATA frame of stream `index`'s body, when the part being sent has octets left and the
/// window and the room let some go. Whether it wrote one.
fn send_chunk(sender: Sender, plan: *const Plan, index: usize, second_parts: bool) Error!bool {
    const messages = sender.messages;
    if (!messages.headed[index]) return false;
    const body_len = sender.body_len[index];
    const limit = if (second_parts) body_len else plan.first_part_len(body_len);
    if (messages.sent[index] >= limit) return false;
    // A first part goes in frames as large as the room allows, and the rest in chunks.
    const chunk_max: u32 = if (second_parts or plan.shape == .random) plan.chunk_len else limits.chunk_len_max;
    const len = @min(limit - messages.sent[index], chunk_max);
    const end = messages.sent[index] + len == body_len;
    const sent = sender.connection.write_data(sender.output.room(), stream_id_of(index), payload[0..len], end) catch return error.WriteRefused;
    if (sent.written == 0) return false;
    sender.output.put(sent.written);
    messages.sent[index] += @intCast(sent.consumed);
    return true;
}

/// Whether every stream's head and first part are written, after which an aligned seed's second
/// parts may go. A random seed has no second parts: its first part is the whole body.
fn every_first_part_sent(messages: *const Messages, body_len: *const [limits.streams_max]u32, plan: *const Plan) bool {
    for (0..plan.streams) |index| {
        if (!messages.headed[index] or messages.sent[index] < plan.first_part_len(body_len[index])) return false;
    }
    return true;
}

fn note_head(messages: *Messages, stream_id: u32, end_stream: bool, plan: *const Plan) Error!void {
    const index = try index_of(stream_id, plan);
    if (messages.head_read[index]) return error.EventUnexpected;
    messages.head_read[index] = true;
    messages.ended[index] = end_stream;
}

fn note_data(messages: *Messages, data: h2.connection.Data, plan: *const Plan) Error!void {
    const index = try index_of(data.stream_id, plan);
    if (!messages.head_read[index] or messages.ended[index]) return error.EventUnexpected;
    messages.read[index] += @intCast(data.payload.len);
    messages.ended[index] = data.end_stream;
}

/// RFC 9113 §5.1.1: the client's `index`th stream, counting from 0, has the odd identifier `2 *
/// index + 1`.
fn stream_id_of(index: usize) u32 {
    return h2.constants.stream_id_client_first + h2.constants.stream_id_step * @as(u32, @intCast(index));
}

fn index_of(stream_id: u32, plan: *const Plan) Error!usize {
    if (stream_id % h2.constants.stream_id_step != h2.constants.stream_id_client_first) return error.EventUnexpected;
    const index = (stream_id - h2.constants.stream_id_client_first) / h2.constants.stream_id_step;
    if (index >= plan.streams) return error.EventUnexpected;
    return index;
}
