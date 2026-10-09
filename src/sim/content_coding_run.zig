//! One run of the content-coding check (`content_coding_check.zig`, decision 101): a colibri
//! client and a colibri server over two streams, delivered in seeded pieces or whole. The client
//! makes every exchange of the plan, and the server's caller answers each as the plan says, marked
//! codable or not, in writes of the content, until every exchange ended.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const tls = @import("tls");
const client = @import("client");
const server = @import("server");
const plan_module = @import("content_coding_plan.zig");

const Random = sim.Random;
const limits = sim.constants.content_coding;
const Plan = plan_module.Plan;

pub const Error = client.RequestError || client.StartError || server.StartError || error{
    /// A side refused what the other wrote, or the server's caller could not answer.
    ExchangeRefused,
    /// The run stopped moving before every exchange ended.
    RunStalled,
};

/// The pools each side codes with: one encoder or decoder for each exchange, so neither side runs
/// out, which the modules' own tests cover.
pub const EncoderPool = server.EncoderPool(limits.exchanges_max, encoder_level);
const encoder_level: u4 = 1;
pub const DecoderPool = client.DecoderPool(limits.exchanges_max);

/// One direction's octets: written at the back, delivered in pieces, consumed from the front.
const Stream = struct {
    octets: [limits.stream_len_max]u8,
    written: usize,
    delivered: usize,
    consumed: usize,

    fn reset(stream: *Stream) void {
        stream.written = 0;
        stream.delivered = 0;
        stream.consumed = 0;
    }

    fn free(stream: *Stream) []u8 {
        return stream.octets[stream.written..];
    }

    fn held(stream: *Stream) []u8 {
        return stream.octets[stream.consumed..stream.delivered];
    }

    /// Delivers a piece drawn from `pieces`, or everything written when it is null.
    fn deliver(stream: *Stream, pieces: ?*Random) void {
        const pending = stream.written - stream.delivered;
        if (pending == 0) return;
        stream.delivered += if (pieces) |random| random.between(1, @min(limits.piece_len_max, pending)) else pending;
    }
};

/// What the server's caller holds of one request: the exchange of the plan it answers, and how
/// far its answer has gone.
const Answer = struct {
    id: u64,
    index: u8,
    responded: bool,
    written: u32,
};

pub const Storage = struct {
    encoders: EncoderPool,
    decoders: DecoderPool,
    server_config: server.Config,
    client_config: client.Config,
    server_connection: server.Connection,
    client_connection: client.Connection,
    to_server: Stream,
    to_client: Stream,
    exchanges: [limits.exchanges_max]client.HttpExchange,
    own_offers: [limits.exchanges_max][1]client.Field,
    bodies: [limits.exchanges_max][limits.coded_len_max]u8,
    contents: [limits.exchanges_max][limits.content_len_max]u8,
    answers: [limits.exchanges_max]Answer,
    answers_len: u8,
    finished: u8,
    tls_random: Random,
};

/// The instant every call passes: the run needs no clock.
const now_ns: u64 = 0;

/// Makes the plan's exchanges between a new client and server and runs them until each ended.
pub fn run(storage: *Storage, plan: *const Plan, content_seed: u64, pieces: ?*Random) Error!void {
    try start(storage, plan, content_seed);
    // Bounded: each round moves octets both ways, and the plan's responses end in fewer.
    for (0..limits.rounds_max) |_| {
        storage.to_server.written += storage.client_connection.send(storage.to_server.free(), now_ns);
        storage.to_server.deliver(pieces);
        try server_read(storage);
        try server_write(storage, plan);
        storage.to_client.written += storage.server_connection.send(storage.to_client.free(), now_ns);
        storage.to_client.deliver(pieces);
        client_read(storage);
        if (storage.finished == plan.exchanges_len) return;
    }
    return error.RunStalled;
}

fn start(storage: *Storage, plan: *const Plan, content_seed: u64) Error!void {
    storage.encoders.reset(.none());
    const decoders = storage.decoders.storage();
    decoders.reset(.none());
    // Decision 117: each side allows the plan's version alone, so each speaks it from the start.
    const server_versions: server.Versions = switch (plan.protocol) {
        .h11 => .{ .h2 = false },
        .h2 => .{ .h11 = false },
    };
    const client_versions: client.Versions = switch (plan.protocol) {
        .h11 => .{ .h2 = false },
        .h2 => .{ .h11 = false },
    };
    storage.server_config = .{ .versions = server_versions };
    if (plan.server_codings_len > 0) {
        storage.server_config.codings = plan.server_offers();
        storage.server_config.encoders = storage.encoders.encoders();
    }
    storage.client_config = .{ .authority = "a.example", .versions = client_versions };
    if (plan.client_codings_len > 0) {
        storage.client_config.codings = plan.client_offers();
        storage.client_config.decoders = decoders;
    }
    storage.tls_random = Random.init(content_seed);
    const source = tls.Random.init(&storage.tls_random, fill);
    try storage.server_connection.init(&storage.server_config, source, 0, now_ns);
    try storage.client_connection.init(&storage.client_config, source, 0, null);
    storage.to_server.reset();
    storage.to_client.reset();
    storage.answers_len = 0;
    storage.finished = 0;
    for (plan.exchanges[0..plan.exchanges_len], 0..) |*planned, index| {
        fill_content(storage.contents[index][0..planned.content_len], planned.compressible, content_seed +% index);
        try request(storage, planned, index);
    }
}

fn request(storage: *Storage, planned: *const plan_module.Exchange, index: usize) Error!void {
    const exchange = &storage.exchanges[index];
    exchange.* = .{ .method = if (planned.head) "HEAD" else "GET", .path = "/", .body = &storage.bodies[index] };
    // A body the client decodes or takes as it came is one octet short of the content when the
    // plan says so; one it passes on coded gets all its room.
    const expected = plan_module.expect_short(planned);
    if (expected) exchange.body = storage.bodies[index][0 .. planned.content_len - 1];
    if (planned.own_offer.value()) |value| {
        storage.own_offers[index] = .{.{ .name = "accept-encoding", .value = value }};
        exchange.fields = &storage.own_offers[index];
    }
    _ = try storage.client_connection.request(exchange);
}

fn fill(random: *Random, buffer: []u8) void {
    for (buffer) |*octet| octet.* = @truncate(random.next());
}

/// Content from `seed`: runs of text DEFLATE shrinks, or octets it cannot.
fn fill_content(content: []u8, compressible: bool, seed: u64) void {
    var random = Random.init(seed);
    if (!compressible) return fill(&random, content);
    for (content, 0..) |*octet, index| octet.* = text[(index + random.below(text_skew_max)) % text.len];
}

const text = "colibri codes content a request accepts, and decodes content it offered. ";
/// How far a compressible octet's text may slip, so the runs vary.
const text_skew_max: u64 = 2;

/// The server reads what the client sent and notes each request it must answer.
fn server_read(storage: *Storage) Error!void {
    const stream = &storage.to_server;
    // Bounded: each pass consumes an octet or reports an event.
    for (0..limits.stream_len_max + limits.exchanges_max * events_per_exchange) |_| {
        const received = storage.server_connection.receive(stream.held(), now_ns) catch return error.ExchangeRefused;
        stream.consumed += received.consumed;
        const reported = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        switch (reported) {
            .request => |head| {
                // Both protocols deliver the client's requests in the order it made them.
                storage.answers[storage.answers_len] = .{ .id = head.id.number, .index = storage.answers_len, .responded = false, .written = 0 };
                storage.answers_len += 1;
            },
            .body, .trailers, .done => {},
            .cancelled => return error.ExchangeRefused,
            // A connection reports none of these: the endpoint does (decision 119).
            .writable, .send, .close, .ended, .closed => unreachable,
        }
    }
}

/// The events one exchange gives the server at most: its request, its end, and its `done`.
const events_per_exchange: usize = 3;

/// The server's caller answers each request it read, writing as much content as it takes.
fn server_write(storage: *Storage, plan: *const Plan) Error!void {
    for (storage.answers[0..storage.answers_len]) |*answer| {
        const planned = &plan.exchanges[answer.index];
        if (!answer.responded and !try respond(storage, answer, planned)) return;
        if (!try write_content(storage, answer, planned)) return;
    }
}

/// Writes the head of the answer. Returns false when the output is full: `send`, then answer again.
fn respond(storage: *Storage, answer: *Answer, planned: *const plan_module.Exchange) Error!bool {
    const end = planned.head or planned.content_len == 0;
    storage.server_connection.respond(answer.id, .{ .status = planned.status, .end = end, .codable = planned.codable }) catch |failure| {
        if (failure == error.NoSpaceLeft) return false;
        return error.ExchangeRefused;
    };
    answer.responded = true;
    if (end) answer.written = planned.content_len;
    return true;
}

/// Writes the answer's content in writes of at most `write_len_max`. Returns false when the
/// server takes no more for now.
fn write_content(storage: *Storage, answer: *Answer, planned: *const plan_module.Exchange) Error!bool {
    const content = storage.contents[answer.index][0..planned.content_len];
    // Bounded: each pass takes an octet at least, or stops.
    for (0..content.len + 1) |_| {
        if (answer.written == content.len) return true;
        const left = content[answer.written..];
        const octets = left[0..@min(left.len, limits.write_len_max)];
        const taken = storage.server_connection.write_body(answer.id, .{ .octets = octets, .end = octets.len == left.len }) catch |failure| {
            // No room, or the ring or h2's window is full: `send`, `receive`, then write again.
            if (failure == error.Blocked) return false;
            return error.ExchangeRefused;
        };
        answer.written += @intCast(taken);
        if (taken < octets.len) return false;
    }
    unreachable;
}

/// The client reads what the server sent, and counts the exchanges that ended.
fn client_read(storage: *Storage) void {
    const stream = &storage.to_client;
    // Bounded: each pass consumes an octet or reports an event.
    for (0..limits.stream_len_max + limits.exchanges_max * events_per_exchange) |_| {
        const received = storage.client_connection.receive(stream.held(), now_ns);
        stream.consumed += received.consumed;
        const reported = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        if (reported == .finished) storage.finished += 1;
    }
}
