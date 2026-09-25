//! One run of the h11 connection check (`h11_exchange_check.zig`): the client sends what the plan
//! asks as soon as its connection lets it, the server answers each request as the plan says, and
//! each side notes what it read, until nothing more can move.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const sim = @import("sim");
const h11_exchange_plan = @import("h11_exchange_plan.zig");

const http = h11.http;
const Random = sim.Random;
const Trace = sim.Trace;
const constants = sim.constants;
const Plan = h11_exchange_plan.Plan;
const BodyKind = h11_exchange_plan.BodyKind;
const Connection = h11.connection.Connection;
const Field = http.field.Field;

pub const Error = h11.connection.SendError || h11.connection.Error || sim.trace.Error || error{
    /// A side read a head or a body other than the plan's.
    ExchangeDiffers,
    /// The close cut a message short, or left requests unanswered other than those sent after
    /// the last response.
    CloseUnexpected,
};

/// One direction's octets: written at the back, delivered in chunks, consumed from the front.
pub const Stream = struct {
    octets: [constants.h11_exchange_stream_len_max]u8 = undefined,
    written: usize = 0,
    delivered: usize = 0,
    consumed: usize = 0,

    pub fn free(stream: *Stream) []u8 {
        return stream.octets[stream.written..];
    }

    pub fn held(stream: *const Stream) []const u8 {
        return stream.octets[stream.consumed..stream.delivered];
    }

    /// Delivers a chunk drawn from `random`, or everything written when it is null.
    pub fn deliver(stream: *Stream, random: ?*Random) bool {
        const pending = stream.written - stream.delivered;
        if (pending == 0) return false;
        stream.delivered += if (random) |seeded| seeded.between(1, @min(constants.chunk_len_max, pending)) else pending;
        return true;
    }
};

/// What one side read of one exchange's body, and the response's status.
pub const Seen = struct {
    status: u16 = 0,
    len: u32 = 0,
    crc32: std.hash.Crc32 = .init(),
    /// The trailer fields a chunked body ended with.
    trailers: u32 = 0,

    fn add(seen: *Seen, data: []const u8) void {
        seen.crc32.update(data);
        seen.len += @intCast(data.len);
    }
};

/// The field lines a planned head carries at most: Host, the framing field and the close.
const head_fields_max = 3;

/// The octets of a decimal Content-Length.
const length_digits_max = 20;

/// Passes of a read loop per octet held: one that consumes it, and one that ends its message.
const passes_per_octet = 2;

/// The chunks a chunked body is written in, when it has an octet for each.
const chunks_per_body = 2;

/// The trailer field each chunked body ends with (RFC 9112 §7.1.2).
const trailer: Field = .{ .name = "Trailer-Check", .value = "0" };

pub const Run = struct {
    plan: *const Plan,
    client: *Connection,
    server: *Connection,
    to_server: *Stream,
    to_client: *Stream,
    request_seen: []Seen,
    response_seen: []Seen,
    /// The next request the client writes, the request the server reads, and the response the
    /// client reads.
    sent: u32 = 0,
    serving: u32 = 0,
    reading: u32 = 0,
    /// Exchanges whose response the client read whole.
    answered: u32 = 0,
    /// The server read the request `serving` whole and holds it, `delayed` steps so far.
    holding: bool = false,
    delayed: u32 = 0,

    /// Writes every request the client connection lets it write now.
    pub fn send_requests(run: *Run) Error!void {
        // Bounded by the plan's exchanges.
        for (0..run.plan.count) |_| {
            if (run.sent == run.plan.count) return;
            const exchange = &run.plan.exchanges[run.sent];
            var digits: [length_digits_max]u8 = undefined;
            var fields: [head_fields_max]Field = undefined;
            var count: usize = 0;
            fields[count] = .{ .name = "Host", .value = "a.example" };
            count += 1;
            count += framing(exchange.request_body, exchange.request_len, &digits, fields[count..]);
            if (exchange.request_close) {
                fields[count] = .{ .name = "Connection", .value = "close" };
                count += 1;
            }
            const written = run.client.write_request(run.to_server.free(), exchange.method, exchange.target, fields[0..count]) catch |failure| switch (failure) {
                // decision 88 holds this request back, or the connection closed before it.
                error.PipelineBlocked, error.ConnectionClosed => return,
                else => return failure,
            };
            run.to_server.written += written;
            try write_body(run.client, run.to_server, exchange.request_body, run.plan.request_octets[run.sent][0..exchange.request_len]);
            run.sent += 1;
        }
    }

    /// Reads what the server holds, and answers each request once it is read whole and its
    /// delay has passed.
    pub fn serve(run: *Run) Error!void {
        if (run.holding) try run.answer_when_due();
        // Every pass consumes an octet or ends a message, and a message takes at least one octet,
        // so n octets take at most 2n passes, and one more finds them short.
        for (0..passes_per_octet * run.to_server.held().len + 1) |_| {
            const received = try run.server.receive(run.to_server.held());
            run.to_server.consumed += received.consumed;
            const event = received.event orelse return;
            // decision 92: a server reads no request past the one it has not answered.
            if (run.holding) return error.ExchangeDiffers;
            try run.served(event);
            // The request is read whole once the server waits, and its `end` is not still owed.
            if (run.server.phase == .waiting and event != .data) {
                run.holding = true;
                run.delayed = 0;
                try run.answer_when_due();
            }
        }
        unreachable;
    }

    /// Answers the request the server holds once the plan's delay has passed.
    fn answer_when_due(run: *Run) Error!void {
        assert(run.holding and run.server.phase == .waiting);
        if (run.delayed < run.plan.exchanges[run.serving].response_delay) {
            run.delayed += 1;
            return;
        }
        run.holding = false;
        try run.respond();
    }

    fn served(run: *Run, event: h11.connection.Event) Error!void {
        if (run.serving == run.plan.count) return error.ExchangeDiffers;
        const exchange = &run.plan.exchanges[run.serving];
        switch (event) {
            .request => |request| {
                if (!std.mem.eql(u8, request.line.method, exchange.method)) return error.ExchangeDiffers;
                if (!std.mem.eql(u8, request.line.target, exchange.target)) return error.ExchangeDiffers;
            },
            .data => |data| run.request_seen[run.serving].add(data),
            .end => if (exchange.request_body == .chunked) {
                run.request_seen[run.serving].trailers = run.server.trailers.len();
            },
            .interim, .response, .tunnel => return error.ExchangeDiffers,
        }
    }

    /// Answers the request read last as the plan says.
    fn respond(run: *Run) Error!void {
        const exchange = &run.plan.exchanges[run.serving];
        const has_body = h11_exchange_plan.response_has_body(exchange.method, exchange.status);
        var digits: [length_digits_max]u8 = undefined;
        var fields: [head_fields_max]Field = undefined;
        var count: usize = 0;
        // RFC 9112 §6.1 and RFC 9110 §8.6: a 204 carries no framing field; a 304 need not.
        const no_content = exchange.status == @intFromEnum(http.status.Code.no_content) or exchange.status == @intFromEnum(http.status.Code.not_modified);
        if (!no_content) count += framing(exchange.response_body, exchange.response_len, &digits, fields[count..]);
        if (exchange.response_close and exchange.response_body != .close_delimited) {
            fields[count] = .{ .name = "Connection", .value = "close" };
            count += 1;
        }
        run.to_client.written += try run.server.write_response(run.to_client.free(), exchange.status, "", fields[0..count]);
        const octets = if (has_body) run.plan.response_octets[run.serving][0..exchange.response_len] else &.{};
        if (run.server.writer.open()) try write_body(run.server, run.to_client, exchange.response_body, octets);
        run.serving += 1;
    }

    /// Reads what the client holds, noting each response and its body.
    pub fn read_responses(run: *Run) Error!void {
        // Bounded as `serve` is: at most 2n passes for n octets, and one more.
        for (0..passes_per_octet * run.to_client.held().len + 1) |_| {
            const received = try run.client.receive(run.to_client.held());
            run.to_client.consumed += received.consumed;
            try run.read(received.event orelse return);
        }
        unreachable;
    }

    fn read(run: *Run, event: h11.connection.Event) Error!void {
        if (run.reading == run.plan.count) return error.ExchangeDiffers;
        const seen = &run.response_seen[run.reading];
        switch (event) {
            .response => |response| {
                seen.status = response.line.status.code;
                // A response without a body is read whole with its head.
                if (run.client.phase != .body) run.finish_reading();
            },
            .data => |data| seen.add(data),
            .end => {
                if (run.plan.exchanges[run.reading].response_body == .chunked) seen.trailers = run.client.trailers.len();
                run.finish_reading();
            },
            .interim, .request, .tunnel => return error.ExchangeDiffers,
        }
    }

    fn finish_reading(run: *Run) void {
        run.reading += 1;
        run.answered += 1;
    }

    /// Nothing moves in either direction any more. A server that closed closes the transport,
    /// which ends a body that runs until the close (RFC 9112 §6.3 rule 8) and cuts no other
    /// message short, and the requests sent after the last response go unanswered (§9.6).
    pub fn settle(run: *Run) Error!void {
        assert(run.to_client.delivered == run.to_client.written);
        // RFC 9112 §9.6: a client closes after the response that carries the close, and only a
        // body that runs until the close is still being read when the server closes.
        const client_closing = run.client.should_close() or run.client.phase == .body;
        if (client_closing != run.server.should_close()) return error.CloseUnexpected;
        if (!run.server.should_close()) return;
        const closed = run.client.transport_closed();
        if (closed.ended_body) run.finish_reading();
        if (closed.incomplete) return error.CloseUnexpected;
        if (closed.unanswered != run.sent - run.answered) return error.CloseUnexpected;
    }

    /// The trace: each answered exchange as both sides read it, then the count.
    pub fn write_summary(run: *const Run, trace: *Trace) Error!void {
        for (0..run.answered) |index| {
            const exchange = &run.plan.exchanges[index];
            const request = run.request_seen[index];
            const response = run.response_seen[index];
            try check_seen(run.plan, index, request, response);
            var line = try trace.record("exchange");
            try line.number("index", index);
            try line.number("status", response.status);
            try line.number("request_len", request.len);
            try line.number("request_crc32", request.crc32.final());
            try line.number("response_len", response.len);
            try line.number("response_crc32", response.crc32.final());
            try line.word("method", exchange.method);
            try trace.write(&line);
        }
        var line = try trace.record("answered");
        try line.number("count", run.answered);
        try trace.write(&line);
    }
};

/// Both bodies of exchange `index` are the plan's, and so is the status.
fn check_seen(plan: *const Plan, index: usize, request: Seen, response: Seen) Error!void {
    const exchange = &plan.exchanges[index];
    const request_octets = plan.request_octets[index][0..exchange.request_len];
    if (request.len != exchange.request_len or request.crc32.final() != std.hash.Crc32.hash(request_octets)) return error.ExchangeDiffers;
    if (response.status != exchange.status) return error.ExchangeDiffers;
    const has_body = h11_exchange_plan.response_has_body(exchange.method, exchange.status);
    const response_octets: []const u8 = if (has_body) plan.response_octets[index][0..exchange.response_len] else &.{};
    if (response.len != response_octets.len or response.crc32.final() != std.hash.Crc32.hash(response_octets)) return error.ExchangeDiffers;
    if (request.trailers != trailers_of(exchange.request_body)) return error.ExchangeDiffers;
    const response_trailers = if (has_body) trailers_of(exchange.response_body) else 0;
    if (response.trailers != response_trailers) return error.ExchangeDiffers;
}

/// The trailer fields a body of `kind` ends with.
fn trailers_of(kind: BodyKind) u32 {
    return if (kind == .chunked) 1 else 0;
}

/// The framing field a body of `kind` declares into `fields`, and how many it wrote.
fn framing(kind: BodyKind, len: u32, digits: []u8, fields: []Field) usize {
    switch (kind) {
        .none, .close_delimited => return 0,
        .fixed => {
            const text = std.fmt.bufPrint(digits, "{d}", .{len}) catch unreachable;
            fields[0] = .{ .name = "Content-Length", .value = text };
        },
        .chunked => fields[0] = .{ .name = "Transfer-Encoding", .value = "chunked" },
    }
    return 1;
}

/// Writes `octets` as a body of `kind`, a chunked one in two chunks with a trailer, then ends it.
fn write_body(target: *Connection, stream: *Stream, kind: BodyKind, octets: []const u8) Error!void {
    if (kind == .none) return;
    if (kind == .chunked and octets.len >= chunks_per_body) {
        const first = octets.len / chunks_per_body;
        stream.written += try target.write_body(stream.free(), octets[0..first]);
        stream.written += try target.write_body(stream.free(), octets[first..]);
    } else if (octets.len > 0) {
        stream.written += try target.write_body(stream.free(), octets);
    }
    const trailers: []const Field = if (kind == .chunked) &.{trailer} else &.{};
    stream.written += try target.write_end(stream.free(), trailers);
}
