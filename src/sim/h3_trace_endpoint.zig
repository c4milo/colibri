//! One endpoint of the h3 trace run (https://github.com/c4milo/colibri/issues/58): step 9e's QUIC
//! endpoint with an h3 connection over it, acting as `spec/tla/h3_connection`'s client or server.
//!
//! The client opens each request from the step the plan names, until a GOAWAY arrives, and cancels
//! the ones the plan names that have not ended. Each request is a HEADERS frame and the plan's DATA
//! frames, and its one regular line is the only one QPACK may insert. The server answers a request
//! once it has read all of it, and sends each GOAWAY from the step the plan names. Every frame
//! either side writes is kept whole, so the stream provider answers any offset (decision 79).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const h3 = @import("h3");
const h3_trace_plan = @import("h3_trace_plan.zig");
const quic_endpoint = @import("quic_endpoint.zig");

const Writer = quic.core.Writer;
const FieldSection = h3.http.FieldSection;
const Indexing = h3.qpack.encoder.Indexing;
const Plan = h3_trace_plan.Plan;
const constants = sim.constants;

pub const Error = quic_endpoint.Error || h3.connection.SendError || h3.http.field_section.AppendError || error{
    /// An event the model's endpoints never read: content or trailers in a response, an interim
    /// response, a refusal, or a reset whose code is not the model's.
    UnexpectedEvent,
};

/// How a request ended, as the client saw it: the model's `outcome`.
pub const Outcome = enum { none, response, rejected, cancelled };

/// What the server read of one request.
pub const Read = struct {
    /// The request's header section went to the application (RFC 9114 §4.1.1).
    head: bool = false,
    content_len: u64 = 0,
    ended: bool = false,
    /// The client's reset was read.
    reset: bool = false,
    answered: bool = false,
};

/// The frames one stream carries from this endpoint, kept whole.
const Kept = struct {
    octets: [constants.h3_trace_prefix_len_max]u8 = undefined,
    len: usize = 0,
};

/// Every window is wider than the plan could fill, so flow control never binds (see the plan on
/// https://github.com/c4milo/colibri/issues/58).
const stream_window: u64 = 65_536;
const connection_window: u64 = 1_048_576;
const idle_timeout_ms: u64 = 60_000;
const authority = "sim.example";
/// The ID step between a client's bidirectional streams (RFC 9000 §2.1).
pub const request_stream_step: u64 = 4;
/// The octets of the longest path or line value: a letter and an index.
const value_len_max: usize = 8;
/// The four pseudo-header fields of a request (RFC 9114 §4.3.1).
const pseudo_lines: usize = 4;
/// The one regular line a request may carry, the one QPACK may insert.
const trace_line_name = "x-trace";

pub const Endpoint = struct {
    transport: quic_endpoint.Endpoint,
    h3: h3.Connection,
    plan: *const Plan,
    started: bool,
    /// At a client, the requests opened and how each ended.
    opened: u32,
    outcome: [constants.h3_trace_requests_max]Outcome,
    /// At a server, what it read of each request and the GOAWAY frames it sent.
    read: [constants.h3_trace_requests_max]Read,
    goaways_sent: u32,
    kept: [constants.h3_trace_requests_max]Kept,
    section: FieldSection,
    body: [constants.h3_trace_prefix_len_max]u8,

    pub fn init(endpoint: *Endpoint, role: quic.connection.Role, plan: *const Plan, now_ns: u64) void {
        endpoint.transport.init_with(role, now_ns, parameters());
        endpoint.h3.init(if (role == .client) client_options(plan) else server_options(plan));
        endpoint.transport.application = endpoint.h3.provider(.{ .context = endpoint, .vtable = &kept_vtable });
        endpoint.plan = plan;
        endpoint.started = false;
        endpoint.opened = 0;
        endpoint.outcome = @splat(.none);
        endpoint.read = @splat(.{});
        endpoint.goaways_sent = 0;
        endpoint.kept = @splat(.{});
    }

    pub fn is_client(endpoint: *const Endpoint) bool {
        return endpoint.transport.connection.role == .client;
    }

    /// What a caller does after `quic` took the step's datagrams: start h3, act on the plan at
    /// step `at`, and read every event.
    pub fn step(endpoint: *Endpoint, at: u64) Error!void {
        if (!endpoint.started) {
            if (!endpoint.transport.connection.handshake_complete) return;
            try endpoint.h3.start(&endpoint.transport.connection);
            endpoint.started = true;
        }
        if (endpoint.is_client()) {
            try endpoint.open_requests(at);
            endpoint.cancel_requests(at);
        } else try endpoint.send_goaways(at);
        // Bounded: every event reads at least one frame the peer sent, and a step's datagrams
        // carry at most this many.
        for (0..constants.h3_trace_steps_max) |_| {
            const event = try endpoint.h3.receive(&endpoint.transport.connection, &endpoint.body) orelse return;
            if (endpoint.is_client()) try endpoint.on_client_event(event) else try endpoint.on_server_event(event);
        }
    }

    /// Whether the client is done: every request it could open has ended, and it opens no more.
    pub fn finished(endpoint: *const Endpoint) bool {
        assert(endpoint.is_client());
        const stopped = endpoint.opened == endpoint.plan.requests or endpoint.h3.goaway_received != null;
        if (!stopped) return false;
        for (endpoint.outcome[0..endpoint.opened]) |outcome| {
            if (outcome == .none) return false;
        }
        return true;
    }

    fn open_requests(endpoint: *Endpoint, at: u64) Error!void {
        // Bounded by the plan's requests.
        while (endpoint.opened < endpoint.plan.requests and endpoint.plan.open_at[endpoint.opened] <= at) {
            const r = endpoint.opened;
            const kept = &endpoint.kept[r];
            var writer = Writer.init(&kept.octets);
            var path: [value_len_max]u8 = undefined;
            var value: [value_len_max]u8 = undefined;
            endpoint.section.init();
            try endpoint.section.append(":method", if (endpoint.plan.content > 0) "POST" else "GET");
            try endpoint.section.append(":scheme", "https");
            try endpoint.section.append(":authority", authority);
            try endpoint.section.append(":path", std.fmt.bufPrint(&path, "/t{d}", .{r}) catch unreachable);
            // Only the regular line may go into the dynamic table: the model's client writes at
            // most one insert with each request (RFC 9204 §3.2).
            var indexing: [pseudo_lines + 1]Indexing = @splat(.no_insert);
            if (line_value(endpoint.plan, r, &value)) |held| {
                try endpoint.section.append(trace_line_name, held);
                indexing[pseudo_lines] = .may_insert;
            }
            const lines = endpoint.section.len();
            const id = endpoint.h3.write_request(&endpoint.transport.connection, &endpoint.section, indexing[0..lines], &writer) catch |failure| switch (failure) {
                // RFC 9114 §5.2: no request opens after the server's GOAWAY.
                error.GoawayReceived => return,
                else => return failure,
            };
            assert(id == r * request_stream_step);
            try write_content(endpoint.plan.content, &writer);
            kept.len = writer.written().len;
            try quic.connection_stream_send.supply(&endpoint.transport.connection, .{ .value = id }, kept.len, true);
            endpoint.opened += 1;
        }
    }

    /// RFC 9114 §4.1.1: the client cancels a request that has not ended by resetting its stream.
    fn cancel_requests(endpoint: *Endpoint, at: u64) void {
        for (endpoint.outcome[0..endpoint.opened], 0..) |*outcome, r| {
            const due = endpoint.plan.cancel_at[r] orelse continue;
            if (due > at or outcome.* != .none) continue;
            endpoint.h3.cancel(&endpoint.transport.connection, r * request_stream_step, h3.constants.error_request_cancelled);
            outcome.* = .cancelled;
        }
    }

    fn send_goaways(endpoint: *Endpoint, at: u64) Error!void {
        // Bounded by the plan's GOAWAY frames.
        while (endpoint.goaways_sent < endpoint.plan.goaways and endpoint.plan.goaway_at[endpoint.goaways_sent] <= at) {
            try endpoint.h3.shutdown(&endpoint.transport.connection);
            endpoint.goaways_sent += 1;
        }
    }

    fn on_client_event(endpoint: *Endpoint, event: h3.connection.Event) Error!void {
        switch (event) {
            .settings, .goaway => {},
            // The model's server answers with a final response and nothing else.
            .response => |held| if (held.response.status.is_interim()) return error.UnexpectedEvent,
            .end => |id| endpoint.settle(id, .response),
            // RFC 9114 §4.1.1: a request the server refused after its GOAWAY is rejected.
            .reset => |held| {
                if (held.error_code != h3.constants.error_request_rejected) return error.UnexpectedEvent;
                endpoint.settle(held.stream_id, .rejected);
            },
            .request, .data, .trailers, .refused => return error.UnexpectedEvent,
        }
    }

    /// Records how a request ended, unless it had already: a cancelled one reports nothing more.
    fn settle(endpoint: *Endpoint, id: u64, outcome: Outcome) void {
        const held = &endpoint.outcome[index_of(id)];
        if (held.* == .none) held.* = outcome;
    }

    fn on_server_event(endpoint: *Endpoint, event: h3.connection.Event) Error!void {
        switch (event) {
            .settings => {},
            .request => |held| endpoint.read[index_of(held.stream_id)].head = true,
            .data => |held| endpoint.read[index_of(held.stream_id)].content_len += held.octets.len,
            .end => |id| try endpoint.respond(id),
            .reset => |held| endpoint.read[index_of(held.stream_id)].reset = true,
            .response, .trailers, .refused, .goaway => return error.UnexpectedEvent,
        }
    }

    /// Answers a request the server has read to its end with a final response and no content.
    fn respond(endpoint: *Endpoint, id: u64) Error!void {
        const r = index_of(id);
        endpoint.read[r].ended = true;
        const kept = &endpoint.kept[r];
        var writer = Writer.init(&kept.octets);
        endpoint.section.init();
        try endpoint.section.append(":status", "200");
        try endpoint.h3.write_response(&endpoint.transport.connection, id, &endpoint.section, &.{.no_insert}, &writer);
        kept.len = writer.written().len;
        quic.connection_stream_send.supply(&endpoint.transport.connection, .{ .value = id }, kept.len, true) catch |failure| switch (failure) {
            // RFC 9000 §3.5: the client cancelled a request it had sent whole, and its
            // STOP_SENDING reset the server's side before the answer, so nothing goes out.
            error.NotWritable => return,
            else => return failure,
        };
        endpoint.read[r].answered = true;
    }
};

/// The value of request `r`'s regular line, or null when it carries none. A repeated line is the
/// last new one's, so the encoder can reference the entry it inserted.
fn line_value(plan: *const Plan, r: usize, value: *[value_len_max]u8) ?[]const u8 {
    const source = switch (plan.lines[r]) {
        .none => return null,
        .new => r,
        .repeat => plan.last_new(r).?,
    };
    return std.fmt.bufPrint(value, "v{d}", .{source}) catch unreachable;
}

/// Writes `count` DATA frames, each carrying `h3_trace_data_len` octets.
fn write_content(count: u32, writer: *Writer) Error!void {
    const payload: [constants.h3_trace_data_len]u8 = @splat(content_octet);
    for (0..count) |_| {
        try h3.connection.write_data_header(payload.len, writer);
        try writer.write_bytes(&payload);
    }
}

/// The octet every DATA frame's payload is made of.
const content_octet: u8 = 0x74;

/// The request a client's stream carries: the client opens one per request, in order.
pub fn index_of(id: u64) usize {
    assert(id % request_stream_step == 0);
    return @intCast(id / request_stream_step);
}

/// The client's decoder allows no dynamic table, so QPACK runs from the client to the server
/// alone, as in the model.
fn client_options(plan: *const Plan) h3.connection.Options {
    return .{ .role = .client, .qpack = .{ .max_table_capacity = 0, .blocked_streams = 0 }, .grease = plan.client_grease };
}

fn server_options(plan: *const Plan) h3.connection.Options {
    return .{ .role = .server, .qpack = plan.server_decoder, .grease = plan.server_grease };
}

fn parameters() quic.transport_parameters.Parameters {
    var held = quic.transport_parameters.Parameters.initial();
    held.initial_max_data = connection_window;
    held.initial_max_stream_data_bidi_local = stream_window;
    held.initial_max_stream_data_bidi_remote = stream_window;
    held.initial_max_stream_data_uni = stream_window;
    held.initial_max_streams_bidi = constants.h3_trace_requests_max;
    held.initial_max_streams_uni = h3.constants.uni_streams_max;
    held.max_idle_timeout_ms = idle_timeout_ms;
    return held;
}

const kept_vtable: quic.stream.stream_provider.VTable = .{ .read = read_kept };

/// A request stream's octets from `offset`: the frames the endpoint kept. Every call at one
/// offset answers the same octets (RFC 9000 §2.2).
fn read_kept(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const endpoint: *const Endpoint = @ptrCast(@alignCast(context));
    const kept = &endpoint.kept[index_of(stream_id)];
    if (offset >= kept.len) return 0;
    const from: usize = @intCast(offset);
    const len = @min(output.len, kept.len - from);
    @memcpy(output[0..len], kept.octets[from..][0..len]);
    return len;
}
