//! One endpoint of the h3 check (design §8 step 12): the QUIC endpoint of step 9e with an h3
//! connection over it, and the part of a caller around them.
//!
//! The caller keeps each request stream's frames (decision 79) and makes its content from the
//! offset, as a file server reads a file (decision 57). It hands `quic` h3's stream provider,
//! which answers h3's own streams and passes the rest to the caller's. It starts h3 once the
//! handshake completes (RFC 9114 §7.2.4.2).
//!
//! A client sends its first request at once, on the defaults, and the rest once the server's
//! SETTINGS arrived, in rounds of `h3_check_round_len`: a round goes out once every response of
//! the one before it has ended. A server answers each request once it has read all of it. Both
//! check every field section and content octet they read against the plan, and read no event the
//! plan does not produce.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const h3 = @import("h3");
const h3_plan = @import("h3_plan.zig");
const quic_endpoint = @import("quic_endpoint.zig");

const Writer = quic.core.Writer;
const FieldSection = h3.http.FieldSection;
const Plan = h3_plan.Plan;
const constants = sim.constants;

pub const Error = quic_endpoint.Error || h3.connection.SendError || h3.http.field_section.AppendError || error{
    /// A field section, content octet, trailer section or end differed from the plan's.
    MessageMismatch,
    /// An event the plan does not produce: a reset, a refusal or a GOAWAY.
    UnexpectedEvent,
};

/// What one endpoint read of one exchange's message from its peer.
const Progress = struct {
    head: bool = false,
    interim: bool = false,
    content_len: u64 = 0,
    trailers: bool = false,
    ended: bool = false,
};

/// What the caller keeps of the message it sends on one request stream (decision 79): the frames
/// before its content, the content's length, and the frames after it.
const Kept = struct {
    prefix: [constants.h3_check_prefix_len_max]u8 = undefined,
    prefix_len: usize = 0,
    content_len: u64 = 0,
    suffix: [constants.h3_check_suffix_len_max]u8 = undefined,
    suffix_len: usize = 0,

    fn len(kept: *const Kept) u64 {
        return kept.prefix_len + kept.content_len + kept.suffix_len;
    }
};

/// What each endpoint grants its peer (RFC 9000 §18.2): every exchange's request stream, h3's
/// unidirectional streams, and windows the plan's messages fit.
const stream_window: u64 = 65_536;
const connection_window: u64 = 1_048_576;
const idle_timeout_ms: u64 = 60_000;
/// The rounds of request streams each server grants at once (RFC 9000 §18.2).
const rounds_granted: u64 = 2;
/// Where every request goes.
const authority = "sim.example";
/// The octets of the longest path, `/e` and an exchange's index.
const path_len_max: usize = 8;

comptime {
    // An index of at most six digits fits after `/e`.
    assert(constants.h3_long_check_exchanges_max < 1_000_000);
}
/// The ID step between a client's bidirectional streams (RFC 9000 §2.1).
const request_stream_step: u64 = 4;

pub const Endpoint = struct {
    transport: quic_endpoint.Endpoint,
    h3: h3.Connection,
    plan: *const Plan,
    started: bool,
    /// At a client, the exchanges whose request went out.
    requests_sent: u32,
    /// At a client, the exchanges whose response ended.
    responses_ended: u32,
    progress: [constants.h3_long_check_exchanges_max]Progress,
    kept: [constants.h3_long_check_exchanges_max]Kept,
    body: [constants.h3_check_content_len_max]u8,
    section: FieldSection,
    expected: FieldSection,

    pub fn init(endpoint: *Endpoint, role: quic.connection.Role, plan: *const Plan, now_ns: u64) void {
        endpoint.transport.init_with(role, now_ns, parameters());
        endpoint.h3.init(if (role == .client) plan.client else plan.server);
        endpoint.transport.application = endpoint.h3.provider(.{ .context = endpoint, .vtable = &kept_vtable });
        endpoint.plan = plan;
        endpoint.started = false;
        endpoint.requests_sent = 0;
        endpoint.responses_ended = 0;
        endpoint.progress = @splat(.{});
        endpoint.kept = @splat(.{});
    }

    fn is_client(endpoint: *const Endpoint) bool {
        return endpoint.transport.connection.role == .client;
    }

    /// What a caller does after `quic` took the step's datagrams: start h3, send what the plan
    /// sends now, and read every event.
    pub fn step(endpoint: *Endpoint) Error!void {
        if (!endpoint.started) {
            if (!endpoint.transport.connection.handshake_complete) return;
            try endpoint.h3.start(&endpoint.transport.connection);
            endpoint.started = true;
        }
        if (endpoint.is_client()) try endpoint.send_requests();
        // Bounded: every event reads at least one frame or content octet the peer sent, and a
        // step's datagrams carry at most this many of either.
        for (0..constants.h3_check_steps_max) |_| {
            const event = try endpoint.h3.receive(&endpoint.transport.connection, &endpoint.body) orelse return;
            try endpoint.on_event(event);
        }
    }

    /// Whether the client has read every response to its end.
    pub fn finished(endpoint: *const Endpoint) bool {
        for (endpoint.progress[0..endpoint.plan.len]) |held| {
            if (!held.ended) return false;
        }
        return true;
    }

    /// The exchanges the client may have sent by now: the first on the defaults, and after the
    /// server's SETTINGS every round whose previous rounds' responses have ended.
    fn requests_allowed(endpoint: *const Endpoint) u32 {
        // RFC 9114 §7.2.4.2: a client need not wait for SETTINGS, and the first request does not.
        if (endpoint.h3.peer_settings == null) return 1;
        const round_len = constants.h3_check_round_len;
        const rounds_ended = endpoint.responses_ended / round_len;
        return @min(endpoint.plan.len, (rounds_ended + 1) * round_len);
    }

    fn send_requests(endpoint: *Endpoint) Error!void {
        const allowed = endpoint.requests_allowed();
        // Bounded by the plan's exchanges.
        while (endpoint.requests_sent < allowed) {
            const index = endpoint.requests_sent;
            const kept = &endpoint.kept[index];
            var writer = Writer.init(&kept.prefix);
            const section = try endpoint.request_section(&endpoint.section, index);
            const id = endpoint.h3.write_request(&endpoint.transport.connection, section, &.{}, &writer) catch |failure| switch (failure) {
                // RFC 9000 §4.6: the server has not raised its stream limit yet, so the client
                // waits for its MAX_STREAMS frame. Nothing was written.
                error.StreamsExhausted => return,
                else => return failure,
            };
            assert(id == index * request_stream_step);
            try endpoint.write_message(id, &endpoint.plan.exchanges[index].request, kept, &writer);
            endpoint.requests_sent += 1;
        }
    }

    /// Answers exchange `index`, whose request the server has read to its end.
    fn respond(endpoint: *Endpoint, id: u64, index: u32) Error!void {
        const exchange = &endpoint.plan.exchanges[index];
        const kept = &endpoint.kept[index];
        var writer = Writer.init(&kept.prefix);
        const connection = &endpoint.transport.connection;
        if (exchange.interim) {
            try endpoint.h3.write_response(connection, id, try status_section(&endpoint.section, h3_plan.interim_status), &.{}, &writer);
        }
        try endpoint.h3.write_response(connection, id, try endpoint.response_section(&endpoint.section, index), &.{}, &writer);
        try endpoint.write_message(id, &exchange.response, kept, &writer);
    }

    /// Writes a message's DATA frame header after its header section, keeps its trailer section
    /// apart, and ends the stream after both (RFC 9114 §4.1). `prefix` wrote the header section.
    fn write_message(endpoint: *Endpoint, id: u64, message: *const h3_plan.Message, kept: *Kept, prefix: *Writer) Error!void {
        if (message.content_len > 0) try h3.connection.write_data_header(message.content_len, prefix);
        kept.prefix_len = prefix.written().len;
        kept.content_len = message.content_len;
        kept.suffix_len = 0;
        if (message.trailers) {
            var suffix = Writer.init(&kept.suffix);
            endpoint.section.init();
            try endpoint.section.append(h3_plan.trailer_line.name, h3_plan.trailer_line.value);
            try endpoint.h3.write_trailers(&endpoint.transport.connection, id, &endpoint.section, &suffix);
            kept.suffix_len = suffix.written().len;
        }
        try quic.connection_stream_send.supply(&endpoint.transport.connection, .{ .value = id }, kept.len(), true);
    }

    fn on_event(endpoint: *Endpoint, event: h3.connection.Event) Error!void {
        switch (event) {
            .settings => {},
            .request => |held| try endpoint.on_head(held.stream_id, try endpoint.request_section(&endpoint.expected, index_of(held.stream_id))),
            .response => |held| try endpoint.on_response(held.stream_id, held.response),
            .data => |held| try endpoint.on_data(held.stream_id, held.octets),
            .trailers => |id| try endpoint.on_trailers(id),
            .end => |id| try endpoint.on_end(id),
            .reset, .refused, .goaway => return error.UnexpectedEvent,
        }
    }

    fn on_response(endpoint: *Endpoint, id: u64, response: h3.message.Response) Error!void {
        const index = index_of(id);
        if (response.status.is_interim()) {
            const progress = &endpoint.progress[index];
            if (!endpoint.plan.exchanges[index].interim or progress.interim) return error.MessageMismatch;
            progress.interim = true;
            return expect_section(endpoint.h3.field_section(), try status_section(&endpoint.expected, h3_plan.interim_status));
        }
        return endpoint.on_head(id, try endpoint.response_section(&endpoint.expected, index));
    }

    fn on_head(endpoint: *Endpoint, id: u64, expected: *const FieldSection) Error!void {
        const progress = &endpoint.progress[index_of(id)];
        if (progress.head) return error.MessageMismatch;
        progress.head = true;
        try expect_section(endpoint.h3.field_section(), expected);
    }

    fn on_data(endpoint: *Endpoint, id: u64, octets: []const u8) Error!void {
        const index = index_of(id);
        const progress = &endpoint.progress[index];
        const direction = endpoint.incoming_direction();
        // Bounded by what one event carried.
        for (octets, 0..) |octet, offset| {
            if (octet != h3_plan.content_octet(index, direction, progress.content_len + offset)) return error.MessageMismatch;
        }
        progress.content_len += octets.len;
    }

    fn on_trailers(endpoint: *Endpoint, id: u64) Error!void {
        const progress = &endpoint.progress[index_of(id)];
        progress.trailers = true;
        endpoint.expected.init();
        try endpoint.expected.append(h3_plan.trailer_line.name, h3_plan.trailer_line.value);
        try expect_section(endpoint.h3.field_section(), &endpoint.expected);
    }

    fn on_end(endpoint: *Endpoint, id: u64) Error!void {
        const index = index_of(id);
        const progress = &endpoint.progress[index];
        const exchange = &endpoint.plan.exchanges[index];
        const message = if (endpoint.is_client()) &exchange.response else &exchange.request;
        if (!progress.head or progress.ended) return error.MessageMismatch;
        if (progress.content_len != message.content_len or progress.trailers != message.trailers) return error.MessageMismatch;
        if (endpoint.is_client() and progress.interim != exchange.interim) return error.MessageMismatch;
        progress.ended = true;
        if (endpoint.is_client()) {
            endpoint.responses_ended += 1;
        } else {
            try endpoint.respond(id, index);
        }
    }

    /// Which way the messages this endpoint reads travel.
    fn incoming_direction(endpoint: *const Endpoint) h3_plan.Direction {
        return if (endpoint.is_client()) .response else .request;
    }

    /// The request of exchange `index`: its pseudo-header fields, its lines, and a content-length
    /// when it has content (RFC 9114 §4.3.1).
    fn request_section(endpoint: *const Endpoint, section: *FieldSection, index: u32) Error!*const FieldSection {
        const message = &endpoint.plan.exchanges[index].request;
        section.init();
        try section.append(":method", if (message.content_len > 0) "POST" else "GET");
        try section.append(":scheme", "https");
        try section.append(":authority", authority);
        var path: [path_len_max]u8 = undefined;
        try section.append(":path", std.fmt.bufPrint(&path, "/e{d}", .{index}) catch unreachable);
        try append_message(section, message);
        return section;
    }

    /// The final response of exchange `index` (RFC 9114 §4.3.2).
    fn response_section(endpoint: *const Endpoint, section: *FieldSection, index: u32) Error!*const FieldSection {
        const exchange = &endpoint.plan.exchanges[index];
        section.init();
        try section.append(":status", exchange.status);
        try append_message(section, &exchange.response);
        return section;
    }
};

fn status_section(section: *FieldSection, status: []const u8) Error!*const FieldSection {
    section.init();
    try section.append(":status", status);
    return section;
}

fn append_message(section: *FieldSection, message: *const h3_plan.Message) Error!void {
    for (message.regular()) |line| try section.append(line.name, line.value);
    if (message.content_len == 0) return;
    var digits: [content_length_digits_max]u8 = undefined;
    try section.append("content-length", std.fmt.bufPrint(&digits, "{d}", .{message.content_len}) catch unreachable);
}

/// The digits of the longest content-length the plan draws.
const content_length_digits_max: usize = 8;

fn expect_section(got: *const FieldSection, expected: *const FieldSection) Error!void {
    if (got.len() != expected.len()) return error.MessageMismatch;
    for (0..got.len()) |at| {
        const index: u32 = @intCast(at);
        const found = got.get(index);
        const wanted = expected.get(index);
        if (!std.mem.eql(u8, found.name, wanted.name) or !std.mem.eql(u8, found.value, wanted.value)) return error.MessageMismatch;
    }
}

/// The exchange a client's request stream carries: the client opens one per exchange, in order.
fn index_of(id: u64) u32 {
    assert(id % request_stream_step == 0);
    return @intCast(id / request_stream_step);
}

fn parameters() quic.transport_parameters.Parameters {
    var held = quic.transport_parameters.Parameters.initial();
    held.initial_max_data = connection_window;
    held.initial_max_stream_data_bidi_local = stream_window;
    held.initial_max_stream_data_bidi_remote = stream_window;
    held.initial_max_stream_data_uni = stream_window;
    // Two rounds at once, so a long run's client waits on MAX_STREAMS (RFC 9000 §4.6).
    held.initial_max_streams_bidi = rounds_granted * constants.h3_check_round_len;
    held.initial_max_streams_uni = h3.constants.uni_streams_max;
    held.max_idle_timeout_ms = idle_timeout_ms;
    return held;
}

const kept_vtable: quic.stream.stream_provider.VTable = .{ .read = read_kept };

/// A request stream's octets from `offset`: the frames the caller kept, and the content made from
/// its offset between them. Every call at one offset answers the same octets (RFC 9000 §2.2).
fn read_kept(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const endpoint: *const Endpoint = @ptrCast(@alignCast(context));
    const index = index_of(stream_id);
    const kept = &endpoint.kept[index];
    const direction: h3_plan.Direction = if (endpoint.is_client()) .request else .response;
    var at = offset;
    var written: usize = 0;
    // Bounded: each pass writes to the end of one of the three parts or of `output`.
    for (0..kept_parts) |_| {
        if (written == output.len or at >= kept.len()) break;
        const len = read_part(kept, index, direction, at, output[written..]);
        written += len;
        at += len;
    }
    return written;
}

/// The frames before the content, the content, and the frames after it.
const kept_parts: usize = 3;

/// Writes from `at` to the end of the part `at` falls in, as much as fits.
fn read_part(kept: *const Kept, index: u32, direction: h3_plan.Direction, at: u64, output: []u8) usize {
    if (at < kept.prefix_len) {
        const from: usize = @intCast(at);
        const len = @min(output.len, kept.prefix_len - from);
        @memcpy(output[0..len], kept.prefix[from..][0..len]);
        return len;
    }
    const content_end = kept.prefix_len + kept.content_len;
    if (at < content_end) {
        const len: usize = @intCast(@min(output.len, content_end - at));
        for (output[0..len], 0..) |*octet, step| octet.* = h3_plan.content_octet(index, direction, at - kept.prefix_len + step);
        return len;
    }
    const from: usize = @intCast(at - content_end);
    const len = @min(output.len, kept.suffix_len - from);
    @memcpy(output[0..len], kept.suffix[from..][0..len]);
    return len;
}
