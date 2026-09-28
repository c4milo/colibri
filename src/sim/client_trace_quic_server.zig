//! The QUIC server of the client trace run (decision 105): h3 over `quic`, with its handshake run
//! through `tls.quic.Server` over the identity in `testdata/`. It answers each request as the
//! seed's plan says: it responds, rejects it unprocessed, or resets it after processing it, and
//! it may send the seed's GOAWAY (RFC 9114 §5.2). Each QUIC connection the origin opens meets a
//! fresh server, which starts from the connection's first Initial (RFC 9000 §7.2).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const sim = @import("sim");
const plan_module = @import("client_trace_plan.zig");
const ledger_module = @import("client_trace_ledger.zig");
const identity = @import("client_trace_identity.zig");

const limits = sim.constants.client_trace;
const Plan = plan_module.Plan;
const Ledger = ledger_module.Ledger;

/// Octets of the server's connection IDs, and of what it keeps of a request stream: its
/// response's frames before the content.
const id_len: usize = 8;
const server_id_octet: u8 = 0x5e;
const prefix_len_max: usize = 1024;
const parameters_len_max: usize = 1024;
const body_len: usize = 16_384;
const status_digits_len: usize = 3;
const length_digits_max: usize = 20;
const ok_status: u16 = 200;
/// What the server grants the client (RFC 9000 §18.2).
const window: u64 = 1_048_576;
const stream_window: u64 = 262_144;
const idle_timeout_ms: u64 = 30_000;
/// Requests one connection's server reads at most: every exchange of a seed.
const requests_max: usize = limits.exchanges_max;

const server_id: [id_len]u8 = @splat(server_id_octet);

/// One request the server read, and what it does with it.
const Request = struct {
    stream_id: u64,
    exchange: usize,
    answer: plan_module.Answer,
    /// The request's end arrived, the instant the server acts on it, and whether it has.
    ended: bool = false,
    due_ns: u64,
    acted: bool = false,
    prefix: [prefix_len_max]u8 = undefined,
    prefix_len: usize = 0,
    content: []const u8 = "",
};

pub const QuicServer = struct {
    config: tls.quic.ServerConfig,
    connection: quic.Connection,
    session: tls.quic.Server,
    send_scratch: quic.connection_send.DefaultScratch,
    scratch: quic.connection_datagram.Scratch,
    pool: quic.stream.stream_incoming.DefaultPool,
    h3: h3.Connection,
    section: h3.http.FieldSection,
    body: [body_len]u8,
    original_id: [id_len]u8,
    peer_id: [id_len]u8,
    requests: [requests_max]Request,
    requests_len: usize,
    /// Which of the run's connections this server serves, whether it has started and runs h3.
    generation: u64,
    started: bool,
    h3_started: bool,

    /// Prepares the server's TLS configuration for a seed: its ALPN names h3 unless the plan has
    /// QUIC refused.
    pub fn configure(server: *QuicServer, plan: *const Plan) !void {
        const protocols: []const []const u8 = if (plan.quic == .refused) &alpn_other else &alpn_h3;
        try server.config.init(.{
            .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
            .cookie_key = &identity.cookie_key,
            .ticket_key = null,
            .alpn = protocols,
        });
    }

    /// A fresh server for the run's connection `generation`, which starts at the first datagram.
    pub fn reset(server: *QuicServer, generation: u64) void {
        server.generation = generation;
        server.started = false;
        server.h3_started = false;
        server.requests_len = 0;
    }

    /// Takes one datagram the client sent at `now_ns`: the first starts the connection.
    pub fn receive(server: *QuicServer, octets: []u8, random: tls.Random, now_ns: u64) !void {
        if (!server.started) try server.start(octets, random, now_ns);
        _ = quic.connection_datagram.receive(&server.connection, server.session.suite(), server.session.provider(), .{ .octets = octets, .now_ns = now_ns, .ecn = .not_ect }, &server.scratch) catch return;
    }

    /// Reads what h3 has, and acts on each request that is due, as the plan says.
    pub fn serve(server: *QuicServer, plan: *const Plan, ledger: *Ledger, now_ns: u64) !void {
        if (!server.started) return;
        if (!server.h3_started and server.connection.handshake_complete) {
            server.h3.init(.{ .role = .server });
            try server.h3.start(&server.connection, now_ns);
            server.h3_started = true;
        }
        if (!server.h3_started) return;
        try server.read(plan, ledger, now_ns);
        try server.act(plan, now_ns);
    }

    /// Sends the seed's GOAWAY (RFC 9114 §5.2), which names the first request stream the server
    /// has not taken.
    pub fn send_goaway(server: *QuicServer, ledger: *Ledger, now_ns: u64) !bool {
        if (!server.h3_started or server.connection.termination.state != .active) return false;
        try server.h3.shutdown(&server.connection, now_ns);
        ledger.goaways += 1;
        return true;
    }

    /// Closes the connection with an error, as a server that failed does (RFC 9000 §10.2).
    pub fn close_with_error(server: *QuicServer) void {
        if (server.connection.termination.state != .active) return;
        quic.connection_close.owe(&server.connection, .{ .layer = .application, .error_code = h3.constants.error_internal, .frame_type = null, .reason = "" });
    }

    /// Writes the next datagram the server owes into `output`, and returns its length, or null.
    pub fn send(server: *QuicServer, output: []u8, now_ns: u64) ?usize {
        if (!server.started) return null;
        const provider = server.h3.provider(.{ .context = server, .vtable = &vtable });
        const sent = quic.connection_send.send(&server.connection, server.session.suite(), server.session.provider(), provider, &server.send_scratch, output, now_ns) catch return null;
        const held = sent orelse return null;
        return held.len;
    }

    /// The instant the server next wants `on_instant` at, or null.
    pub fn deadline_ns(server: *QuicServer) ?u64 {
        if (!server.started) return null;
        const deadline = quic.connection_timer.next(&server.connection) orelse return null;
        return deadline.at_ns;
    }

    pub fn on_instant(server: *QuicServer, now_ns: u64) void {
        if (!server.started) return;
        _ = quic.connection_timer.on_instant(&server.connection, server.session.suite(), &server.scratch.recovery, now_ns) catch {};
    }

    /// The instant the next request is due, or null. A request whose answer waits for its end is
    /// not due until the end arrives.
    pub fn due_ns(server: *const QuicServer, plan: *const Plan) ?u64 {
        var earliest: ?u64 = null;
        for (server.requests[0..server.requests_len]) |*request| {
            if (request.acted or request.answer == .reject) continue;
            if (!request.ended and !plan.answer_early) continue;
            earliest = @min(earliest orelse request.due_ns, request.due_ns);
        }
        return earliest;
    }

    fn start(server: *QuicServer, first: []const u8, random: tls.Random, now_ns: u64) !void {
        const parsed = try quic.packet.header.read(first, id_len);
        const long = parsed.long;
        @memcpy(&server.original_id, long.dcid);
        @memcpy(&server.peer_id, long.scid);
        server.connection.init(.{
            .role = .server,
            .local_parameters = parameters(),
            .now_ns = now_ns,
            .identity = .{ .local_initial_source = &server_id, .original_destination = &server.original_id, .peer_initial_source = &server.peer_id },
            .receive = server.pool.storage(),
        });
        server.session.start(&server.config, random, identity.now_seconds);
        server.send_scratch = .{};
        var encoded: [parameters_len_max]u8 = undefined;
        var writer = quic.core.Writer.init(&encoded);
        try quic.transport_parameters.write(&writer, &server.connection.local_parameters, .server);
        try server.session.provider().set_transport_params(writer.written());
        const suite = server.session.suite();
        try suite.vtable.install_initial_keys(suite.context, .server, &server.original_id);
        server.started = true;
    }

    /// Reads every h3 event, noting each request and deciding at its head what to do with it.
    fn read(server: *QuicServer, plan: *const Plan, ledger: *Ledger, now_ns: u64) !void {
        // Bounded: each event reads octets the pool holds or ends a stream.
        for (0..body_len) |_| {
            const read_event = server.h3.receive(&server.connection, &server.body, now_ns) catch return;
            const got = read_event orelse return;
            switch (got) {
                .request => |held| try server.take(held, plan, ledger, now_ns),
                .end => |id| if (server.request_of(id)) |request| {
                    request.ended = true;
                },
                else => {},
            }
        }
    }

    /// A request's head arrived: the server rejects it unprocessed, or processes it and answers
    /// or resets it once due.
    fn take(server: *QuicServer, held: h3.connection.Request, plan: *const Plan, ledger: *Ledger, now_ns: u64) !void {
        const index = ledger_module.exchange_of(held.request.path orelse "") orelse return;
        if (server.requests_len == server.requests.len) return error.TooManyRequests;
        const answer = plan.quic_answers[index];
        server.requests[server.requests_len] = .{ .stream_id = held.stream_id, .exchange = index, .answer = answer, .due_ns = now_ns + plan.answer_delay_ns };
        server.requests_len += 1;
        if (answer == .reject) {
            // RFC 9114 §4.1.1: a request the server rejects is one it did not process.
            server.h3.cancel(&server.connection, held.stream_id, h3.constants.error_request_rejected);
            return;
        }
        ledger.process(index, .{ .transport = .quic, .generation = server.generation });
    }

    /// Answers or resets each processed request that is due: at its instant, and after its end
    /// unless the plan answers early.
    fn act(server: *QuicServer, plan: *const Plan, now_ns: u64) !void {
        for (server.requests[0..server.requests_len]) |*request| {
            if (request.acted or request.answer == .reject or now_ns < request.due_ns) continue;
            if (!request.ended and !plan.answer_early) continue;
            request.acted = true;
            switch (request.answer) {
                .respond => try server.respond(request, now_ns),
                .reset => server.h3.cancel(&server.connection, request.stream_id, h3.constants.error_request_cancelled),
                .reject => unreachable,
            }
        }
    }

    fn respond(server: *QuicServer, request: *Request, now_ns: u64) !void {
        request.content = contents[request.exchange];
        var status_digits: [status_digits_len]u8 = undefined;
        var length_digits: [length_digits_max]u8 = undefined;
        server.section.init();
        try server.section.append(":status", std.fmt.bufPrint(&status_digits, "{d}", .{ok_status}) catch unreachable);
        try server.section.append("content-length", std.fmt.bufPrint(&length_digits, "{d}", .{request.content.len}) catch unreachable);
        var writer = quic.core.Writer.init(&request.prefix);
        try server.h3.write_response(&server.connection, request.stream_id, &server.section, &.{}, &writer, now_ns);
        try server.h3.write_data_header(request.stream_id, request.content.len, &writer, now_ns);
        request.prefix_len = writer.written().len;
        const total = request.prefix_len + request.content.len;
        quic.connection_stream_send.supply(&server.connection, .{ .value = request.stream_id }, total, true) catch |failure| {
            // RFC 9000 §3.5: a stream the client stopped was reset, and takes no response.
            if (failure == error.NotWritable) return;
            return failure;
        };
    }

    fn request_of(server: *QuicServer, stream_id: u64) ?*Request {
        for (server.requests[0..server.requests_len]) |*request| {
            if (request.stream_id == stream_id) return request;
        }
        return null;
    }
};

/// Each exchange's response content, which names it.
pub const contents = [_][]const u8{ "response 0", "response 1", "response 2" };

comptime {
    assert(contents.len == limits.exchanges_max);
}

const alpn_h3 = [_][]const u8{"h3"};
const alpn_other = [_][]const u8{"hq-interop"};

fn parameters() quic.transport_parameters.Parameters {
    var held = quic.transport_parameters.Parameters.initial();
    held.initial_max_data = window;
    held.initial_max_stream_data_bidi_remote = stream_window;
    held.initial_max_stream_data_bidi_local = stream_window;
    held.initial_max_stream_data_uni = stream_window;
    held.initial_max_streams_bidi = requests_max;
    held.initial_max_streams_uni = h3.constants.uni_streams_max;
    held.max_idle_timeout_ms = idle_timeout_ms;
    return held;
}

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_answer };

/// A response stream's octets from `offset`: its kept frames, then its content.
fn read_answer(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const server: *QuicServer = @ptrCast(@alignCast(context));
    const request = server.request_of(stream_id) orelse return 0;
    const from: usize = @intCast(offset);
    const total = request.prefix_len + request.content.len;
    if (from >= total) return 0;
    var written: usize = 0;
    if (from < request.prefix_len) {
        written = @min(output.len, request.prefix_len - from);
        @memcpy(output[0..written], request.prefix[from..][0..written]);
        if (written < request.prefix_len - from) return written;
    }
    const content_from = from + written - request.prefix_len;
    const len = @min(output.len - written, request.content.len - content_from);
    @memcpy(output[written..][0..len], request.content[content_from..][0..len]);
    return written + len;
}
