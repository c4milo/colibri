//! The TCP server of the client trace run (decision 105): h2 over TLS, with its handshake run
//! through `tls.record.Server` over the test identity of `src/testing/testdata/`. It answers each
//! request as the seed's plan says, may send the seed's GOAWAY (RFC 9113 §6.8), and under a
//! learning plan names h3 in each response's Alt-Svc (RFC 7838 §3). Each TCP connection the channel
//! opens meets a fresh server.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const tls = @import("tls");
const sim = @import("sim");
const tls_provider = sim.tls_provider;
const plan_module = @import("client_trace_plan.zig");
const ledger_module = @import("client_trace_ledger.zig");
const link_module = @import("client_trace_link.zig");
const identity = @import("client_trace_identity.zig");
const quic_server = @import("client_trace_quic_server.zig");

const limits = sim.constants.client_trace;
const Plan = plan_module.Plan;
const Ledger = ledger_module.Ledger;
const Direction = link_module.Direction;

/// Octets of the records the client sent and the server has not opened, of the plaintext they
/// opened, of what the server writes, and of one sealed write: each holds several records, and a
/// provider opens a record only into room for all that follows its header (RFC 9846 §5.2).
const record_len_max: usize = tls_provider.constants.record_ciphertext_len_max;
const input_len: usize = records_held * record_len_max;
const plain_len: usize = records_held * record_len_max;
const out_len: usize = records_held * record_len_max;
const sealed_len: usize = records_sealed * record_len_max;
const records_held: usize = 8;
/// A seal writes the records of all it holds, each a little longer than its plaintext.
const records_sealed: usize = 10;
/// Frames or records one call reads at most, each at least a header long.
const reads_max: usize = input_len / h2.constants.frame_header_len + 1;
const requests_max: usize = limits.exchanges_max;
const status_digits_len: usize = 3;
const length_digits_max: usize = 20;
const ok_status: u16 = 200;
/// RFC 7838 §3: h3 on the origin's host and port 443, which the client learns.
const alt_svc_value = "h3=\":443\"";

const Request = struct {
    stream_id: u32,
    exchange: usize,
    answer: plan_module.Answer,
    ended: bool = false,
    due_ns: u64,
    acted: bool = false,
};

pub const TcpServer = struct {
    config: tls.record.ServerConfig,
    session: tls.record.Server,
    h2: h2.Connection,
    input: [input_len]u8,
    input_used: usize,
    plain: [plain_len]u8,
    plain_used: usize,
    out: [out_len]u8,
    out_used: usize,
    sealed: [sealed_len]u8,
    requests: [requests_max]Request,
    requests_len: usize,
    /// Which of the run's connections this server serves, whether it runs, and whether its
    /// handshake completed.
    generation: u64,
    running: bool,
    handshaken: bool,

    pub fn configure(server: *TcpServer) !void {
        try server.config.init(.{
            .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
            .cookie_key = &identity.cookie_key,
            .ticket_key = null,
            .alpn = &alpn_h2,
            .cpu = identity.cpu,
        });
    }

    /// A fresh server for the run's connection `generation`, waiting for the ClientHello.
    pub fn reset(server: *TcpServer, generation: u64, random: tls.Random) !void {
        server.generation = generation;
        server.input_used = 0;
        server.plain_used = 0;
        server.out_used = 0;
        server.requests_len = 0;
        server.handshaken = false;
        try server.session.start(&server.config, random, identity.now_seconds);
        server.running = true;
    }

    /// The client closed the connection: the server reads and writes nothing more.
    pub fn stop(server: *TcpServer) void {
        if (server.running) server.session.close();
        server.running = false;
    }

    /// Takes octets the client sent.
    pub fn take(server: *TcpServer, octets: []const u8) !void {
        if (!server.running) return;
        if (server.input_used + octets.len > server.input.len) return error.ServerInputFull;
        @memcpy(server.input[server.input_used..][0..octets.len], octets);
        server.input_used += octets.len;
    }

    /// Runs the handshake, reads the requests, acts on each that is due, and sends what it wrote.
    /// Returns whether it sent anything.
    pub fn serve(server: *TcpServer, plan: *const Plan, ledger: *Ledger, to_client: *Direction, now_ns: u64) !bool {
        if (!server.running) return false;
        var sent = false;
        if (!server.handshaken) {
            sent = try server.run_handshake(to_client, now_ns);
            if (!server.handshaken) return sent;
        }
        try server.open_records();
        try server.read(plan, ledger, now_ns);
        try server.act(plan, now_ns);
        server.out_used += server.h2.write_pending(server.out[server.out_used..], now_ns);
        return try server.seal(to_client, now_ns) or sent;
    }

    /// Queues the seed's GOAWAY (RFC 9113 §6.8), which the next `serve` sends.
    pub fn send_goaway(server: *TcpServer, ledger: *Ledger) bool {
        if (!server.running or !server.handshaken) return false;
        server.h2.shutdown(h2.constants.error_no_error);
        ledger.goaways += 1;
        return true;
    }

    /// The instant the next request is due, or null. A request whose answer waits for its end is
    /// not due until the end arrives.
    pub fn due_ns(server: *const TcpServer, plan: *const Plan) ?u64 {
        if (!server.running) return null;
        var earliest: ?u64 = null;
        for (server.requests[0..server.requests_len]) |*request| {
            if (request.acted or request.answer == .reject) continue;
            if (!request.ended and !plan.answer_early) continue;
            earliest = @min(earliest orelse request.due_ns, request.due_ns);
        }
        return earliest;
    }

    fn run_handshake(server: *TcpServer, to_client: *Direction, now_ns: u64) !bool {
        const progress = server.session.handshake(server.input[0..server.input_used], &server.sealed) catch {
            // RFC 9846 §6.2: the alert that says why goes out before the server stops.
            const written = server.session.failure_written();
            try to_client.push(server.sealed[0..written], now_ns + limits.tcp_delay_ns);
            server.running = false;
            return written > 0;
        };
        server.consume_input(progress.consumed);
        try to_client.push(server.sealed[0..progress.written], now_ns + limits.tcp_delay_ns);
        if (progress.complete) {
            server.handshaken = true;
            server.h2.init(.server);
            try server.h2.attach_tls(server.session.provider());
            // RFC 9113 §3.4: the server's preface, a SETTINGS frame, is its first frame.
            server.out_used += server.h2.write_pending(server.out[server.out_used..], now_ns);
        }
        return progress.written > 0;
    }

    /// Opens every whole record the client sent into the plaintext h2 reads.
    fn open_records(server: *TcpServer) !void {
        const provider = server.session.provider();
        // Bounded: each pass opens a record, or stops.
        for (0..reads_max) |_| {
            const record = try provider.vtable.decrypt_record(provider.context, server.input[0..server.input_used], server.plain[server.plain_used..]);
            if (record.content == .incomplete) return;
            server.consume_input(record.consumed);
            if (record.content == .application_data) server.plain_used += record.plaintext_len;
        }
    }

    /// Reads every whole frame h2 takes, noting each request and deciding at its head what to do.
    fn read(server: *TcpServer, plan: *const Plan, ledger: *Ledger, now_ns: u64) !void {
        var consumed: usize = 0;
        // Bounded: each pass consumes a frame, or stops.
        for (0..reads_max) |_| {
            const received = try server.h2.receive(server.plain[consumed..server.plain_used], now_ns);
            if (received.consumed == 0 and received.event == null) break;
            consumed += received.consumed;
            const got = received.event orelse continue;
            if (got == .request) try server.take_request(got.request, plan, ledger, now_ns);
            if (got.ended_stream()) |stream_id| {
                if (server.request_of(stream_id)) |request| request.ended = true;
            }
        }
        std.mem.copyForwards(u8, &server.plain, server.plain[consumed..server.plain_used]);
        server.plain_used -= consumed;
    }

    fn take_request(server: *TcpServer, held: h2.connection.Request, plan: *const Plan, ledger: *Ledger, now_ns: u64) !void {
        const index = ledger_module.exchange_of(held.request.path orelse "") orelse return;
        if (server.requests_len == server.requests.len) return error.TooManyRequests;
        const answer = plan.tcp_answers[index];
        server.requests[server.requests_len] = .{ .stream_id = held.stream_id, .exchange = index, .answer = answer, .due_ns = now_ns + plan.answer_delay_ns };
        server.requests_len += 1;
        if (answer == .reject) {
            // RFC 9113 §8.7: REFUSED_STREAM says the server processed none of the request.
            try server.h2.reset_stream(held.stream_id, h2.constants.error_refused_stream);
            return;
        }
        ledger.process(index, .{ .transport = .tcp, .generation = server.generation });
    }

    fn act(server: *TcpServer, plan: *const Plan, now_ns: u64) !void {
        for (server.requests[0..server.requests_len]) |*request| {
            if (request.acted or request.answer == .reject or now_ns < request.due_ns) continue;
            if (!request.ended and !plan.answer_early) continue;
            request.acted = true;
            switch (request.answer) {
                .respond => try server.respond(request, plan),
                .reset => try server.h2.reset_stream(request.stream_id, h2.constants.error_cancel),
                .reject => unreachable,
            }
        }
    }

    fn respond(server: *TcpServer, request: *const Request, plan: *const Plan) !void {
        const content = quic_server.contents[request.exchange];
        var length_digits: [length_digits_max]u8 = undefined;
        const length = std.fmt.bufPrint(&length_digits, "{d}", .{content.len}) catch unreachable;
        const with_alt_svc = [_]h2.hpack.Field{ .{ .name = "content-length", .value = length }, .{ .name = "alt-svc", .value = alt_svc_value } };
        const fields = if (plan.policy == .learn) with_alt_svc[0..] else with_alt_svc[0..1];
        server.out_used += try server.h2.write_response(server.out[server.out_used..], request.stream_id, ok_status, fields, false);
        const data = try server.h2.write_data(server.out[server.out_used..], request.stream_id, content, true);
        assert(data.consumed == content.len);
        server.out_used += data.written;
    }

    /// Seals what the server wrote into records, and sends them.
    fn seal(server: *TcpServer, to_client: *Direction, now_ns: u64) !bool {
        if (server.out_used == 0) return false;
        const provider = server.session.provider();
        var taken: usize = 0;
        // Bounded: each pass seals at least one record's plaintext.
        for (0..reads_max) |_| {
            if (taken == server.out_used) break;
            const sealed = try provider.vtable.encrypt_record(provider.context, server.out[taken..server.out_used], &server.sealed);
            taken += sealed.consumed;
            try to_client.push(server.sealed[0..sealed.written], now_ns + limits.tcp_delay_ns);
        }
        assert(taken == server.out_used);
        server.out_used = 0;
        return true;
    }

    fn consume_input(server: *TcpServer, len: usize) void {
        std.mem.copyForwards(u8, &server.input, server.input[len..server.input_used]);
        server.input_used -= len;
    }

    fn request_of(server: *TcpServer, stream_id: u32) ?*Request {
        for (server.requests[0..server.requests_len]) |*request| {
            if (request.stream_id == stream_id) return request;
        }
        return null;
    }
};

const alpn_h2 = [_][]const u8{"h2"};
