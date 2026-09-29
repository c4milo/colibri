//! What the QUIC client's tests share: the connection they drive, and an h3 server over QUIC in the
//! same process, a `tls.quic.Server` over the test identity of `src/testing/testdata/`, which
//! answers each request once the request has ended. Time moves only when `pump` moves it.
//! Test-only.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const support = @import("../connection/connection_test_support.zig");
const quic_connection = @import("quic_connection.zig");
const event = @import("../event.zig");

pub const QuicConnection = quic_connection.QuicConnection;
pub const HttpExchange = event.HttpExchange;
pub const Event = event.Event;

/// The connection IDs and grease value the client starts from. Test-only.
const id_len: usize = 8;
const client_id_octet: u8 = 0xc1;
const server_id_octet: u8 = 0x5e;
const original_id_octet: u8 = 0x0d;
const grease: u64 = 0x1f2e_3d4c;
const server_id: [id_len]u8 = @splat(server_id_octet);
pub const client_start: quic_connection.Start = .{
    .source_id = @splat(client_id_octet),
    .original_destination_id = @splat(original_id_octet),
    .grease = grease,
};

/// What the server grants the client (RFC 9000 §18.2), its bidirectional streams first, which a
/// test may lower before `pump` starts the server. Test-only.
pub var server_streams_bidi: u64 = server_streams_bidi_default;
const server_streams_bidi_default: u64 = 16;
const server_window: u64 = 1_048_576;
const server_stream_window: u64 = 262_144;
const idle_timeout_ms: u64 = 30_000;

/// The ALPN lists: h3 alone, and a list whose first choice is another protocol.
pub const alpn_h3 = [_][]const u8{"h3"};
pub const alpn_other = [_][]const u8{"hq-interop"};

/// The instant a test starts at, and how far each round of `pump` moves it: past h3's and QUIC's
/// delayed acknowledgment (RFC 9000 §13.2.1), so every packet is acknowledged.
pub const start_ns: u64 = 1_000_000_000;
const round_ns: u64 = 30_000_000;
/// Rounds `pump` moves datagrams both ways, and the most datagrams one side sends a round.
pub const rounds_default: usize = 8;
const datagrams_per_round_max: usize = 64;

pub var now_ns: u64 = start_ns;
pub var connection: QuicConnection align(@alignOf(QuicConnection)) = undefined;
pub var config: quic_connection.Config align(@alignOf(quic_connection.Config)) = undefined;
pub var client_tls: tls.quic.ClientConfig align(@alignOf(tls.quic.ClientConfig)) = undefined;
pub var server_tls: tls.quic.ServerConfig align(@alignOf(tls.quic.ServerConfig)) = undefined;
pub var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
pub var events_len: usize = 0;

/// The server's connection and what it runs on.
pub var server: quic.Connection align(@alignOf(quic.Connection)) = undefined;
pub var server_session: tls.quic.Server align(@alignOf(tls.quic.Server)) = undefined;
var server_send_scratch: quic.connection_send.DefaultScratch align(@alignOf(quic.connection_send.DefaultScratch)) = undefined;
var server_scratch: quic.connection_datagram.Scratch align(@alignOf(quic.connection_datagram.Scratch)) = undefined;
var server_pool: quic.stream.stream_incoming.DefaultPool align(@alignOf(quic.stream.stream_incoming.DefaultPool)) = undefined;
pub var server_h3: h3.Connection align(@alignOf(h3.Connection)) = undefined;
var server_section: h3.http.FieldSection align(@alignOf(h3.http.FieldSection)) = undefined;
var server_body: [body_len]u8 = undefined;
var server_original_id: [id_len]u8 = undefined;
var server_peer_id: [id_len]u8 = undefined;
const body_len: usize = 16_384;
/// Whether the server's connection started, and whether its h3 runs.
pub var server_started: bool = false;
var server_h3_started: bool = false;
/// Whether the server answers the requests that end, which a test turns off to act first,
/// whether it answers each as soon as its head arrives, before its content has, and whether it
/// leaves each response open, never ending its stream.
pub var server_answers: bool = true;
pub var answer_early: bool = false;
pub var answer_open: bool = false;
/// Interim responses the server sends before each final one, and whether its content-length
/// names more than the content, which RFC 9114 §4.1.2 makes malformed.
pub var answer_interims: usize = 0;
pub var answer_malformed: bool = false;

/// One request the server read, and its answer: the kept frames, then the content.
pub const Answer = struct {
    id: u64,
    path: [path_len_max]u8 = undefined,
    path_len: usize = 0,
    /// Octets of the request's content the server read, the content-length it named, and whether
    /// its `:scheme` was https.
    received: usize = 0,
    content_length: ?u64 = null,
    https: bool = false,
    /// Whether the request offered gzip first in Accept-Encoding (decision 101).
    offers_gzip: bool = false,
    ended: bool = false,
    answered: bool = false,
    prefix: [prefix_len_max]u8 = undefined,
    prefix_len: usize = 0,
    content: []const u8 = "",
};
const path_len_max: usize = 256;
/// Octets of the server's encoded transport parameters, a content-length and a status code.
const parameters_len_max: usize = 1024;
const length_digits_max: usize = 20;
const status_digits_len: usize = 3;
const prefix_len_max: usize = 1024;
const answers_max: usize = 16;
pub var answers: [answers_max]Answer align(@alignOf(Answer)) = undefined;
pub var answers_len: usize = 0;
/// What the server answers each request with.
pub var answer_status: u16 = ok_status;
const ok_status: u16 = 200;
pub var answer_content: []const u8 = "hello";
/// The Content-Encoding the server names in each answer, or null for none (decision 101).
pub var answer_coding: ?[]const u8 = null;

/// The client's receive pool (decision 61), placed outside any stack frame. Test-only.
pub var client_pool: quic.stream.stream_incoming.DefaultPool align(@alignOf(quic.stream.stream_incoming.DefaultPool)) = undefined;

/// Where a datagram crosses from one side to the other.
var datagram: [quic.constants.datagram_len_max]u8 = undefined;
var crossing: [quic.constants.datagram_len_max]u8 = undefined;

/// A client offering `client_protocols` to a server selecting from `server_protocols`, which
/// issues tickets when `tickets`. Nothing has been sent.
pub fn start(client_protocols: []const []const u8, server_protocols: []const []const u8, tickets: bool) !void {
    try start_with_pool(client_pool.storage(), client_protocols, server_protocols, tickets);
}

/// As `start`, with the server's octets held in `receive_pool` until h3 reads them.
pub fn start_with_pool(receive_pool: quic_connection.ReceiveStorage, client_protocols: []const []const u8, server_protocols: []const []const u8, tickets: bool) !void {
    try prepare(client_protocols, server_protocols, tickets);
    try connection.init(&config, receive_pool, client_start, support.stream.random(), support.now_seconds, now_ns, null);
}

/// The TLS configurations of `start`, the client's `config`, and a server that starts from the
/// first datagram it takes, with time back at `start_ns`. No client connection is made.
pub fn prepare(client_protocols: []const []const u8, server_protocols: []const []const u8, tickets: bool) !void {
    try client_tls.init(.{
        .trust = .{ .web_pki = .{ .anchors = &support.anchors, .server_name = support.authority } },
        .alpn = client_protocols,
    });
    try server_tls.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .ticket_key = if (tickets) &support.ticket_key else null,
        .alpn = server_protocols,
    });
    config = .{ .tls = &client_tls, .authority = support.authority };
    now_ns = start_ns;
    server_started = false;
    server_h3_started = false;
    server_answers = true;
    answer_early = false;
    answer_open = false;
    answer_interims = 0;
    answer_malformed = false;
    server_streams_bidi = server_streams_bidi_default;
    answers_len = 0;
    events_len = 0;
    answer_status = ok_status;
    answer_content = "hello";
    answer_coding = null;
}

/// A server with no connection, which starts from the next Initial it takes, as a second
/// connection's server does. Time and each test's settings stay as they are.
pub fn reset_server() void {
    server_started = false;
    server_h3_started = false;
    answers_len = 0;
}

/// Moves datagrams both ways for `rounds` rounds, moving time on and firing each side's timers, and
/// keeps the client's events.
pub fn pump(rounds: usize) !void {
    for (0..rounds) |_| {
        now_ns += round_ns;
        try client_to_server();
        try answer_due();
        try server_to_client();
        connection.on_instant(now_ns);
        server_on_instant();
        try collect();
    }
}

/// Reports every event the client owes, and keeps them.
pub fn collect() !void {
    var none: [0]u8 = .{};
    for (0..support.events_max) |_| {
        const received = connection.receive(&none, .not_ect, .{}, now_ns);
        const reported = received.event orelse return;
        try keep(reported);
    }
}

fn keep(reported: Event) !void {
    if (events_len == events.len) return error.TestUnexpectedResult;
    events[events_len] = reported;
    events_len += 1;
}

/// The first event of `tag` the client reported, or null.
pub fn find(tag: std.meta.Tag(Event)) ?Event {
    for (events[0..events_len]) |reported| {
        if (reported == tag) return reported;
    }
    return null;
}

fn client_to_server() !void {
    for (0..datagrams_per_round_max) |_| {
        const sent = connection.send(&datagram, now_ns) orelse return;
        @memcpy(crossing[0..sent.octets.len], sent.octets);
        try server_receive(crossing[0..sent.octets.len]);
    }
}

fn server_to_client() !void {
    for (0..datagrams_per_round_max) |_| {
        const len = (try server_send(&datagram)) orelse return;
        @memcpy(crossing[0..len], datagram[0..len]);
        // Bounded: each pass consumes the datagram or reports one of the client's events.
        for (0..support.events_max) |_| {
            const received = connection.receive(crossing[0..len], .not_ect, .{}, now_ns);
            if (received.event) |reported| try keep(reported);
            if (received.consumed > 0) break;
        }
    }
}

/// Writes the next datagram the server owes into `output`, and returns its length, or null when
/// it owes none.
pub fn server_send(output: []u8) !?usize {
    if (!server_started) return null;
    const sent = quic.connection_send.send(&server, server_session.suite(), server_session.provider(), server_provider(), &server_send_scratch, output, now_ns) catch return error.TestUnexpectedResult;
    const held = sent orelse return null;
    return held.len;
}

/// Fires the server's deadlines at `now_ns`.
pub fn server_on_instant() void {
    if (server_started) _ = quic.connection_timer.on_instant(&server, server_session.suite(), &server_scratch.recovery, now_ns) catch {};
}

/// The server takes one datagram: the first starts its connection from the client's Initial (RFC
/// 9000 §7.2), and each after it may carry h3.
pub fn server_receive(octets: []u8) !void {
    if (!server_started) try start_server(octets);
    _ = quic.connection_datagram.receive(&server, server_session.suite(), server_session.provider(), .{ .octets = octets, .now_ns = now_ns, .ecn = .not_ect }, &server_scratch) catch return;
    if (!server_h3_started and server.handshake_complete) {
        server_h3.init(.{ .role = .server });
        try server_h3.start(&server, now_ns);
        server_h3_started = true;
    }
    if (server_h3_started) try server_read();
}

fn start_server(first: []const u8) !void {
    const parsed = try quic.packet.header.read(first, id_len);
    const long = parsed.long;
    @memcpy(&server_original_id, long.dcid);
    @memcpy(&server_peer_id, long.scid);
    server.init(.{
        .role = .server,
        .local_parameters = server_parameters(),
        .now_ns = now_ns,
        .identity = .{ .local_initial_source = &server_id, .original_destination = &server_original_id, .peer_initial_source = &server_peer_id },
        .receive = server_pool.storage(),
    });
    server_session.start(&server_tls, support.stream.random(), support.now_seconds, .v1);
    server_send_scratch = .{};
    var body: [parameters_len_max]u8 = undefined;
    var writer = quic.core.Writer.init(&body);
    try quic.transport_parameters.write(&writer, &server.local_parameters, .server);
    try server_session.provider().set_transport_params(writer.written());
    const suite = server_session.suite();
    try suite.vtable.install_initial_keys(suite.context, .server, &server_original_id);
    server_started = true;
}

fn server_parameters() quic.transport_parameters.Parameters {
    var held = quic.transport_parameters.Parameters.initial();
    held.initial_max_data = server_window;
    held.initial_max_stream_data_bidi_remote = server_stream_window;
    held.initial_max_stream_data_bidi_local = server_stream_window;
    held.initial_max_stream_data_uni = server_stream_window;
    held.initial_max_streams_bidi = server_streams_bidi;
    held.initial_max_streams_uni = h3.constants.uni_streams_max;
    held.max_idle_timeout_ms = idle_timeout_ms;
    return held;
}

/// The server reads every h3 event, and answers each request that has ended.
fn server_read() !void {
    for (0..support.buffer_len) |_| {
        const read = server_h3.receive(&server, &server_body, now_ns) catch return;
        const got = read orelse break;
        switch (got) {
            .request => |held| {
                const answer = &answers[answers_len];
                answer.* = .{ .id = held.stream_id };
                const path = held.request.path orelse "";
                @memcpy(answer.path[0..path.len], path);
                answer.path_len = path.len;
                answer.content_length = held.request.content_length;
                answer.https = std.mem.eql(u8, held.request.scheme orelse "", "https");
                const offer = server_h3.field_section().find("accept-encoding");
                answer.offers_gzip = offer != null and std.mem.startsWith(u8, offer.?.value, "gzip");
                answers_len += 1;
            },
            .data => |held| if (answer_of(held.stream_id)) |answer| {
                answer.received += held.octets.len;
            },
            .end => |id| if (answer_of(id)) |answer| {
                answer.ended = true;
            },
            else => {},
        }
    }
    try answer_due();
}

/// The server answers each request that is due, once a test lets it.
pub fn answer_due() !void {
    if (!server_answers or !server_h3_started) return;
    for (answers[0..answers_len]) |*answer| {
        const due = answer.ended or answer_early;
        if (due and !answer.answered) try server_answer(answer, answer_status, answer_content);
    }
}

pub fn answer_of(id: u64) ?*Answer {
    for (answers[0..answers_len]) |*answer| {
        if (answer.id == id) return answer;
    }
    return null;
}

/// The server answers `answer`'s request with `status` and `content`, and ends the stream.
pub fn server_answer(answer: *Answer, status: u16, content: []const u8) !void {
    answer.answered = true;
    answer.content = content;
    var digits: [length_digits_max]u8 = undefined;
    var status_digits: [status_digits_len]u8 = undefined;
    server_section.init();
    try server_section.append(":status", std.fmt.bufPrint(&status_digits, "{d}", .{status}) catch unreachable);
    try server_section.append("content-type", "application/dns-message");
    const named = if (answer_malformed) content.len + 1 else content.len;
    try server_section.append("content-length", std.fmt.bufPrint(&digits, "{d}", .{named}) catch unreachable);
    if (answer_coding) |coding| try server_section.append("content-encoding", coding);
    var writer = quic.core.Writer.init(&answer.prefix);
    try write_interims(answer.id, &writer);
    try server_h3.write_response(&server, answer.id, &server_section, &.{}, &writer, now_ns);
    if (content.len > 0) try server_h3.write_data_header(answer.id, content.len, &writer, now_ns);
    answer.prefix_len = writer.written().len;
    quic.connection_stream_send.supply(&server, .{ .value = answer.id }, answer.prefix_len + content.len, !answer_open) catch |failure| {
        // RFC 9000 §3.5: a stream the client stopped was reset by the server, and takes no answer.
        if (failure == error.NotWritable) return;
        return failure;
    };
}

/// Writes `answer_interims` 103 (Early Hints) responses (RFC 9110 §15.2.4).
fn write_interims(id: u64, writer: *quic.core.Writer) !void {
    var interim: h3.http.FieldSection = undefined;
    for (0..answer_interims) |_| {
        interim.init();
        try interim.append(":status", "103");
        try server_h3.write_response(&server, id, &interim, &.{}, writer, now_ns);
    }
}

fn server_provider() quic.stream.StreamProvider {
    return server_h3.provider(.{ .context = &answers, .vtable = &server_vtable });
}

const server_vtable: quic.stream.stream_provider.VTable = .{ .read = read_answer };

fn read_answer(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    const answer = answer_of(stream_id) orelse return 0;
    const from: usize = @intCast(offset);
    const total = answer.prefix_len + answer.content.len;
    if (from >= total) return 0;
    var written: usize = 0;
    if (from < answer.prefix_len) {
        written = @min(output.len, answer.prefix_len - from);
        @memcpy(output[0..written], answer.prefix[from..][0..written]);
        if (written < answer.prefix_len - from) return written;
    }
    const content_from = from + written - answer.prefix_len;
    const len = @min(output.len - written, answer.content.len - content_from);
    @memcpy(output[written..][0..len], answer.content[content_from..][0..len]);
    return written + len;
}
