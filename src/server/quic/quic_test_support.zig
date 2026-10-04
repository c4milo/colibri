//! What the server's QUIC tests share: the connection they drive, started from a client's first
//! Initial as `Endpoint` starts one, and an h3 client over QUIC in the same process, a
//! `tls.quic.Client` trusting the test identity of `src/testing/testdata/`. Time moves only when
//! `pump` moves it. Test-only.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const support = @import("../connection/connection_test_support.zig");
const quic_connection = @import("quic_connection.zig");
const internal = @import("quic_connection_internal.zig");
const endpoint_module = @import("../endpoint/endpoint.zig");
const event = @import("../event.zig");

pub const QuicConnection = quic_connection.QuicConnection;
pub const Event = event.Event;
pub const Field = quic_connection.Field;

/// The connection IDs and grease value each side starts from. Test-only.
const id_len: usize = 8;
const client_id: [id_len]u8 = @splat(client_id_octet);
const original_id: [id_len]u8 = @splat(original_id_octet);
const server_id: [id_len]u8 = @splat(server_id_octet);
const client_id_octet: u8 = 0xc1;
const original_id_octet: u8 = 0x0d;
const server_id_octet: u8 = 0x5e;
const grease: u64 = 0x1f2e_3d4c;
/// Where the client sends from, which the server reads off each datagram (decision 72).
const client_octets = [_]u8{ loopback_first, 0, 0, 1 };
const loopback_first: u8 = 127;
pub const client_port: u16 = 50_000;
/// The port the client sends from now, which a test moves as a NAT rebinding would (RFC 9000 §9).
pub var client_port_now: u16 = client_port;

/// The instant a test starts at, and how far each round of `pump` moves it: past each side's
/// delayed acknowledgment (RFC 9000 §13.2.1), so every packet is acknowledged.
pub const start_ns: u64 = 1_000_000_000;
pub const round_ns: u64 = 30_000_000;
pub const rounds_default: usize = 8;
const datagrams_per_round_max: usize = 64;
const client_idle_timeout_ms: u64 = 30_000;
const client_stream_window: u64 = 65_536;

pub var now_ns: u64 = start_ns;
/// The server's connection and what it borrows.
pub var connection: QuicConnection align(@alignOf(QuicConnection)) = undefined;
pub var config: quic_connection.Config align(@alignOf(quic_connection.Config)) = undefined;
var server_tls: tls.quic.ServerConfig align(@alignOf(tls.quic.ServerConfig)) = undefined;
const Pool = quic.stream.stream_incoming.DefaultPool;
var server_pool: Pool align(@alignOf(Pool)) = undefined;
/// The pool the server's connection starts with: its own by default, or one a test placed.
var server_receive: quic_connection.ReceiveStorage align(@alignOf(quic_connection.ReceiveStorage)) = undefined;
pub var server_started: bool = false;
/// Whether a `receive` of the server's failed.
pub var server_failed: bool = false;

/// The endpoint a test may route through instead of starting `connection` itself, and the
/// connection the server's events come from either way.
const TestEndpoint = endpoint_module.EndpointOf(endpoint_connections, endpoint_receive_capacity);
const endpoint_connections: usize = 2;
const endpoint_receive_capacity: usize = 65_536;
pub var endpoint: TestEndpoint align(@alignOf(TestEndpoint)) = undefined;
pub var endpoint_config: endpoint_module.Config align(@alignOf(endpoint_module.Config)) = undefined;
pub var through_endpoint: bool = false;
pub var served: *QuicConnection = &connection;

/// The client and what it runs on. It starts in `client_version`, which a test that sets another
/// restores after it.
pub var client: quic.Connection align(@alignOf(quic.Connection)) = undefined;
pub var client_version: quic.packet.header.Version align(@alignOf(quic.packet.header.Version)) = .v1;
var client_tls: tls.quic.ClientConfig align(@alignOf(tls.quic.ClientConfig)) = undefined;
var client_session: tls.quic.Client align(@alignOf(tls.quic.Client)) = undefined;
var client_send_scratch: quic.connection_send.DefaultScratch align(@alignOf(quic.connection_send.DefaultScratch)) = undefined;
var client_scratch: quic.connection_datagram.Scratch align(@alignOf(quic.connection_datagram.Scratch)) = undefined;
var client_pool: Pool align(@alignOf(Pool)) = undefined;
pub var client_h3: h3.Connection align(@alignOf(h3.Connection)) = undefined;
var client_section: h3.http.FieldSection align(@alignOf(h3.http.FieldSection)) = undefined;
var client_body: [client_body_len]u8 = undefined;
const client_body_len: usize = 16_384;
var client_h3_started: bool = false;

/// What the server reported, kept past the call that reported it: its kind, its request, and a
/// request's path, a body event's length and end, or why a request was cancelled.
pub const Seen = struct {
    kind: std.meta.Tag(Event),
    id: u64,
    path: [path_len_max]u8 = undefined,
    path_len: usize = 0,
    len: usize = 0,
    end: bool = false,
    reason: ?event.CancelReason = null,

    pub fn path_of(entry: *const Seen) []const u8 {
        return entry.path[0..entry.path_len];
    }
};
const path_len_max: usize = 256;
const seen_max: usize = 256;
pub var seen: [seen_max]Seen align(@alignOf(Seen)) = undefined;
pub var seen_len: usize = 0;

/// One request the client sent, and the response that came back.
pub const Fetch = struct {
    id: u64,
    prefix: [prefix_len_max]u8 = undefined,
    prefix_len: usize = 0,
    content: []const u8 = "",
    status: u16 = 0,
    interims: usize = 0,
    received_len: usize = 0,
    ended: bool = false,
    /// The code of the server's RESET_STREAM, once one arrived (RFC 9000 §19.4).
    reset: ?u64 = null,
    /// Whether the final response's head named gzip in Content-Encoding and Accept-Encoding in
    /// Vary (decision 101).
    gzip: bool = false,
    varies: bool = false,
};
const prefix_len_max: usize = 1024;
const fetches_max: usize = 4;
pub const received_len_max: usize = 262_144;
pub var fetches: [fetches_max]Fetch align(@alignOf(Fetch)) = undefined;
pub var fetches_len: usize = 0;
/// Each fetch's response content, at its index.
pub var received: [fetches_max][received_len_max]u8 = undefined;

/// Where a datagram crosses from one side to the other.
var datagram: [quic.constants.datagram_len_max]u8 = undefined;
var crossing: [quic.constants.datagram_len_max]u8 = undefined;

/// A client whose first datagram is owed, and a server that starts from it, over TLS for h3.
pub fn start() !void {
    try start_with_pool(server_pool.storage());
}

/// As `start`, with the client's octets held in `receive_pool` at the server.
pub fn start_with_pool(receive_pool: quic_connection.ReceiveStorage) !void {
    server_receive = receive_pool;
    client_port_now = client_port;
    through_endpoint = false;
    served = &connection;
    try server_tls.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .alpn = &alpn_h3,
        .cpu = support.cpu,
    });
    try client_tls.init(.{ .trust = .{ .web_pki = .{ .anchors = &support.anchors, .server_name = "localhost" } }, .alpn = &alpn_h3, .cpu = support.cpu });
    config = .{ .tls = &server_tls };
    now_ns = start_ns;
    server_started = false;
    server_failed = false;
    client_h3_started = false;
    seen_len = 0;
    fetches_len = 0;
    try start_client();
}

const alpn_h3 = [_][]const u8{"h3"};

/// As `start`, with every datagram passing through `endpoint`, which starts the server's
/// connection itself, after a Retry when `retry` is set (RFC 9000 §8.1.2).
pub fn start_endpoint(retry: ?*const tls.quic.Retry) !void {
    try start();
    through_endpoint = true;
    endpoint_config = .{ .quic = &config, .retry = retry };
    endpoint.init(&endpoint_config, support.stream.random(), 0, now_ns);
}

fn start_client() !void {
    client.init(.{
        .role = .client,
        .version = client_version,
        .local_parameters = client_parameters(),
        .now_ns = now_ns,
        .identity = .{ .local_initial_source = &client_id, .original_destination = &original_id },
        .receive = client_pool.storage(),
    });
    client_send_scratch = .{};
    client_h3.init(.{ .role = .client, .grease = grease });
    client_tls.values.quic_version = @enumFromInt(@intFromEnum(client_version));
    try client_session.start(&client_tls, support.stream.random(), support.now_seconds, null);
    var encoded: [parameters_len_max]u8 = undefined;
    var writer = quic.core.Writer.init(&encoded);
    try quic.transport_parameters.write(&writer, &client.local_parameters, .client);
    try client_session.provider().set_transport_params(writer.written());
    const suite = client_session.suite();
    try suite.vtable.install_initial_keys(suite.context, .client, &original_id);
}
const parameters_len_max: usize = 1024;

fn client_parameters() quic.transport_parameters.Parameters {
    var held = quic.transport_parameters.Parameters.initial();
    held.initial_max_data = quic.constants.receive_pool_len_default;
    held.initial_max_stream_data_bidi_local = quic.constants.receive_pool_len_default;
    held.initial_max_stream_data_uni = client_stream_window;
    held.initial_max_streams_uni = h3.constants.uni_streams_max;
    held.max_idle_timeout_ms = client_idle_timeout_ms;
    return held;
}

/// Pumps until both handshakes complete and each side's h3 runs.
pub fn connect() !void {
    try pump(rounds_default);
    if (!client_h3_started or served.protocol() == null) return error.TestUnexpectedResult;
}

/// The client sends a request for `path` with `content`, ending its stream.
pub fn request(method: []const u8, path: []const u8, content: []const u8) !*Fetch {
    return write_request(method, path, &.{}, content, &.{}, true);
}

/// As `request`, with no content and the field lines `fields` after the pseudo-header fields.
pub fn request_with_fields(method: []const u8, path: []const u8, fields: []const Field) !*Fetch {
    return write_request(method, path, fields, "", &.{}, true);
}

/// A client and a server as `start` makes them, the server coding content with the encoders of
/// the TCP tests' pool, every one free (decision 101).
pub fn start_coding() !void {
    try start();
    support.pool.reset(.none());
    config.codings = &support.codings;
    config.encoders = support.pool.encoders();
}

/// As `request`, leaving the stream open, so its receiving part at the server never finishes.
pub fn request_open(method: []const u8, path: []const u8, content: []const u8) !*Fetch {
    return write_request(method, path, &.{}, content, &.{}, false);
}

/// As `request_with_fields`, leaving the stream open.
pub fn request_open_with_fields(method: []const u8, path: []const u8, fields: []const Field) !*Fetch {
    return write_request(method, path, fields, "", &.{}, false);
}

/// A request for `path` with no content, whose trailer section `trailers` ends it (RFC 9114 §4.1).
pub fn request_with_trailers(path: []const u8, trailers: []const Field) !*Fetch {
    return write_request("POST", path, &.{}, "", trailers, true);
}

fn write_request(method: []const u8, path: []const u8, fields: []const Field, content: []const u8, trailers: []const Field, fin: bool) !*Fetch {
    assert(client_h3_started and fetches_len < fetches.len);
    assert(trailers.len == 0 or content.len == 0);
    const fetch = &fetches[fetches_len];
    fetch.* = .{ .id = 0, .content = content };
    client_section.init();
    try client_section.append(":method", method);
    try client_section.append(":scheme", "https");
    try client_section.append(":authority", "localhost");
    try client_section.append(":path", path);
    for (fields) |line| try client_section.append(line.name, line.value);
    const indexing: [request_lines + request_fields_max]h3.qpack.encoder.Indexing = @splat(.no_insert);
    var writer = quic.core.Writer.init(&fetch.prefix);
    fetch.id = try client_h3.write_request(&client, &client_section, indexing[0..client_section.len()], &writer, now_ns);
    if (content.len > 0) try client_h3.write_data_header(fetch.id, content.len, &writer, now_ns);
    if (trailers.len > 0) {
        client_section.init();
        for (trailers) |line| try client_section.append(line.name, line.value);
        try client_h3.write_trailers(&client, fetch.id, &client_section, &writer, now_ns);
    }
    fetch.prefix_len = writer.written().len;
    try quic.connection_stream_send.supply(&client, .{ .value = fetch.id }, fetch.prefix_len + content.len, fin);
    fetches_len += 1;
    return fetch;
}

/// The client asks the server to stop sending `fetch`'s response, and nothing more (RFC 9000
/// §3.5).
pub fn stop_fetch(fetch: *const Fetch) !void {
    try quic.connection_stream_send.stop_sending(&client, .{ .value = fetch.id }, h3.constants.error_request_cancelled);
}

/// The client resets its side of `fetch`'s stream, and nothing more (RFC 9000 §3.1).
pub fn reset_fetch(fetch: *const Fetch) !void {
    try quic.connection_stream_send.reset(&client, .{ .value = fetch.id }, h3.constants.error_request_cancelled);
}
const request_lines: usize = 4;
/// The most field lines a test's request carries after its pseudo-header fields.
const request_fields_max: usize = 4;

/// The client cancels `fetch` (RFC 9114 §4.1.1).
pub fn cancel_fetch(fetch: *const Fetch) void {
    client_h3.cancel(&client, fetch.id, h3.constants.error_request_cancelled);
}

/// Moves datagrams both ways for `rounds` rounds, moving time on and firing each side's timers,
/// and keeps what the server reports.
pub fn pump(rounds: usize) !void {
    for (0..rounds) |_| {
        now_ns += round_ns;
        try client_to_server();
        collect();
        try server_to_client();
        if (through_endpoint) endpoint.on_instant(now_ns) else internal.on_instant(&connection, now_ns);
        _ = quic.connection_timer.on_instant(&client, client_session.suite(), &client_scratch.recovery, now_ns) catch {};
        collect();
    }
}

/// Keeps every event the server reports.
pub fn collect() void {
    if (!server_started) return;
    for (0..seen_max) |_| {
        const received_event = served.receive(now_ns) catch {
            server_failed = true;
            continue;
        };
        keep(received_event.event orelse return);
    }
}

fn keep(reported: Event) void {
    assert(seen_len < seen.len);
    const entry = &seen[seen_len];
    entry.* = .{ .kind = reported, .id = 0 };
    switch (reported) {
        .request => |head| {
            entry.id = head.id;
            const path = head.path orelse "";
            @memcpy(entry.path[0..path.len], path);
            entry.path_len = path.len;
        },
        .body => |body| {
            entry.id = body.id;
            entry.len = body.octets.len;
            entry.end = body.end;
        },
        .trailers => |trailers| entry.id = trailers.id,
        .cancelled => |cancelled| {
            entry.id = cancelled.id;
            entry.reason = cancelled.reason;
        },
        .done => |done| entry.id = done.id,
    }
    seen_len += 1;
}

/// The `n`th event of `kind` the server reported, or null.
pub fn nth(kind: std.meta.Tag(Event), n: usize) ?*const Seen {
    var count: usize = 0;
    for (seen[0..seen_len]) |*entry| {
        if (entry.kind != kind) continue;
        if (count == n) return entry;
        count += 1;
    }
    return null;
}

fn client_to_server() !void {
    for (0..datagrams_per_round_max) |_| {
        const sent = quic.connection_send.send(&client, client_session.suite(), client_session.provider(), client_provider(), &client_send_scratch, &datagram, now_ns) catch return error.TestUnexpectedResult;
        const held = sent orelse return;
        @memcpy(crossing[0..held.len], datagram[0..held.len]);
        if (through_endpoint) {
            const taken = endpoint.receive(crossing[0..held.len], .not_ect, client_address(), now_ns) orelse continue;
            served = taken;
            server_started = true;
            continue;
        }
        if (!server_started) try start_server(crossing[0..held.len]);
        internal.take(&connection, crossing[0..held.len], .not_ect, client_address(), now_ns);
    }
}

/// Starts the server's connection from the client's first Initial (RFC 9000 §7.2), as `Endpoint`
/// does.
fn start_server(first: []const u8) !void {
    const parsed = try quic.packet.header.read(first, id_len);
    const long = parsed.long;
    try internal.start(&connection, &config, server_receive, .{
        .local_id = server_id,
        .original_destination = long.dcid,
        .peer_source = long.scid,
        .grease = grease,
        .peer = client_address(),
    }, support.stream.random(), 0, now_ns);
    server_started = true;
}

pub fn client_address() quic.peer_address.PeerAddress {
    return quic.peer_address.PeerAddress.of(&client_octets, client_port_now);
}

fn server_to_client() !void {
    for (0..datagrams_per_round_max) |_| {
        const sent = (if (through_endpoint) endpoint.send(&datagram, now_ns) else internal.send(&connection, &datagram, now_ns)) orelse return;
        @memcpy(crossing[0..sent.octets.len], sent.octets);
        _ = quic.connection_datagram.receive(&client, client_session.suite(), client_session.provider(), .{ .octets = crossing[0..sent.octets.len], .now_ns = now_ns, .ecn = .not_ect }, &client_scratch) catch return error.TestUnexpectedResult;
        try client_read();
    }
}

/// Starts the client's h3 once its handshake completed, and reads every event it has.
fn client_read() !void {
    if (!client_h3_started) {
        if (!client.handshake_complete) return;
        try client_h3.start(&client, now_ns);
        client_h3_started = true;
    }
    for (0..received_len_max) |_| {
        const read = client_h3.receive(&client, &client_body, now_ns) catch return error.TestUnexpectedResult;
        client_record(read orelse return);
    }
}

fn client_record(read: h3.connection.Event) void {
    switch (read) {
        .response => |head| if (fetch_of(head.stream_id)) |fetch| {
            if (head.response.status.is_interim()) fetch.interims += 1 else note_final(fetch, head.response.status.code);
        },
        .data => |data| if (fetch_of(data.stream_id)) |fetch| {
            const index = fetch_index(fetch);
            @memcpy(received[index][fetch.received_len..][0..data.octets.len], data.octets);
            fetch.received_len += data.octets.len;
        },
        .end => |stream_id| if (fetch_of(stream_id)) |fetch| {
            fetch.ended = true;
        },
        .reset => |ended| if (fetch_of(ended.stream_id)) |fetch| {
            fetch.reset = ended.error_code;
        },
        else => {},
    }
}

/// Keeps a final response's status and what its head says of its coding.
fn note_final(fetch: *Fetch, status: u16) void {
    fetch.status = status;
    const section = client_h3.field_section();
    if (section.find("content-encoding")) |line| fetch.gzip = std.mem.eql(u8, line.value, "gzip");
    if (section.find("vary")) |line| fetch.varies = std.mem.eql(u8, line.value, "accept-encoding");
}

pub fn fetch_of(stream_id: u64) ?*Fetch {
    for (fetches[0..fetches_len]) |*fetch| {
        if (fetch.id == stream_id) return fetch;
    }
    return null;
}

fn fetch_index(fetch: *const Fetch) usize {
    return (@intFromPtr(fetch) - @intFromPtr(&fetches[0])) / @sizeOf(Fetch);
}

/// What the client received on `fetch`'s stream.
pub fn content_of(fetch: *const Fetch) []const u8 {
    return received[fetch_index(fetch)][0..fetch.received_len];
}

fn client_provider() quic.stream.StreamProvider {
    return client_h3.provider(.{ .context = &fetches, .vtable = &client_vtable });
}

const client_vtable: quic.stream.stream_provider.VTable = .{ .read = read_fetch };

fn read_fetch(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    const fetch = fetch_of(stream_id) orelse return 0;
    const from: usize = @intCast(offset);
    const total = fetch.prefix_len + fetch.content.len;
    if (from >= total) return 0;
    var written: usize = 0;
    if (from < fetch.prefix_len) {
        written = @min(output.len, fetch.prefix_len - from);
        @memcpy(output[0..written], fetch.prefix[from..][0..written]);
        if (written < fetch.prefix_len - from) return written;
    }
    const content_from = from + written - fetch.prefix_len;
    const len = @min(output.len - written, fetch.content.len - content_from);
    @memcpy(output[written..][0..len], fetch.content[content_from..][0..len]);
    return written + len;
}
