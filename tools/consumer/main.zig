//! The program the consumer project builds: it reaches h11, h2, tls, server and client through
//! `colibri`, the one module colibri exports (decision 170), and stdx's gzip through stdx. It
//! writes a request, reads a response, starts a
//! TLS handshake, codes content, moves a request through the client and the server's engine,
//! binds a `colibri.Server` on a loopback port, and prepares a `colibri.Client` for it. This shows
//! that the modules link and run for a project that depends on colibri.
const std = @import("std");
const colibri = @import("colibri");
const h11 = colibri.h11;
const h2 = colibri.h2;
const tls = colibri.tls;
const server_module = colibri.server;
const client_module = colibri.client;
const stdx = @import("stdx");
const gzip = stdx.compress.gzip;
const platform = stdx.platform;

var client: h11.Connection align(@alignOf(h11.Connection)) = undefined;
var h2_client: h2.Connection align(@alignOf(h2.Connection)) = undefined;
var tls_config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var tls_client: tls.record.Client align(@alignOf(tls.record.Client)) = undefined;
var output: [4096]u8 = undefined;
var gzip_encoder: gzip.Encoder(.{ .level = 6 }) align(@alignOf(gzip.Encoder(.{ .level = 6 }))) = undefined;
var gzip_decoder: gzip.Decoder align(@alignOf(gzip.Decoder)) = undefined;
var coded: [256]u8 = undefined;
// The server's engine and the client's pool hold hundreds of kilobytes, so they live outside
// the stack. The engine holds the one TCP connection this program accepts, and no QUIC
// connection.
const Engine = server_module.Engine(.{ .tcp_connections = 1, .quic_connections = 0 });
var engine: Engine align(@alignOf(Engine)) = undefined;
/// Where each `receive` of the engine writes what it took and the event it reports (decision 165).
var engine_received: server_module.ReceiveResult align(@alignOf(server_module.ReceiveResult)) = undefined;
// The pool speaks h2 over TCP alone, so it holds no QUIC state (decision 124).
const ConnectionPool = client_module.ConnectionPool(.{ .quic = false });
var asked: ConnectionPool align(@alignOf(ConnectionPool)) = undefined;
var asked_memory: [ConnectionPool.memory_bytes(.{})]u8 align(ConnectionPool.memory_alignment) = undefined;
/// The connection the pool's `open` named, which each later call about it names.
var asked_connection: client_module.ConnectionHandle align(@alignOf(client_module.ConnectionHandle)) = .{ .slot = 0, .generation = 0 };
const get: client_module.Request = .{ .method = "GET", .path = "/" };
var get_response: client_module.Response align(@alignOf(client_module.Response)) = .{};
// The bytes the client wrote, which the server reads, and the bytes the server wrote, which the
// client reads. The engine reports a `send` while `wire` may still hold bytes the server has
// not read, so the server's bytes go into a buffer of their own.
var wire: [4096]u8 = undefined;
var server_output: [4096]u8 = undefined;
// A `colibri.Server` of one TCP connection on colibri's own loop, which binds a port the system
// chooses, and the router that `init` takes.
const BoundServer = colibri.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .private);
var bound_server: BoundServer align(@alignOf(BoundServer)) = undefined;
const bound_routes = .{
    .error_handler = on_route_error,
    .routes = .{
        .{ .get, "/", on_root },
    },
};
// `colibri.server` is the module `server`, which the root of `colibri` names.
const BoundRouter = colibri.server.Router(void, bound_routes, .{ .requests = 1, .response_buffer_bytes = 256, .request_body_bytes = 0, .request_header_bytes = 0 });
var router: BoundRouter align(@alignOf(BoundRouter)) = undefined;
var router_context: void = {};
// A `colibri.Client` of one TCP connection, four requests and no QUIC, which the program places
// the same way.
const client_capacity: colibri.ClientCapacity = .{ .quic = false, .tcp_connections = 1, .requests = 4 };
const BoundClient = colibri.Client(client_capacity, .private);
var bound_client: BoundClient align(@alignOf(BoundClient)) = undefined;

/// Rounds of moving bytes between the client and the server before the exchange must have ended.
const exchange_rounds_max = 8;
/// Events one side reads in one round, at most.
const events_per_round_max = 16;

/// chapulin's module calls this when one of its assertions fails, in place of its own report
/// (decision 172). A program that declares no such function gets chapulin's panic.
pub fn chapulinAssertFail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) noreturn {
    std.debug.panic("this program stops: chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

/// A random source over the operating system's entropy, which every TLS session of the program
/// draws from (decision 175). Each draw calls `io.randomSecure`, which is thread-safe, keeps no
/// state that a fork copies, and has no weaker fallback. A draw that fails halts the program, so
/// no session runs on bytes the system did not give.
const SecureRandom = struct {
    io: std.Io,

    fn fill(pointer: *anyopaque, bytes: []u8) void {
        const self: *SecureRandom = @ptrCast(@alignCast(pointer));
        self.io.randomSecure(bytes) catch |err| std.debug.panic("no entropy: {t}", .{err});
    }

    fn random(self: *SecureRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

/// A root this client never meets a chain of: an empty DER SEQUENCE for its name and its key.
const empty_sequence = [_]u8{ 0x30, 0 };
/// Unix seconds, which a program reads from its clock; colibri reads none.
const now_seconds: u64 = 1_800_000_000;
/// RFC 9846 §5.1: a handshake record's content type.
const handshake_record: u8 = 22;
/// The server's address, which a DNS lookup returns, and the port of an "http" origin (RFC 9110
/// §4.2.1). The bytes move in memory, so no socket connects to them.
const loopback = [_]u8{ 127, 0, 0, 1 };
const server_addresses = [_]client_module.Address{.init(&loopback, 0)};
const server_port: u16 = 80;

pub fn main(init: std.process.Init) !void {
    // The random source of every TLS session: the operating system's entropy.
    var secure: SecureRandom = .{ .io = init.io };
    // The CPU features the program detects once, for its codecs (decision 169) and for TLS.
    const cpu_features: platform.CpuFeatures = .detect();
    // PSTATE.DIT on this thread, where the core has FEAT_DIT. Elsewhere the call changes nothing.
    _ = platform.set_data_independent_timing(cpu_features, true);
    // The program's one context, which each TLS value holds (decision 175).
    const crypto = stdx.crypto.init(cpu_features, secure.random());
    client.init(.{ .role = .client, .cpu_features = cpu_features });
    const head_len = try client.write_request(&output, "GET", "/", &.{
        .{ .name = "Host", .value = "example.test" },
    });
    if (!std.mem.startsWith(u8, output[0..head_len], "GET / HTTP/1.1\r\n")) return error.RequestWrong;
    const step = try client.receive("HTTP/1.1 204 No Content\r\n\r\n", &.{});
    const status = @intFromEnum(step.event.?.response.line.status);
    if (status != 204) return error.ResponseWrong;

    // h2's client preface starts with the 24 bytes of RFC 9113 §3.4.
    h2_client.init(.{ .role = .client });
    const preface_len = h2_client.write_pending(&output, 0);
    if (!std.mem.startsWith(u8, output[0..preface_len], "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) return error.PrefaceWrong;

    try check_tls(crypto);

    // stdx's gzip, from stdx's one module, codes content and decodes it.
    gzip_encoder.init(.target());
    const coded_len = try gzip_encoder.encode_all("colibri", &coded);
    gzip_decoder.init(cpu_features);
    const decoded = try gzip_decoder.decode_all(coded[0..coded_len], &output);
    if (!std.mem.eql(u8, output[0..decoded.written], "colibri")) return error.CodingWrong;

    // The `server` and `client` modules (decision 100), in cleartext h2: the client's request and
    // the server's 204 move between the two in memory, at one instant. The client is a pool
    // with no QUIC, which allows h2 alone, so it speaks h2 with prior knowledge. The server's
    // engine names no version, and the connection it accepts reads h2 from the client's
    // connection preface (decision 117).
    const engine_config: server_module.Config = .{ .cpu_features = cpu_features };
    const client_config: client_module.Config = .{ .protocols = .{ .h11 = false, .h3 = false }, .authority = "example.test", .cpu_features = cpu_features };
    try engine.init(&engine_config, .{ .unix_seconds = 0, .monotonic_ns = 0 });
    // One call for the socket a program accepted, in cleartext here. The handle names the
    // connection from then on.
    const accepted = engine.accept(.{ .tls = false }, 0) orelse return error.ExchangeWrong;
    // The pool takes what DNS knows as values. A pool with no QUIC takes no receive pool.
    try asked.init(&asked_memory, &client_config, &.{ .addresses = &server_addresses, .port = server_port }, null);
    _ = try asked.request(&get, &get_response);
    // The pool asks for a socket. A program connects one, then starts the connection on it, and
    // reads what the connection then owes: in cleartext, that it is connected. A connection in
    // cleartext draws nothing, so the pool's configuration holds no context.
    const open = asked.receive(.none, 0).event orelse return error.ExchangeWrong;
    if (open != .open) return error.ExchangeWrong;
    asked_connection = open.open.connection;
    try asked.start_tcp(asked_connection, 0, null);
    hear(server_output[0..0]);
    for (0..exchange_rounds_max) |_| {
        try serve(accepted, asked.send_stream(asked_connection, &wire, 0));
    }
    if (get_response.result != .response or get_response.status != .no_content) return error.ExchangeWrong;

    // `colibri` (decision 150): `init` binds 127.0.0.1 on port 0, and `port()` names the port the
    // system chose. The program does not call `run`, so it serves nothing, and `deinit` closes
    // the socket.
    const config: colibri.ServerConfig = .{ .host = "127.0.0.1", .port = 0, .crypto = crypto, .unix_seconds = now_seconds, .engine = .{ .cpu_features = cpu_features } };
    router.init();
    try bound_server.init(&config, &router, &router_context);
    defer bound_server.deinit();
    if (bound_server.port() == 0) return error.BindWrong;
    // `colibri.Client` (decision 153 ruling 8): `init` prepares the pool for the server's port, in
    // cleartext and with no h3, which a client with no QUIC refuses. The program passes its own
    // instant, because the client reads no clock, and no handler. It does not call `run`, so it
    // fetches nothing.
    const bound_client_config: colibri.ClientConfig = .{
        .destination = .{ .addresses = &server_addresses, .port = bound_server.port() },
        .pool = .{ .authority = "localhost", .protocols = .{ .h3 = false }, .cpu_features = cpu_features },
        .unix_seconds = now_seconds,
    };
    try bound_client.init(&bound_client_config, null);
    defer bound_client.deinit();
    std.debug.print("consumer: h11, h2, tls, gzip, server, client and colibri link and run as a dependency\n", .{});
}

/// Answers a GET of `/` with an empty 200. The program never runs the server, so no request
/// arrives.
fn on_root(_: *void, _: *colibri.server.RequestContext, _: *const colibri.server.Request, response: *colibri.server.Response) !void {
    try response.end();
}

/// Answers 500 when a route's function fails (RFC 9110 §15.6.1).
fn on_route_error(_: *void, _: *colibri.server.RequestContext, _: *const colibri.server.Request, _: anyerror, response: *colibri.server.Response) void {
    response.status = .internal_server_error;
}

/// tls converts the client's values once, and a session's first call writes its ClientHello. The
/// values hold the program's one context, and the session draws from its source.
fn check_tls(crypto: stdx.crypto.Context) !void {
    const anchors = [_]tls.Anchor{.{ .subject = &empty_sequence, .spki = &empty_sequence }};
    try tls_config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "example.test" } },
        .alpn = &.{ "h2", "http/1.1" },
        .crypto = crypto,
    });
    try tls_client.start(&tls_config, now_seconds, null);
    const hello = try tls_client.handshake(&.{}, &output);
    if (hello.written == 0 or output[0] != handshake_record) return error.HelloWrong;
    // What the handshake selected, the key-exchange group among it, is null until it completes.
    const provider = tls_client.provider();
    if (provider.negotiated_parameters()) |chosen| {
        std.debug.print("consumer: group 0x{x:0>4}\n", .{chosen.group});
        return error.NegotiatedWrong;
    }
    // A program that finds an error in what it read, such as a record longer than RFC 9846 §5.2
    // allows, sends the alert that names it, then closes. A session whose handshake has not
    // completed sends none.
    if (tls_client.fail(.record_overflow, &output)) |_| return error.FailWrong else |failure| {
        if (failure != error.NotConnected) return error.FailWrong;
    }
    tls_client.close();
}

/// The server reads the first `len` bytes of `wire`, which the socket of `accepted` read. It
/// answers each request with 204, by the request's id, and sends what its connection owes at each
/// `send` event.
fn serve(accepted: server_module.ConnectionHandle, len: usize) !void {
    var consumed: usize = 0;
    for (0..events_per_round_max) |_| {
        const read: server_module.StreamBytes = .{ .connection = accepted, .bytes = wire[consumed..len] };
        engine.receive(.{ .stream = read }, 0, &engine_received);
        const received = &engine_received;
        consumed += received.consumed;
        const event = if (received.event) |*reported| reported else {
            if (received.consumed == 0) return;
            continue;
        };
        switch (event.*) {
            .request => |request| try engine.respond(request.id, .{ .status = .no_content, .end = true }),
            .send => |connection| try send(connection),
            else => {},
        }
    }
}

/// Writes what `connection` owes its socket into `server_output`, which the client then reads.
/// One call takes all this exchange owes. A call that filled the buffer would leave more owed,
/// and a program then calls again.
fn send(connection: server_module.ConnectionHandle) !void {
    const written = engine.send_stream(connection, &server_output, 0);
    if (written == server_output.len) return error.ExchangeWrong;
    hear(server_output[0..written]);
}

/// The client reads `octets`, which the server wrote, and its response holds what they say. Each
/// call passes the bytes it still holds, or `.none` when it holds none.
fn hear(octets: []u8) void {
    var consumed: usize = 0;
    for (0..events_per_round_max) |_| {
        const held = octets[consumed..];
        const read: client_module.Input = if (held.len > 0) .{ .stream = .{ .connection = asked_connection, .bytes = held } } else .none;
        const received = asked.receive(read, 0);
        consumed += received.consumed;
        if (received.event == null and received.consumed == 0) return;
    }
}
