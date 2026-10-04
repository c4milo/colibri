//! Example: a client sends two requests over TLS and a server answers them, through colibri's
//! `client` and `server` modules.
//!
//! The two modules put one set of calls over h11 and h2 (decision 100). Each connection runs its
//! TLS handshake itself, and ALPN picks the version during it: here h2, which both sides prefer.
//! The program never names h2 again: the server answers a request by its id, and the client gets
//! one outcome for each exchange it placed, in memory it owns.
//!
//! Each side does three things in a turn. It hands colibri the octets that arrived and takes one
//! event from each `receive`. It acts on the event. It sends what `send` writes. Both run over
//! `link.zig`, which stands where a program's sockets would be, and `tls_program.zig` holds what
//! any program that links `tls` defines once.
//!
//! The program checks what arrived: the client must see 200 twice, the greeting, the note it
//! posted and the content type, octet for octet. Anything else exits with an error, which is how
//! `zig build examples` and CI know the example still works.
//!
//! Run it with `zig build example-tls_exchange`, or every example with `zig build examples`.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const server = @import("server");
const tls = @import("tls");
const platform = @import("platform");
const identity = @import("testdata");
const program = @import("tls_program.zig");
const link_module = @import("link.zig");

const Link = link_module.Link;

/// The octets one side writes before it sends them, at most.
const output_len = 16384;

/// Turns of both sides before the example gives up.
const turns_max = 32;

/// Events one side takes in one turn, at most.
const events_per_turn_max = 64;

const greeting = "hello from colibri over TLS\n";
const note = "a note the client posts, which the server sends back\n";
const content_type = "text/plain; charset=utf-8";

/// The name the server's certificate carries, which the client asks for and judges it by.
const origin = "localhost";

/// The versions each side offers through ALPN, most preferred first (RFC 7301 §3.1).
const protocols = [_][]const u8{ "h2", "http/1.1" };

/// Unix seconds. A program reads them from its clock; colibri reads no clock. The client judges
/// the server's certificates at this instant, which the test identity is valid at.
const now_seconds = identity.now_seconds;

pub const Error = error{
    /// The connections had not both ended within `turns_max` turns.
    ExchangeUnfinished,
    /// What arrived is not what was sent.
    ExchangeWrong,
};

// The link and the connections hold hundreds of kilobytes, so they live outside the stack.
var link: Link align(@alignOf(Link)) = undefined;
var output: [output_len]u8 = undefined;

// The server: its TLS configuration, which every connection borrows, and one connection.
// colibri's test identity stands in for the certificate and the key a program loads.
const chain = [_][]const u8{ identity.leaf, identity.root };
var cookie_key: [tls.constants.server_key_len]u8 = undefined;
var server_tls: tls.record.ServerConfig align(@alignOf(tls.record.ServerConfig)) = undefined;
var server_config: server.Config align(@alignOf(server.Config)) = undefined;
var server_connection: server.Connection align(@alignOf(server.Connection)) = undefined;
/// The content of the POST the server is reading, which it sends back once the request ends.
var posted: [note.len]u8 = undefined;
var posted_len: usize = 0;
/// Responses the peer has in full.
var answered: u32 = 0;

// The client: its TLS configuration, one connection, and an exchange for each request. An exchange
// holds the request and the memory its response goes into.
const anchors = [_]tls.Anchor{.{ .subject = identity.root_name, .spki = identity.root_spki }};
var client_tls: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var client_config: client.Config align(@alignOf(client.Config)) = undefined;
var client_connection: client.Connection align(@alignOf(client.Connection)) = undefined;
/// The fields of the response the client reads. colibri keeps no other field.
var wanted: [1]client.Wanted align(@alignOf(client.Wanted)) = .{.{ .name = "content-type" }};
var wanted_values: [content_type.len]u8 = undefined;
var get_body: [greeting.len]u8 = undefined;
var post_body: [note.len]u8 = undefined;
var get: client.HttpExchange align(@alignOf(client.HttpExchange)) = .{
    .method = "GET",
    .path = "/greeting",
    .wanted = &wanted,
    .values = &wanted_values,
    .body = &get_body,
};
var post: client.HttpExchange align(@alignOf(client.HttpExchange)) = .{
    .method = "POST",
    .path = "/echo",
    .fields = &.{.{ .name = "content-type", .value = content_type }},
    .content = note,
    .body = &post_body,
};
/// Exchanges that have ended, and the version ALPN picked.
var finished: u32 = 0;
var spoken: ?client.Protocol align(@alignOf(client.Protocol)) = null;

pub fn main() !void {
    try link.init();
    defer link.deinit();
    // A program probes its CPU once, and passes the answer to every TLS configuration.
    const cpu = platform.probe();
    try start_server(cpu);
    try start_client(cpu);
    for (0..turns_max) |_| {
        try client_turn();
        try server_turn();
        if (client_connection.should_close() and server_connection.should_close()) break;
    } else return error.ExchangeUnfinished;
    // `should_close` says when to close the transport: the connection is over and `send` has
    // written everything, the TLS close_notify too. `transport_closed` then wipes the session's
    // secrets.
    client_connection.transport_closed();
    server_connection.transport_closed();
    return check();
}

fn start_server(cpu: tls.Cpu) !void {
    // RFC 9846 §4.3.2's cookie key, which a server draws once.
    program.fill(&cookie_key);
    try server_tls.init(.{
        .ecdsa_p256 = .{
            .chain = &chain,
            .public_key = identity.public_key,
            .private_key = identity.private_key,
        },
        .cookie_key = &cookie_key,
        .alpn = &protocols,
        .cpu = cpu,
    });
    server_config = .{ .tls = &server_tls };
    // One call for each connection the listener accepts, in storage the program owns.
    try server_connection.init(&server_config, program.random(), now_seconds, link.now_ns(.server));
}

fn start_client(cpu: tls.Cpu) !void {
    try client_tls.init(.{
        .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = origin } },
        .alpn = &protocols,
        .cpu = cpu,
    });
    client_config = .{ .tls = &client_tls, .authority = origin };
    try client_connection.init(&client_config, program.random(), now_seconds, null);
    // `request` only takes an exchange. `send` writes it once the handshake has picked the
    // version, so a program asks at once and never waits for the connection.
    _ = try client_connection.request(&get);
    _ = try client_connection.request(&post);
}

/// One turn of the server: read every event that arrived, answer, and send.
fn server_turn() !void {
    const input = try link.receive(.server);
    const now_ns = link.now_ns(.server);
    var consumed: usize = 0;
    for (0..events_per_turn_max) |_| {
        const received = try server_connection.receive(input[consumed..], now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        try serve(event);
    }
    // What an event carried points into the queue, so the queue is consumed only now.
    link.consume(.server, consumed);
    try link.send(.server, output[0..server_connection.send(&output, now_ns)]);
    // Decision 110: a deadline bounds how long a peer may hold the connection. A program sleeps
    // until `deadline_ns` and then calls `on_instant`, which ends a connection whose peer is late.
    server_connection.on_instant(now_ns);
}

/// Acts on one event of the server. A request is answered by its id, in h11 and h2 alike.
fn serve(event: server.Event) !void {
    switch (event) {
        .request => |request| {
            std.debug.print("server: {s} {s}\n", .{ request.method, request.target });
            if (is(request, "GET", "/greeting")) return answer(request.id, greeting);
            // The POST's content follows in `body` events, and the answer waits for its end.
            if (is(request, "POST", "/echo")) return;
            try server_connection.respond(request.id, .{ .status = 404, .end = true });
        },
        .body => |body| {
            if (posted_len + body.octets.len > posted.len) return error.ExchangeWrong;
            @memcpy(posted[posted_len..][0..body.octets.len], body.octets);
            posted_len += body.octets.len;
            if (body.end) try answer(body.id, posted[0..posted_len]);
        },
        // The peer has the whole response to this request.
        .done => answered += 1,
        .trailers, .cancelled => {},
    }
}

fn is(request: server.Request, method: []const u8, path: []const u8) bool {
    if (!std.mem.eql(u8, request.method, method)) return false;
    return std.mem.eql(u8, request.path orelse "", path);
}

/// Answers request `id` with 200 and `content`: the head, then the content, which ends the
/// response.
fn answer(id: server.Id, content: []const u8) !void {
    var digits: [8]u8 = undefined;
    const length = std.fmt.bufPrint(&digits, "{d}", .{content.len}) catch unreachable;
    try server_connection.respond(id, .{
        .status = 200,
        .fields = &.{
            .{ .name = "content-type", .value = content_type },
            .{ .name = "content-length", .value = length },
        },
        .end = false,
    });
    // `write_body` returns the octets it took. It takes fewer than it was given when the room or
    // the peer's window runs out, and a program then calls it again with the rest after `send`.
    const taken = try server_connection.write_body(id, .{ .octets = content, .end = true });
    assert(taken == content.len);
}

/// One turn of the client: send what the connection owes, then read every event that arrived.
fn client_turn() !void {
    const input = try link.receive(.client);
    const now_ns = link.now_ns(.client);
    try link.send(.client, output[0..client_connection.send(&output, now_ns)]);
    var consumed: usize = 0;
    for (0..events_per_turn_max) |_| {
        const received = client_connection.receive(input[consumed..], now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        report(event);
    }
    link.consume(.client, consumed);
}

/// Acts on one event of the client. Each exchange ends in one `finished` event, whatever happened
/// to it: its `outcome` says whether the response arrived.
fn report(event: client.Event) void {
    switch (event) {
        .connected => |protocol| {
            std.debug.print("client: connected over {s}\n", .{@tagName(protocol)});
            spoken = protocol;
        },
        .finished => |ended| {
            const exchange = ended.exchange;
            std.debug.print("client: {s}: {s}, {d}\n", .{
                exchange.path, @tagName(exchange.outcome), exchange.status,
            });
            finished += 1;
            // Every exchange has ended, so the client ends the connection.
            if (finished == exchanges_count) client_connection.shutdown();
        },
        // This client opens no second connection, so it wipes the ticket a server gives it.
        .ticket => if (client_connection.take_ticket()) |ticket| {
            var held = ticket;
            held.wipe();
        },
        .draining, .closed => {},
    }
}

/// The exchanges `start_client` requested.
const exchanges_count = 2;

/// The client saw what the server sent, and the server heard that each response arrived.
fn check() Error!void {
    const greeted = arrived(&get, greeting);
    const typed = std.mem.eql(u8, wanted[0].value orelse "", content_type);
    const echoed = arrived(&post, note);
    if (spoken == .h2 and greeted and typed and echoed and answered == exchanges_count) {
        std.debug.print("tls_exchange: every octet arrived as sent\n", .{});
        return;
    }
    std.debug.print("tls_exchange: greeting {}, content type {}, echo {}, answered {d}\n", .{
        greeted, typed, echoed, answered,
    });
    return error.ExchangeWrong;
}

/// Whether `exchange` ended in a 200 response whose content is `content`.
fn arrived(exchange: *const client.HttpExchange, content: []const u8) bool {
    if (exchange.outcome != .response or exchange.status != 200) return false;
    return std.mem.eql(u8, exchange.content_received(), content);
}
