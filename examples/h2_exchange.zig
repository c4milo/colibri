//! Example: an h2 client asks for a resource, and an h2 server answers it.
//!
//! Each side runs the loop every h2 program runs: hand colibri the octets that arrived, one frame
//! per `receive`, then write what colibri owes with `write_pending` and send it. What colibri owes
//! on its own is the connection preface, its SETTINGS, and the acknowledgment of the peer's
//! (RFC 9113 §3.4, §6.5.3). What the application sends goes through `write_request`,
//! `write_response` and `write_data`. Every call that needs the instant takes the one the side's
//! loop read. Both run over `link.zig`, which stands where a program's sockets would be.
//!
//! The program checks what arrived: the client must see 200 and the greeting, octet for octet.
//! Anything else exits with an error, which is how `zig build examples` and CI know the example
//! still works.
//!
//! Run it with `zig build example-h2_exchange`, or every example with `zig build examples`.
const std = @import("std");
const h2 = @import("h2");
const link_module = @import("link.zig");

const Connection = h2.connection.Connection;
const Link = link_module.Link;
const Side = link_module.Side;

/// The octets one side writes before it sends them, at most.
const output_len = 16384;

/// Rounds of both sides reading and writing before the example gives up.
const rounds_max = 16;

/// Frames one side reads in one round, at most.
const frames_per_round_max = 64;

const greeting = "hello from colibri over h2\n";

/// The status the client must see.
const status_expected = 200;

/// Where the exchange stands, and what the client received, which `main` checks at the end.
const State = struct {
    /// The stream the server answers on, once its request has arrived.
    request_stream: ?u32 = null,
    answered: bool = false,
    /// The client has the whole response.
    done: bool = false,
    status: u16 = 0,
    body: [greeting.len]u8 = undefined,
    body_len: usize = 0,
    /// The client received more body octets than the server sent.
    overflowed: bool = false,
};

pub const Error = error{
    /// The exchange did not end within `rounds_max` rounds.
    ExchangeUnfinished,
    /// What arrived is not what was sent.
    ExchangeWrong,
};

// The connections and the link hold tens of kilobytes each, so they live outside the stack.
var link: Link align(@alignOf(Link)) = undefined;
var client: Connection align(@alignOf(Connection)) = undefined;
var server: Connection align(@alignOf(Connection)) = undefined;
var output: [output_len]u8 = undefined;

pub fn main() !void {
    try link.init();
    defer link.deinit();
    client.init(.client);
    server.init(.server);

    // The client's first octets: its preface and SETTINGS, then a request on a new stream. GET
    // carries no content, so the request ends the stream.
    const preface_len = client.write_pending(&output, link.now_ns(.client));
    const sent = try client.write_request(output[preface_len..], .{
        .method = "GET",
        .scheme = "https",
        .authority = "example.test",
        .path = "/greeting",
    }, &.{.{ .name = "user-agent", .value = "colibri-example" }}, &.{}, true);
    std.debug.print("client: GET /greeting on stream {d}\n", .{sent.stream_id});
    try link.send(.client, output[0 .. preface_len + sent.written]);

    var state: State = .{};
    for (0..rounds_max) |_| {
        try step(&server, .server, &state);
        try step(&client, .client, &state);
        if (state.done) return check(&state);
    }
    return error.ExchangeUnfinished;
}

/// The client saw the status the server sent, and every octet of the body.
fn check(state: *const State) Error!void {
    const body_right = !state.overflowed and std.mem.eql(u8, state.body[0..state.body_len], greeting);
    if (state.status == status_expected and body_right) {
        std.debug.print("h2_exchange: every octet arrived as sent\n", .{});
        return;
    }
    std.debug.print("h2_exchange: status {d}, body {s}\n", .{ state.status, if (body_right) "as sent" else "changed" });
    return error.ExchangeWrong;
}

/// One round of one side: read every frame that arrived, answer what the application owes, then
/// write what colibri owes and send it.
fn step(connection: *Connection, side: Side, state: *State) !void {
    const input = try link.receive(side);
    var consumed: usize = 0;
    for (0..frames_per_round_max) |_| {
        const received = try connection.receive(input[consumed..], link.now_ns(side));
        if (received.event) |event| handle(side, event, state);
        consumed += received.consumed;
        if (received.consumed == 0) break;
    }
    // Every slice an event carried points into the queue, so it is consumed only now.
    link.consume(side, consumed);
    // What colibri owes goes first: a server's SETTINGS must be the first frame it sends
    // (RFC 9113 §3.4). Anything the answer made owed goes out after it.
    var written = connection.write_pending(&output, link.now_ns(side));
    if (side == .server and state.request_stream != null and !state.answered) {
        written += try answer(output[written..], state.request_stream.?);
        state.answered = true;
    }
    written += connection.write_pending(output[written..], link.now_ns(side));
    try link.send(side, output[0..written]);
}

fn handle(side: Side, event: h2.connection.Event, state: *State) void {
    switch (event) {
        .request => |request| {
            std.debug.print("server: {s} {s} on stream {d}\n", .{
                request.request.method,
                request.request.path orelse "",
                request.stream_id,
            });
            state.request_stream = request.stream_id;
        },
        .response => |response| {
            std.debug.print("client: {d} on stream {d}\n", .{ response.response.status.code, response.stream_id });
            state.status = response.response.status.code;
        },
        .data => |data| {
            std.debug.print("{s}: body {s}", .{ @tagName(side), data.payload });
            keep_body(state, data.payload);
            if (data.end_stream) state.done = true;
        },
        .settings_applied => std.debug.print("{s}: the peer's SETTINGS applied\n", .{@tagName(side)}),
        else => {},
    }
}

fn keep_body(state: *State, payload: []const u8) void {
    if (state.body_len + payload.len > state.body.len) {
        state.overflowed = true;
        return;
    }
    @memcpy(state.body[state.body_len..][0..payload.len], payload);
    state.body_len += payload.len;
}

/// Writes the server's response: a HEADERS frame, then the content in a DATA frame that ends the
/// stream.
fn answer(buffer: []u8, stream_id: u32) !usize {
    const head_len = try server.write_response(buffer, stream_id, 200, &.{
        .{ .name = "content-length", .value = std.fmt.comptimePrint("{d}", .{greeting.len}) },
    }, false);
    const data = try server.write_data(buffer[head_len..], stream_id, greeting, true);
    std.debug.assert(data.consumed == greeting.len);
    return head_len + data.written;
}
