//! What the tests of a stream route that answers while its client still sends share (decision 127
//! as amended, design §8 step 46). The route owes `App.reply_len` bytes for each request byte,
//! and writes them from `on_data` and `next`. The route table names it beside a function route,
//! which answers once the body ended (decision 163 ruling 4). Test-only.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const Response = @import("../response/response.zig").Response;
const RequestBodyStream = @import("../request_body_stream.zig").RequestBodyStream;
const RequestContext = @import("../request_context.zig").RequestContext;
const Router = @import("router.zig").Router;

/// Bytes of the entry's response memory, body memory and header memory, and of each message the
/// route writes. Test-only.
pub const response_buffer_bytes = 256;
const request_body_bytes = 16;
const request_header_bytes = 128;
const message_len = 100;
/// The prime that `octet_at` counts modulo, so no message repeats the one before it.
const pattern_period = 251;
/// The writes one call makes at most: more than a reply of the longest test holds.
const writes_max = 4096;
const internal_server_error: http.Status = .internal_server_error;

/// The byte at `offset` of each test's response.
pub fn octet_at(offset: usize) u8 {
    return @intCast(offset % pattern_period);
}

/// Whether `bytes` is the start of each test's response, `len` bytes long.
pub fn is_reply(bytes: []const u8, len: usize) bool {
    if (bytes.len != len) return false;
    for (bytes, 0..) |octet, offset| {
        if (octet != octet_at(offset)) return false;
    }
    return true;
}

/// What a test sets for its route, and what the route did.
pub const App = struct {
    /// Bytes the route owes for each request byte, and at the request's head.
    reply_len: usize,
    head_len: usize = 0,
    /// Bytes the route wrote through `body()`, the calls of `next` while the request body was
    /// open, and those of them that wrote nothing.
    written: usize = 0,
    open_calls: usize = 0,
    idle_calls: usize = 0,
    /// Whether the route ended its response.
    ended: bool = false,
    /// The calls of the function route, and the bytes of the body it read.
    whole_calls: usize = 0,
    body_len: usize = 0,
};

/// Owes `App.head_len` bytes at the head and `App.reply_len` for each request byte, writes what
/// it owes from each of its calls, and ends the response once the request body ended and it owes nothing.
pub const Duplex = struct {
    pub const State = struct { owed: usize = 0, body_ended: bool = false };

    pub fn on_request(app: *App, _: *RequestContext, state: *State, _: *const event.Request, response: *Response) !void {
        try response.header("content-type", "application/octet-stream");
        state.owed = app.head_len;
        try write_owed(app, state, response);
    }

    pub fn on_data(app: *App, _: *RequestContext, state: *State, body: *RequestBodyStream, response: *Response) !void {
        // Bounded: each pass takes one piece of the bytes that arrived.
        for (0..writes_max) |_| {
            const piece = body.next() orelse break;
            state.owed += piece.len * app.reply_len;
        }
        // The stream ends once `next` found the request's end.
        state.body_ended = body.ended();
        try write_owed(app, state, response);
    }

    pub fn next(app: *App, _: *RequestContext, state: *State, response: *Response) !void {
        if (!state.body_ended) app.open_calls += 1;
        const before = app.written;
        try write_owed(app, state, response);
        if (!state.body_ended and app.written == before) app.idle_calls += 1;
    }
};

/// Reads the whole body in its one call, and owes `App.head_len` bytes, which it writes before it
/// ends the response. The engine takes a part of them, and the router writes the rest once the
/// engine has room.
pub fn whole(app: *App, _: *RequestContext, request: *const event.Request, response: *Response) !void {
    app.whole_calls += 1;
    var bytes: [request_body_bytes]u8 = undefined;
    app.body_len = try request.body.readSliceShort(&bytes);
    var state: Duplex.State = .{ .owed = app.head_len, .body_ended = true };
    try write_owed(app, &state, response);
}

/// Writes what the route owes, one message at a time, each flushed. A message that does not fit
/// waits for the next call. Ends the response once the body ended and nothing is owed.
fn write_owed(app: *App, state: *Duplex.State, response: *Response) !void {
    const writer = response.body();
    var message: [message_len]u8 = undefined;
    // Bounded: each pass writes one message.
    for (0..writes_max) |_| {
        if (state.owed == 0) break;
        const len = @min(message_len, state.owed);
        for (message[0..len], app.written..) |*octet, offset| octet.* = octet_at(offset);
        writer.writeAll(message[0..len]) catch return;
        try writer.flush();
        app.written += len;
        state.owed -= len;
    }
    if (state.owed == 0 and state.body_ended and !app.ended) {
        app.ended = true;
        try response.end();
    }
}

fn on_error(_: *App, _: *RequestContext, _: *const event.Request, _: anyerror, response: *Response) void {
    response.status = internal_server_error;
}

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .post, "/duplex", Duplex },
        .{ .post, "/whole", whole },
    },
};

pub const Pool = Router(App, routes, .{ .requests = 1, .response_buffer_bytes = response_buffer_bytes, .request_body_bytes = request_body_bytes, .request_header_bytes = request_header_bytes });
