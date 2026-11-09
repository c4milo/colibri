//! What the tests of a struct route that answers while its client still sends share (decision 127
//! as amended, design §8 step 46): a route that owes `App.reply_len` octets for each request octet
//! and writes them from `on_body` and `on_writable`, and the route table that names it twice, once
//! with `.whole_body`. Test-only.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const Router = @import("router.zig").Router;

/// Octets of the entry's response memory and of its body memory, and of each message the route
/// writes. Test-only.
pub const response_bytes = 256;
const body_bytes = 16;
const message_len = 100;
/// The prime that `octet_at` counts modulo, so no message repeats the one before it.
const pattern_period = 251;
/// The writes one call makes at most: more than a reply of the longest test holds.
const writes_max = 4096;
const internal_server_error: http.Status = .internal_server_error;

/// The octet at `offset` of each test's response.
pub fn octet_at(offset: usize) u8 {
    return @intCast(offset % pattern_period);
}

/// Whether `bytes` is the start of each test's response, `len` octets long.
pub fn is_reply(bytes: []const u8, len: usize) bool {
    if (bytes.len != len) return false;
    for (bytes, 0..) |octet, offset| {
        if (octet != octet_at(offset)) return false;
    }
    return true;
}

/// What a test sets for its route, and what the route did.
pub const App = struct {
    /// Octets the route owes for each request octet, and at the request's head.
    reply_len: usize,
    head_len: usize = 0,
    /// Octets the route wrote through `body()`, the calls of `on_writable` while the request body
    /// was open, and those of them that wrote nothing.
    written: usize = 0,
    open_calls: usize = 0,
    idle_calls: usize = 0,
    /// Whether the route ended its response.
    ended: bool = false,
};

/// Owes `App.head_len` octets at the head and `App.reply_len` for each request octet, writes what
/// it owes from each of its calls, and ends the response once the request body ended and it owes nothing.
pub const Duplex = struct {
    pub const State = struct { owed: usize = 0, body_ended: bool = false };

    pub fn on_request(app: *App, state: *State, _: *const event.Request, _: void, _: void, response: *ResponseWriter) !void {
        try response.header("content-type", "application/octet-stream");
        state.owed = app.head_len;
        try write_owed(app, state, response);
    }

    pub fn on_body(app: *App, state: *State, reader: *std.Io.Reader, response: *ResponseWriter) !void {
        const bytes = reader.buffered();
        reader.toss(bytes.len);
        state.owed += bytes.len * app.reply_len;
        // The body reader fails with `error.EndOfStream` at the request's last byte only.
        if (reader.peekByte()) |_| unreachable else |failure| state.body_ended = failure == error.EndOfStream;
        try write_owed(app, state, response);
    }

    pub fn on_writable(app: *App, state: *State, response: *ResponseWriter) !void {
        if (!state.body_ended) app.open_calls += 1;
        const before = app.written;
        try write_owed(app, state, response);
        if (!state.body_ended and app.written == before) app.idle_calls += 1;
    }
};

/// Writes what the route owes, one message at a time, each flushed. A message that does not fit
/// waits for the next call. Ends the response once the body ended and nothing is owed.
fn write_owed(app: *App, state: *Duplex.State, response: *ResponseWriter) !void {
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

fn on_error(_: *App, _: *const event.Request, _: anyerror, response: *ResponseWriter) void {
    response.status = internal_server_error;
}

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .post, "/duplex", Duplex },
        .{ .post, "/whole", Duplex, .{ .whole_body = true } },
    },
};

pub const Pool = Router(App, routes, .{ .requests = 1, .response_bytes = response_bytes, .body_bytes = body_bytes });
