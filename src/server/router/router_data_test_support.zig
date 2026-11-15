//! What the tests of a stream route's `on_data` share (decision 163 ruling 6, design §8 step 50f):
//! routes that read each piece of a body through `server.RequestBodyStream`, keep the end of a piece,
//! read messages that two events cut, and answer at the head. Test-only.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const Response = @import("../response/response.zig").Response;
const RequestBodyStream = @import("../request_body_stream.zig").RequestBodyStream;
const RequestContext = @import("../request_context.zig").RequestContext;
const Next = @import("../middleware.zig").Next;
const Router = @import("router.zig").Router;

/// The calls of `on_data` a test records, the pieces one call takes at most, and octets of each
/// text a test records. Test-only.
pub const calls_max = 8;
const pieces_max = 16;
const piece_len_max = 32;
/// Octets of the buffer of each wrapper of the request body.
pub const small_buffer_len = 4;
const large_buffer_len = 8;

/// A copy of a short text. Test-only.
pub const Text = struct {
    bytes: [piece_len_max]u8 = @splat(0),
    len: usize = 0,

    fn set(text: *Text, from: []const u8) void {
        std.debug.assert(from.len <= piece_len_max);
        @memcpy(text.bytes[0..from.len], from);
        text.len = from.len;
    }

    fn add(text: *Text, from: []const u8) void {
        std.debug.assert(text.len + from.len <= piece_len_max);
        @memcpy(text.bytes[text.len..][0..from.len], from);
        text.len += from.len;
    }

    pub fn get(text: *const Text) []const u8 {
        return text.bytes[0..text.len];
    }
};

pub const App = struct {
    /// The calls of `on_request` and of `on_data`.
    heads: usize = 0,
    calls: usize = 0,
    /// For each call of `on_data`: its first piece, its pieces, and `ended` at its end.
    firsts: [calls_max]Text = @splat(.{}),
    pieces: [calls_max]usize = @splat(0),
    ended_at: [calls_max]bool = @splat(false),
    /// Every octet the pieces gave, without the octets they gave again after a `keep`.
    collected: Text = .{},
    /// Octets of each piece that `Collect` keeps, and whether it then calls `keep(0)`.
    keep_len: usize = 0,
    keep_none: bool = false,
    /// The messages `Framed` read, one after the other, and the call of `on_data` that read each.
    messages: Text = .{},
    message_calls: [calls_max]usize = @splat(0),
    message_count: usize = 0,

    /// Records that call `call` of `on_data` got `piece`, of which the first `given_again` octets
    /// came before.
    fn record(app: *App, call: usize, piece: []const u8, given_again: usize) void {
        if (app.pieces[call] == 0) app.firsts[call].set(piece);
        app.pieces[call] += 1;
        app.collected.add(piece[given_again..]);
    }

    /// The call that ran last.
    pub fn last_call(app: *const App) usize {
        std.debug.assert(app.calls > 0);
        return app.calls - 1;
    }
};

/// Records each piece of the body, and keeps `App.keep_len` octets of each.
const Collect = struct {
    pub const State = struct { kept: usize = 0 };

    pub fn on_request(app: *App, _: *RequestContext, _: *State, _: *const event.Request, _: *Response) !void {
        app.heads += 1;
    }

    pub fn on_data(app: *App, _: *RequestContext, state: *State, body: *RequestBodyStream, _: *Response) !void {
        const call = app.calls;
        app.calls += 1;
        // Bounded: each pass takes one piece.
        for (0..pieces_max) |_| {
            const piece = body.next() orelse break;
            app.record(call, piece, state.kept);
            state.kept = @min(app.keep_len, piece.len);
            body.keep(state.kept);
            if (app.keep_none) {
                body.keep(0);
                state.kept = 0;
            }
        }
        app.ended_at[call] = body.ended();
    }
};

/// Reads messages of one octet of length and that many octets, as Connect and gRPC frame theirs
/// with a longer prefix. A message that a piece holds a part of stays unread.
const Framed = struct {
    pub fn on_request(_: *App, _: *RequestContext, _: *void, _: *const event.Request, _: *Response) !void {}

    pub fn on_data(app: *App, _: *RequestContext, _: *void, body: *RequestBodyStream, _: *Response) !void {
        const call = app.calls;
        app.calls += 1;
        // Bounded: each pass takes one piece.
        for (0..pieces_max) |_| {
            const piece = body.next() orelse break;
            body.keep(read_messages(app, call, piece).len);
        }
        app.ended_at[call] = body.ended();
    }

    /// Reads each whole message at the start of `piece`, and returns the octets after them.
    fn read_messages(app: *App, call: usize, piece: []const u8) []const u8 {
        var rest = piece;
        // Bounded: each pass takes one message of one octet at least.
        for (0..piece.len) |_| {
            if (rest.len == 0 or rest.len <= rest[0]) break;
            app.messages.add(rest[1..][0..rest[0]]);
            app.message_calls[app.message_count] = call;
            app.message_count += 1;
            rest = rest[1 + rest[0] ..];
        }
        return rest;
    }
};

/// Refuses each request at the head, with 403 and no content.
const Refused = struct {
    pub fn on_request(app: *App, _: *RequestContext, _: *void, _: *const event.Request, response: *Response) !void {
        app.heads += 1;
        response.status = forbidden;
        try response.end();
    }

    pub fn on_data(app: *App, _: *RequestContext, _: *void, _: *RequestBodyStream, _: *Response) !void {
        app.calls += 1;
    }
};

/// Answers 202 with a header at the head, and leaves the response for the router to end.
const HeadOnly = struct {
    pub fn on_request(app: *App, _: *RequestContext, _: *void, _: *const event.Request, response: *Response) !void {
        app.heads += 1;
        response.status = accepted;
        try response.header("x-kind", "head");
    }
};

/// Answers 201 with a header from `on_request`, and with what the body held once it ended.
const Created = struct {
    pub fn on_request(app: *App, _: *RequestContext, _: *void, _: *const event.Request, response: *Response) !void {
        app.heads += 1;
        response.status = created;
        try response.header("x-kind", "stream");
    }

    pub fn on_data(app: *App, _: *RequestContext, _: *void, body: *RequestBodyStream, response: *Response) !void {
        app.calls += 1;
        // Bounded: each pass writes one piece.
        for (0..pieces_max) |_| {
            const piece = body.next() orelse break;
            try response.body().writeAll(piece);
        }
        if (body.ended()) try response.end();
    }
};

/// A middleware that adds a header to the `Response` it gets.
const Brand = struct {
    pub fn on_request(_: *App, _: *RequestContext, _: *const event.Request, response: *Response) !Next {
        try response.header("server", "colibri");
        return .next;
    }
};

/// A wrapper of the request body's reader with a buffer of `buffer_len` octets, which passes each
/// octet as it is, one octet a read.
fn Passing(comptime buffer_len: usize) type {
    return struct {
        pub const State = struct {
            reader: std.Io.Reader = undefined,
            buffer: [buffer_len]u8 = undefined,
            inner: *std.Io.Reader = undefined,
        };

        pub fn wrap_body(_: *App, _: *RequestContext, state: *State, _: *const event.Request, inner: *std.Io.Reader) ?*std.Io.Reader {
            state.* = .{ .reader = .{ .vtable = &vtable, .buffer = &state.buffer, .seek = 0, .end = 0 }, .inner = inner };
            return &state.reader;
        }

        const vtable: std.Io.Reader.VTable = .{ .stream = stream };

        fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            if (limit == .nothing) return 0;
            const state: *State = @alignCast(@fieldParentPtr("reader", reader));
            try writer.writeByte(try state.inner.takeByte());
            return 1;
        }
    };
}

/// A middleware whose `wrap_body` keeps the reader it got, as docs/usage.md allows.
const Keeping = struct {
    pub const State = struct {};

    pub fn wrap_body(_: *App, _: *RequestContext, _: *State, _: *const event.Request, _: *std.Io.Reader) ?*std.Io.Reader {
        return null;
    }
};

fn on_error(_: *App, _: *RequestContext, _: *const event.Request, _: anyerror, response: *Response) void {
    response.status = .internal_server_error;
}

/// The statuses the routes choose. Test-only.
pub const forbidden: http.Status = .forbidden;
pub const accepted: http.Status = .accepted;
pub const created: http.Status = .created;

pub const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .post, "/collect", Collect },
        .{ .post, "/framed", Framed },
        .{ .post, "/framed-wrapped", Framed, .{ .middleware = .{Passing(large_buffer_len)} } },
        .{ .post, "/framed-kept-reader", Framed, .{ .middleware = .{Keeping} } },
        .{ .post, "/collect-wrapped", Collect, .{ .middleware = .{Passing(small_buffer_len)} } },
        .{ .post, "/refused", Refused },
        .{ .post, "/head-only", HeadOnly },
        .{ .post, "/created", Created, .{ .middleware = .{Brand} } },
    },
};

/// Octets of each entry's response memory and body memory. Test-only.
pub const response_bytes = 128;
pub const body_bytes = 16;

pub const Pool = Router(App, routes, .{ .requests = 1, .response_bytes = response_bytes, .body_bytes = body_bytes, .header_bytes = 0 });
