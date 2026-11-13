//! The tests of the request context (decision 163 rulings 1 to 3, design §8 step 50c). Each
//! callback of one request gets the same `server.RequestContext`. A middleware writes the
//! request's values, and the route reads the same bytes. The route reads its path and its query
//! from the context, and `id()` is the request's id. The tests run against an engine that records
//! each call, then over h11, h2 and h3.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const Response = @import("../response/response.zig").Response;
const RequestContext = @import("../request_context.zig").RequestContext;
const Next = @import("../middleware.zig").Next;
const Router = @import("router.zig").Router;
const support = @import("router_handle_test_support.zig");
const tcp_support = @import("../engine/engine_tcp_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");
const quic_support = @import("../quic/quic_test_support.zig");

const testing = std.testing;
const Recorder = support.Recorder;

/// Octets of the longest text that the values or a route's state hold a copy of. Test-only.
const text_len_max = 8;

/// A copy of a short text. Test-only.
const Text = struct {
    bytes: [text_len_max]u8 = @splat(0),
    len: usize = 0,

    fn set(text: *Text, from: []const u8) void {
        std.debug.assert(from.len <= text_len_max);
        @memcpy(text.bytes[0..from.len], from);
        text.len = from.len;
    }

    fn get(text: *const Text) []const u8 {
        return text.bytes[0..text.len];
    }
};

/// What a middleware learns about one request, which the route table names as `.Values`
/// (decision 163 ruling 2). Test-only.
const Values = struct {
    /// The user that `Identify` wrote.
    user: Text = .{},
    /// The callbacks of the request that wrote into these values.
    writes: u8 = 0,
};

const App = struct {
    /// The user that `Identify` writes into each request's values.
    user: []const u8 = "",
    /// The values that `Identify` found at the last request's head, before it wrote.
    found: ?Values = null,
    /// The requests that finished, and what `Identify` read at the end of the last one.
    finished: usize = 0,
    finished_id: ?event.RequestId = null,
    finished_writes: u8 = 0,
    /// What `Later` read at the end of its request.
    later_id: ?event.RequestId = null,
    later_writes: u8 = 0,
    /// The user that the error function read, and the one that `Identify`'s wrapper read.
    error_user: Text = .{},
    wrapper_user: Text = .{},
};

/// The route table's middleware. It writes the user into the request's values at the head, as a
/// middleware that authenticates a request does. Its wrapper, which wraps nothing, and its
/// `on_finished` read the values again.
const Identify = struct {
    pub fn on_request(app: *App, ctx: *RequestContext, _: *const event.Request, _: *Response) Next {
        const values = ctx.values(Values);
        app.found = values.*;
        values.user.set(app.user);
        values.writes += 1;
        return .next;
    }

    pub fn wrap_body(app: *App, ctx: *RequestContext, _: *void, _: *const event.Request, _: *std.Io.Reader) ?*std.Io.Reader {
        app.wrapper_user = ctx.values(Values).user;
        return null;
    }

    pub fn on_finished(app: *App, ctx: *RequestContext, _: event.Result) void {
        app.finished += 1;
        app.finished_id = ctx.id();
        app.finished_writes = ctx.values(Values).writes;
    }
};

/// The path and the query that the entries of `who` and of `Later` name (decision 163 ruling 3).
/// Test-only.
const Name = struct { name: []const u8 };
const Mark = struct { mark: ?[]const u8 = null };

/// The word for a context whose id is `request`'s, or the word for another id.
fn id_word(ctx: *const RequestContext, request: *const event.Request) []const u8 {
    return if (ctx.id() == request.id) "same" else "other";
}

/// Answers with the user of the values, the path's name, the query's mark, and the word for the
/// context's id.
fn who(_: *App, ctx: *RequestContext, request: *const event.Request, response: *Response) !void {
    const values = ctx.values(Values);
    values.writes += 1;
    const mark = ctx.query(Mark).mark orelse "";
    try response.body().print("{s} {s}{s} {s}", .{ values.user.get(), ctx.path(Name).name, mark, id_word(ctx, request) });
    try response.end();
}

fn broken(_: *App, _: *RequestContext, _: *const event.Request, _: *Response) !void {
    return error.TestBroken;
}

/// A struct route. Its `on_request` copies the path's name into its state, because the context
/// lends the path during that call alone. Its `on_body` answers from the values and the state.
const Later = struct {
    pub const State = struct { name: Text = .{} };

    pub fn on_request(_: *App, ctx: *RequestContext, state: *State, _: *const event.Request, _: *Response) !void {
        state.name.set(ctx.path(Name).name);
        ctx.values(Values).writes += 1;
    }

    pub fn on_body(_: *App, ctx: *RequestContext, state: *State, _: *std.Io.Reader, response: *Response) !void {
        const values = ctx.values(Values);
        values.writes += 1;
        try response.body().print("{s} {s} {d}", .{ values.user.get(), state.name.get(), values.writes });
        try response.end();
    }

    pub fn on_finished(app: *App, ctx: *RequestContext, _: *State, _: event.Result) void {
        app.later_id = ctx.id();
        app.later_writes = ctx.values(Values).writes;
    }
};

/// Chooses 422, and keeps the user of the request's values.
fn on_error(app: *App, ctx: *RequestContext, _: *const event.Request, _: anyerror, response: *Response) void {
    response.status = unprocessable;
    app.error_user = ctx.values(Values).user;
}

const routes = .{
    .error_handler = on_error,
    .Values = Values,
    .middleware = .{Identify},
    .routes = .{
        .{ .get, "/who/:name", who, .{ .path = Name, .query = Mark } },
        .{ .post, "/later/:name", Later, .{ .path = Name } },
        .{ .get, "/broken", broken },
    },
};

/// One entry, so each request of a test holds the entry that the request before it held.
const Pool = Router(App, routes, .{ .requests = 1, .response_bytes = response_bytes });

/// Octets of the entry's response memory, and the status the error function chooses. Test-only.
const response_bytes = 64;
const unprocessable: http.Status = .unprocessable_content;

const Fixture = struct {
    app: App = .{ .user = "ada" },
    recorder: Recorder = .{},
    pool: Pool = .{},

    fn handle(fixture: *Fixture, received: event.Event) void {
        const handled = fixture.pool.handle(&fixture.app, &fixture.recorder, received);
        std.debug.assert(handled == .taken);
    }

    fn request(fixture: *Fixture, number: u64, method: []const u8, target: []const u8, end: bool) void {
        fixture.handle(.{ .request = support.request_of(number, method, target, end) });
    }

    fn finish(fixture: *Fixture, number: u64) void {
        fixture.handle(.{ .finished = .{ .id = id_of(number), .user_data = fixture.recorder.user_data, .result = .sent } });
    }

    /// The values of the pool's one entry, which a test reads as a program does not.
    fn values(fixture: *const Fixture) *const Values {
        return &fixture.pool.entries[0].values;
    }

    /// The request context of the pool's one entry, which a test reads between two callbacks.
    fn context(fixture: *const Fixture) *const RequestContext {
        return &fixture.pool.entries[0].request_context;
    }
};

/// The id of the request that `support.request_of` makes for `number`.
fn id_of(number: u64) event.RequestId {
    return @bitCast(@as(u128, number));
}

test "decision 163 ruling 2: a route reads the bytes that a middleware wrote into the values" {
    var fixture: Fixture = .{};
    fixture.request(1, "GET", "/who/x", true);
    try testing.expectEqualStrings("ada x same", fixture.recorder.body_bytes());
    // The middleware wrote once and the route once, into the same values.
    try testing.expectEqual(2, fixture.values().writes);
}

test "decision 163 ruling 2: a second request on the same entry starts from the defaults" {
    var fixture: Fixture = .{};
    fixture.request(1, "GET", "/who/x", true);
    fixture.finish(1);
    // The entry still holds what the first request wrote.
    try testing.expectEqualStrings("ada", fixture.values().user.get());
    try testing.expectEqual(2, fixture.values().writes);
    fixture.app.user = "";
    fixture.recorder = .{};
    fixture.request(2, "GET", "/who/y", true);
    try testing.expectEqual(Values{}, fixture.app.found.?);
    try testing.expectEqualStrings(" y same", fixture.recorder.body_bytes());
    try testing.expectEqual(2, fixture.values().writes);
}

test "decision 163 ruling 3: path and query give what the router read" {
    var fixture: Fixture = .{};
    // RFC 3986 §2.1: the router decodes the path's segment and the query's value.
    fixture.request(1, "GET", "/who/col%69bri?mark=%21", true);
    try testing.expectEqualStrings("ada colibri! same", fixture.recorder.body_bytes());
}

test "decision 163 ruling 3: the context lends the path and the query during the first call alone" {
    var fixture: Fixture = .{};
    fixture.request(1, "GET", "/who/x?mark=y", true);
    try testing.expectEqualStrings("ada xy same", fixture.recorder.body_bytes());
    // The router holds the path and the query for the route's first call alone. The request has
    // not finished, and its context keeps no pointer to them.
    try testing.expectEqual(null, fixture.context().path_held.pointer);
    try testing.expectEqual(null, fixture.context().query_held.pointer);
    // The values are the entry's own, so the context keeps its pointer to them.
    const held: *const anyopaque = fixture.context().values_held.pointer.?;
    try testing.expect(held == @as(*const anyopaque, fixture.values()));
}

test "decision 163 ruling 1: id is the request's id, at the head and at the end" {
    var fixture: Fixture = .{};
    fixture.request(7, "GET", "/who/x", true);
    try testing.expect(std.mem.endsWith(u8, fixture.recorder.body_bytes(), " same"));
    fixture.finish(7);
    try testing.expectEqual(id_of(7), fixture.app.finished_id.?);
    // The id is the request's own, and no part of the entry: the next request has another.
    fixture.request(8, "GET", "/who/x", true);
    fixture.finish(8);
    try testing.expectEqual(id_of(8), fixture.app.finished_id.?);
}

test "decision 163 ruling 1: each callback of a struct route reads the same values" {
    var fixture: Fixture = .{};
    fixture.request(1, "POST", "/later/x", false);
    try testing.expectEqual(2, fixture.values().writes);
    const body: event.RequestBody = .{ .id = id_of(1), .user_data = fixture.recorder.user_data, .bytes = "b", .end = true };
    fixture.handle(.{ .body = body });
    // `Identify`, `on_request` and `on_body` each wrote once.
    try testing.expectEqualStrings("ada x 3", fixture.recorder.body_bytes());
    fixture.finish(1);
    try testing.expectEqual(3, fixture.app.later_writes);
    try testing.expectEqual(id_of(1), fixture.app.later_id.?);
    try testing.expectEqual(3, fixture.app.finished_writes);
}

test "decision 163 ruling 1: the error function and a middleware's wrapper read the request's values" {
    var fixture: Fixture = .{};
    fixture.request(1, "GET", "/broken", true);
    try testing.expectEqual(unprocessable, fixture.recorder.heads[0].status);
    try testing.expectEqualStrings("ada", fixture.app.error_user.get());
    try testing.expectEqualStrings("ada", fixture.app.wrapper_user.get());
}

/// The router and the program's context of the tests over an engine, which the program hooks
/// reach. Test-only.
var engine_router: Pool align(@alignOf(Pool)) = .{};
var engine_app: App align(@alignOf(App)) = .{};

const tcp_engine = &tcp_support.engine;
const quic_engine = &quic_support.engine_support.engine;

/// The two requests of each test over an engine: the target, the user that `Identify` writes, and
/// the content of the response. The second request holds the entry that the first one freed.
const first_target = "/who/col%69bri?mark=%21";
const first_user = "ada";
const first_content = "ada colibri! same";
const second_target = "/who/x";
const second_user = "grace";
const second_content = "grace x same";
/// The h2 streams of the two requests (RFC 9113 §5.1.1), and the rounds an h3 test pumps for
/// each request at most.
const first_stream: u32 = 1;
const second_stream: u32 = 3;
const rounds_max = 64;
/// The writes into the values of one request for `who`: one of `Identify`, and one of the route.
const who_writes = 2;

/// Passes each event the TCP engine reports to the router, as a program's loop does.
fn take_tcp(reported: event.Event) void {
    _ = engine_router.handle(&engine_app, tcp_engine, reported);
}

/// Passes each event the QUIC engine reports to the router.
fn take_quic(reported: event.Event) void {
    _ = engine_router.handle(&engine_app, quic_engine, reported);
}

/// Starts the TCP engine with the router as its program, and accepts one cleartext connection.
fn start_tcp() !event.ConnectionHandle {
    try tcp_support.start(null, .{});
    tcp_support.program = take_tcp;
    engine_router = .{};
    engine_app = .{ .user = first_user };
    return tcp_engine.accept(.{ .tls = false }, tcp_support.now_ns).?;
}

/// Requires the connection to have sent `content` after its first `from` octets, and `count`
/// requests to have finished.
fn expect_sent(handle: event.ConnectionHandle, from: usize, content: []const u8, count: usize) !void {
    const sent = tcp_support.sent_of(handle.slot)[from..];
    try testing.expect(std.mem.indexOf(u8, sent, content) != null);
    try testing.expectEqual(count, engine_app.finished);
}

/// Requires the second request to have found the defaults in the entry that the first one wrote
/// (decision 163 ruling 2).
fn expect_defaults_found() !void {
    try testing.expectEqual(Values{}, engine_app.found.?);
    try testing.expectEqual(who_writes, engine_app.finished_writes);
}

test "decision 163: a route reads a middleware's values, its path and its query, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, "GET " ++ first_target ++ " HTTP/1.1\r\nHost: example.com\r\n\r\n");
    try expect_sent(handle, 0, first_content, 1);
    const first_len = tcp_support.sent_of(handle.slot).len;
    engine_app.user = second_user;
    _ = tcp_support.give(handle, "GET " ++ second_target ++ " HTTP/1.1\r\nHost: example.com\r\n\r\n");
    try expect_sent(handle, first_len, second_content, 2);
    try expect_defaults_found();
}

test "decision 163: a route reads a middleware's values, its path and its query, over h2" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h2_support.client_preface);
    _ = tcp_support.give(handle, try h2_support.request_frame_with(first_stream, "GET", first_target, &.{}, true));
    try expect_sent(handle, 0, first_content, 1);
    const first_len = tcp_support.sent_of(handle.slot).len;
    engine_app.user = second_user;
    _ = tcp_support.give(handle, try h2_support.request_frame_with(second_stream, "GET", second_target, &.{}, true));
    try expect_sent(handle, first_len, second_content, 2);
    try expect_defaults_found();
}

/// Moves datagrams both ways until the client has the whole response of `fetch` and `count`
/// requests finished.
fn pump_until_finished(fetch: *const quic_support.Fetch, count: usize) !void {
    // Bounded: each round moves time on and moves datagrams both ways.
    for (0..rounds_max) |_| {
        if (fetch.ended and engine_app.finished == count) return;
        try quic_support.pump(1);
    }
    return error.TestExpectedFinished;
}

test "decision 163: a route reads a middleware's values, its path and its query, over h3" {
    try quic_support.start_engine(null);
    try quic_support.connect();
    engine_router = .{};
    engine_app = .{ .user = first_user };
    quic_support.seen_support.program = take_quic;
    defer quic_support.seen_support.program = null;
    const first = try quic_support.request("GET", first_target, "");
    try pump_until_finished(first, 1);
    try testing.expectEqualStrings(first_content, quic_support.content_of(first));
    engine_app.user = second_user;
    const second = try quic_support.request("GET", second_target, "");
    try pump_until_finished(second, 2);
    try testing.expectEqualStrings(second_content, quic_support.content_of(second));
    try expect_defaults_found();
}
