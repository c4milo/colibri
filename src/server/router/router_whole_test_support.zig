//! What the tests of a function route that gets the whole request share (decision 163 rulings 4
//! and 5, design §8 step 50e). It holds the route table, the program's context, into which the
//! routes write what they read, and the requests the tests send. Test-only.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const Response = @import("../response/response.zig").Response;
const RequestContext = @import("../request_context.zig").RequestContext;
const Next = @import("../middleware.zig").Next;
const router_pool = @import("router_pool.zig");
const router_copy = @import("router_copy.zig");
const handle_support = @import("router_handle_test_support.zig");

/// Octets of each entry's body and response memory, and of the copy of a header over an engine.
/// Then the longest text that the context keeps a copy of. Test-only.
pub const body_bytes = 16;
const response_bytes = 64;
pub const engine_header_bytes = 256;
const text_len_max = 16;

/// The name of the field line each test's request carries, the two values it takes, and the two
/// path parameters and query marks of `/item/:id`.
pub const name_field = "x-name";
pub const first_name = "ada";
pub const second_name = "bob";
pub const first_id_text = "one";
pub const second_id_text = "two";
pub const first_mark = "a";
pub const second_mark = "b";

/// The h2 streams of the two requests (RFC 9113 §5.1.1), and the id of the fixture's request.
/// Then the body of `/echo`, and a body as long as `body_bytes`.
pub const first_stream: u32 = 1;
pub const second_stream: u32 = 3;
pub const first_id: event.RequestId = @bitCast(@as(u128, 1));
pub const echo_body = "abcdef";
pub const full_body = "0123456789abcdef";
/// The rounds an h3 test pumps for a whole response at most, and for one piece of a body.
pub const rounds_max = 64;
pub const rounds_piece = 4;
pub const unprocessable: http.Status = .unprocessable_content;

comptime {
    std.debug.assert(full_body.len == body_bytes);
}

/// A copy of a short text. Test-only.
pub const Text = struct {
    bytes: [text_len_max]u8 = @splat(0),
    len: usize = 0,

    fn set(text: *Text, from: []const u8) void {
        std.debug.assert(from.len <= text_len_max);
        @memcpy(text.bytes[0..from.len], from);
        text.len = from.len;
    }

    pub fn get(text: *const Text) []const u8 {
        return text.bytes[0..text.len];
    }
};

/// What the routes read.
pub const App = struct {
    /// The calls of the function routes.
    calls: usize = 0,
    /// What a read of `request.body` gave in the middleware's `on_request`, in the struct route's
    /// `on_request`, and in the function route `empty`.
    middleware_read: ?anyerror = null,
    struct_read: ?anyerror = null,
    empty_read: ?anyerror = null,
    /// The reader that `empty` read.
    empty_body: ?*const std.Io.Reader = null,
    /// The request that the middleware got, and the one that `empty` got: the same one when the
    /// router passes the engine's request with no copy.
    middleware_request: ?*const event.Request = null,
    empty_request: ?*const event.Request = null,
    /// The method as the middleware got it at the head: the engine's octets, which a test reads
    /// after a later event.
    head_method: []const u8 = "",
    /// The name and the path that the error function read of its request.
    error_name: Text = .{},
    error_path: Text = .{},
};

/// The error of a read of one byte, or null when the read gave one.
fn read_error(reader: *std.Io.Reader) ?anyerror {
    _ = reader.takeByte() catch |failure| return failure;
    return null;
}

/// The route table's middleware, which reads the request's body at the head.
const Peek = struct {
    pub fn on_request(app: *App, _: *RequestContext, request: *const event.Request, _: *Response) Next {
        app.middleware_read = read_error(request.body);
        app.middleware_request = request;
        app.head_method = request.method;
        return .next;
    }
};

/// Answers with the whole body.
fn echo(app: *App, _: *RequestContext, request: *const event.Request, response: *Response) !void {
    app.calls += 1;
    var bytes: [body_bytes]u8 = undefined;
    const len = try request.body.readSliceShort(&bytes);
    try response.body().writeAll(bytes[0..len]);
}

/// The path and the query of `/item/:id`, which its entry names as `.path` and `.query` (decision
/// 163 ruling 3).
const Id = struct { id: []const u8 };
const Mark = struct { mark: []const u8 };

/// Answers with the request's name, its path parameter, its query's mark and its whole body.
fn item(app: *App, ctx: *RequestContext, request: *const event.Request, response: *Response) !void {
    app.calls += 1;
    var bytes: [body_bytes]u8 = undefined;
    const len = try request.body.readSliceShort(&bytes);
    const name = request.headers.find(name_field) orelse return error.TestNoName;
    try response.body().print("{s} {s} {s} {s}", .{ name.value, ctx.path(Id).id, ctx.query(Mark).mark, bytes[0..len] });
}

/// What `parts` writes for a part that the request does not carry.
const no_part = "-";

/// Answers with the request's method, target, path, query, scheme and authority.
fn parts(app: *App, _: *RequestContext, request: *const event.Request, response: *Response) !void {
    app.calls += 1;
    const path = request.path orelse no_part;
    const query = request.query orelse no_part;
    const scheme = request.scheme orelse no_part;
    const authority = request.authority orelse no_part;
    try response.body().print("{s} {s} {s} {s} {s} {s}", .{ request.method, request.target, path, query, scheme, authority });
}

/// A route that reads one byte of its body, and keeps the error and the reader.
fn empty(app: *App, _: *RequestContext, request: *const event.Request, _: *Response) !void {
    app.calls += 1;
    app.empty_read = read_error(request.body);
    app.empty_body = request.body;
    app.empty_request = request;
}

/// A struct route that reads the request's body at the head, and answers there.
const Stream = struct {
    pub fn on_request(app: *App, _: *RequestContext, _: *void, request: *const event.Request, response: *Response) !void {
        app.struct_read = read_error(request.body);
        try response.body().writeAll("streamed");
    }
};

fn broken(app: *App, _: *RequestContext, _: *const event.Request, _: *Response) !void {
    app.calls += 1;
    return error.TestBroken;
}

/// Chooses 422, and keeps the name and the path of the request it gets.
fn on_error(app: *App, _: *RequestContext, request: *const event.Request, _: anyerror, response: *Response) void {
    response.status = unprocessable;
    if (request.headers.find(name_field)) |name| app.error_name.set(name.value);
    app.error_path.set(request.path orelse "");
}

pub const routes = .{
    .error_handler = on_error,
    .middleware = .{Peek},
    .routes = .{
        .{ .post, "/echo", echo },
        .{ .post, "/item/:id", item, .{ .path = Id, .query = Mark } },
        .{ .get, "/empty", empty },
        .{ .post, "/empty", empty },
        .{ .post, "/parts", parts },
        .{ .post, "/stream", Stream },
        .{ .post, "/broken", broken },
    },
};

/// The requests a router answers at once: the two of an h2 test.
const requests = 2;

/// The options of a router whose copy of a header holds `header_bytes`.
pub fn options_with(comptime header_bytes: usize) router_pool.Options {
    return .{ .requests = requests, .response_bytes = response_bytes, .body_bytes = body_bytes, .header_bytes = header_bytes };
}

/// Octets of the copy of `named_request("/echo", first_name, false)`. The copy holds its line's
/// record, name and value, then its target, method, scheme and authority. Its path lies in its
/// target, so it takes no more.
pub const exact_header_bytes = router_copy.line_record_len + name_field.len + first_name.len + "POST".len +
    "/echo".len + handle_support.scheme.len + handle_support.authority.len;

/// The field section a request of `named_request` reads, which the next call writes again, as an
/// engine's next event does.
var test_section: http.FieldSection align(@alignOf(http.FieldSection)) = undefined;
var test_lines: http.FieldSection.Slice align(@alignOf(http.FieldSection.Slice)) = undefined;

/// A POST of `target` whose one field line is `x-name: name`.
pub fn named_request(target: []const u8, name: []const u8, end: bool) !event.Request {
    test_section.init();
    try test_section.append(name_field, name);
    test_lines = test_section.slice();
    var request = handle_support.request_of(1, "POST", target, end);
    request.headers = .init(&test_lines);
    return request;
}

/// Octets the router's copy of `request` takes (decision 163 ruling 5): its line records and their
/// octets, and each part that lies neither in those octets nor in the target.
pub fn copy_len(request: *const event.Request) usize {
    const lines = request.headers.lines;
    var len = lines.lines.len * router_copy.line_record_len + lines.octets.len;
    if (!lies_in(lines.octets, request.target)) len += request.target.len;
    for ([_]?[]const u8{ request.method, request.scheme, request.authority, request.path, request.query }) |part| {
        const present = part orelse continue;
        if (lies_in(lines.octets, present) or lies_in(request.target, present)) continue;
        len += present.len;
    }
    return len;
}

/// Whether `part` is a slice of `whole`.
fn lies_in(whole: []const u8, part: []const u8) bool {
    const start = @intFromPtr(whole.ptr);
    const at = @intFromPtr(part.ptr);
    return at >= start and at + part.len <= start + whole.len;
}
