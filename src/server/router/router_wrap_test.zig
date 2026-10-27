//! The tests of a middleware's wrappers (decision 127 ruling 5, design §8 step 25.6): each wraps
//! what the middleware before it gave, the route reads and writes through the last one, and the
//! router finishes them from the route's side outward before it ends the response.
const std = @import("std");
const event = @import("../event.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const router = @import("router.zig").router;
const support = @import("router_handle_test_support.zig");
const Recorder = support.Recorder;

const testing = std.testing;

/// The request body bytes a route reads back. Test-only.
const read_len_max = 16;

const App = struct {
    read: [read_len_max]u8 = undefined,
    read_len: usize = 0,
    /// Whether `Outer`'s `finish_response` fails.
    fail_finish: bool = false,
    /// The count `Count` found in its state, at its last call.
    counted: u8 = 0,
};

/// A middleware whose state counts its calls, which each request starts from 0. It wraps
/// nothing. Test-only.
const Count = struct {
    pub const State = struct { calls: u8 = 0 };

    pub fn wrap_body(app: *App, state: *State, _: *const event.Request, _: *std.Io.Reader) ?*std.Io.Reader {
        state.calls += 1;
        app.counted = state.calls;
        return null;
    }
};

/// How many times `Outer` and `Inner` write each byte. Test-only.
const once = 1;
const twice = 2;

/// A middleware whose writer writes each byte `times` times, upper-cased when `upper` is true,
/// and whose `finish_response` writes `suffix`. Test-only.
fn Mapping(comptime times: usize, comptime upper: bool, comptime suffix: u8) type {
    return struct {
        pub const State = struct {
            writer: std.Io.Writer = undefined,
            inner: *std.Io.Writer = undefined,
        };

        pub fn wrap_response(_: *App, state: *State, _: *const event.Request, _: *ResponseWriter, inner: *std.Io.Writer) ?*std.Io.Writer {
            state.* = .{ .writer = .{ .vtable = &vtable, .buffer = &.{} }, .inner = inner };
            return &state.writer;
        }

        pub fn finish_response(app: *App, state: *State) !void {
            if (upper and app.fail_finish) return error.TestFinishFailed;
            try state.inner.writeByte(suffix);
        }

        const vtable: std.Io.Writer.VTable = .{ .drain = drain };

        fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const state: *State = @alignCast(@fieldParentPtr("writer", writer));
            var consumed: usize = 0;
            for (data, 0..) |slice, index| {
                const repeats = if (index + 1 == data.len) splat else 1;
                for (0..repeats) |_| consumed += try map(state.inner, slice, times, upper);
            }
            return consumed;
        }
    };
}

/// Writes each byte of `slice` to `inner` `times` times, upper-cased when `upper` is true, and
/// returns the bytes of `slice` it took. Test-only.
fn map(inner: *std.Io.Writer, slice: []const u8, times: usize, upper: bool) std.Io.Writer.Error!usize {
    for (slice) |byte| try inner.splatByteAll(if (upper) std.ascii.toUpper(byte) else byte, times);
    return slice.len;
}

/// The route table's wrapper, nearest the wire: it upper-cases, and ends with "!".
const Outer = Mapping(once, true, '!');
/// The route entry's wrapper, nearest the route: it doubles each byte, and ends with "#".
const Inner = Mapping(twice, false, '#');

/// The bytes `Lower` reads ahead of the route. Test-only.
const lower_buffer_len = 4;

/// A wrapper of the request body's reader that lower-cases each byte. Test-only.
const Lower = struct {
    pub const State = struct {
        reader: std.Io.Reader = undefined,
        buffer: [lower_buffer_len]u8 = undefined,
        inner: *std.Io.Reader = undefined,
    };

    pub fn wrap_body(_: *App, state: *State, _: *const event.Request, inner: *std.Io.Reader) ?*std.Io.Reader {
        state.* = .{ .reader = .{ .vtable = &vtable, .buffer = &state.buffer, .seek = 0, .end = 0 }, .inner = inner };
        return &state.reader;
    }

    const vtable: std.Io.Reader.VTable = .{ .stream = stream };

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        if (limit == .nothing) return 0;
        const state: *State = @alignCast(@fieldParentPtr("reader", reader));
        const byte = try state.inner.takeByte();
        try writer.writeByte(std.ascii.toLower(byte));
        return 1;
    }
};

fn written(_: *App, _: *const event.Request, _: void, _: void, response: *ResponseWriter) !void {
    try response.body().writeAll("ok");
    try response.end();
}

fn kept(_: *App, _: *const event.Request, _: void, _: void, response: *ResponseWriter) !void {
    try response.write_kept("ok");
    try response.trailers(&.{.{ .name = "x-sum", .value = "1" }});
}

/// A struct route that reads the whole body through `Lower`, and answers with what it read.
const Echo = struct {
    pub fn on_request(_: *App, _: *void, _: *const event.Request, _: void, _: void, _: *ResponseWriter) !void {}

    pub fn on_body(app: *App, _: *void, reader: *std.Io.Reader, response: *ResponseWriter) !void {
        for (0..read_len_max) |_| {
            const byte = reader.takeByte() catch |failure| switch (failure) {
                error.EndOfStream => break,
                else => |other| return other,
            };
            app.read[app.read_len] = byte;
            app.read_len += 1;
        }
        try response.end();
    }
};

fn left_open(_: *App, _: *const event.Request, _: void, _: void, _: *ResponseWriter) !void {}

/// Bytes that, with the trailers, fill the response memory, so `Outer`'s "!" finds no room.
const full_len = response_bytes - "x-sum".len - "1".len;

fn full(_: *App, _: *const event.Request, _: void, _: void, response: *ResponseWriter) !void {
    try response.body().splatByteAll('a', full_len);
    try response.trailers(&.{.{ .name = "x-sum", .value = "1" }});
}

/// A struct route that writes its response on `writable`, and ends it.
const Late = struct {
    pub fn on_request(_: *App, _: *void, _: *const event.Request, _: void, _: void, _: *ResponseWriter) !void {}

    pub fn on_writable(_: *App, _: *void, response: *ResponseWriter) !void {
        try response.body().writeAll("ab");
        try response.end();
    }
};

fn on_error(_: *App, _: *const event.Request, _: anyerror, _: *ResponseWriter) void {}

const routes = router(App, .{
    .error_handler = on_error,
    .middleware = .{ Outer, Count },
    .routes = .{
        .{ .get, "/written", written, .{ .middleware = .{Inner} } },
        .{ .get, "/kept", kept },
        .{ .post, "/echo", Echo, .{ .middleware = .{Lower} } },
        .{ .get, "/open", left_open },
        .{ .get, "/full", full },
        .{ .get, "/late", Late },
    },
});

const response_bytes = 64;
const Pool = @TypeOf(routes).Of(.{ .requests = 1, .response_bytes = response_bytes });

const Fixture = struct {
    app: App = .{},
    recorder: Recorder = .{},
    pool: Pool = .{},

    fn handle(fixture: *Fixture, received: event.Event) void {
        const handled = fixture.pool.handle(&fixture.app, &fixture.recorder, received);
        std.debug.assert(handled == .taken);
    }

    fn send(fixture: *Fixture, method: []const u8, target: []const u8, end: bool) void {
        fixture.handle(.{ .request = support.request_of(1, method, target, end) });
    }

    fn finish(fixture: *Fixture) void {
        fixture.handle(.{ .finished = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.recorder.user_data, .result = .sent } });
    }

    fn body(fixture: *Fixture, bytes: []const u8, end: bool) void {
        fixture.handle(.{ .body = .{ .id = @bitCast(@as(u128, 1)), .user_data = fixture.recorder.user_data, .bytes = bytes, .end = end } });
    }
};

test "design §8 step 25.6: the route writes through each wrapper, and they finish from the route's side outward" {
    var fixture: Fixture = .{};
    fixture.send("GET", "/written", true);
    // "ok" doubled by Inner, then upper-cased by Outer; Inner's "#" goes through Outer, then "!".
    try testing.expectEqualStrings("OOKK#!", fixture.recorder.body_bytes());
    try testing.expect(fixture.recorder.ended);
    // The head carries the whole body, so its Content-Length counts the bytes the wrappers wrote.
    const head = fixture.recorder.heads[0];
    try testing.expectEqualStrings("content-length", head.headers[head.headers.len - 1].name);
    try testing.expectEqualStrings("6", head.headers[head.headers.len - 1].value);
}

test "design §8 step 25.6: write_kept copies through the wrapper, and the trailers wait for it" {
    var fixture: Fixture = .{};
    fixture.send("GET", "/kept", true);
    try testing.expectEqualStrings("OK!", fixture.recorder.body_bytes());
    try testing.expectEqualStrings("x-sum", fixture.recorder.trailer_name);
    try testing.expectEqualStrings("1", fixture.recorder.trailer_value);
}

test "design §8 step 25.6: an error of finish_response cancels the request" {
    var fixture: Fixture = .{};
    fixture.app.fail_finish = true;
    fixture.send("GET", "/written", true);
    try testing.expectEqual(1, fixture.recorder.cancelled);
    try testing.expect(!fixture.recorder.ended);
}

test "design §8 step 25.6: the route reads the request body through the wrapper, over two calls" {
    var fixture: Fixture = .{};
    fixture.send("POST", "/echo", false);
    fixture.body("HeL", false);
    try testing.expectEqualStrings("hel", fixture.app.read[0..fixture.app.read_len]);
    fixture.body("LO", true);
    try testing.expectEqualStrings("hello", fixture.app.read[0..fixture.app.read_len]);
    // Outer wraps the response, so its "!" ends it.
    try testing.expectEqualStrings("!", fixture.recorder.body_bytes());
}

test "design §8 step 25.6: a response the route left open ends once the wrapper finishes" {
    var fixture: Fixture = .{};
    fixture.send("GET", "/open", true);
    try testing.expectEqualStrings("!", fixture.recorder.body_bytes());
    try testing.expect(fixture.recorder.ended);
    try testing.expectEqual(0, fixture.recorder.cancelled);
}

test "design §8 step 25.6: a wrapped response that on_writable ends ends once" {
    var fixture: Fixture = .{};
    fixture.send("GET", "/late", true);
    try testing.expectEqualStrings("AB!", fixture.recorder.body_bytes());
    try testing.expect(fixture.recorder.ended);
    try testing.expectEqual(0, fixture.recorder.cancelled);
}

test "design §8 step 25.6: a wrapper's last bytes do not write over the trailers" {
    var fixture: Fixture = .{};
    fixture.send("GET", "/full", true);
    // The trailers hold the end of the memory, so "!" finds no room, and the request is cancelled.
    try testing.expectEqual(1, fixture.recorder.cancelled);
    try testing.expectEqualStrings("", fixture.recorder.trailer_name);
}

test "design §8 step 25.6: each request starts from the defaults of a middleware's state" {
    var fixture: Fixture = .{};
    fixture.send("GET", "/open", true);
    fixture.finish();
    fixture.send("GET", "/open", true);
    try testing.expectEqual(1, fixture.app.counted);
}
