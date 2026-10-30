//! The tests of `ResponseWriter` (decision 127, design §8 step 25.2), against a sink that records
//! each call and takes as many bytes as a test lets it.
const std = @import("std");
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const ResponseWriter = @import("response_writer.zig").ResponseWriter;
const internal = @import("response_writer_internal.zig");

const testing = std.testing;

/// The calls a test reads back. Test-only.
const calls_max = 32;
/// Octets of response memory each test gives. Test-only.
const memory_len = 256;

const Call = union(enum) {
    head: event.Response,
    body: event.ResponseBody,
    trailers: []const http.Field,
};

/// An endpoint that records each call. `room` is how many body bytes the next `write_body`
/// takes, `head_blocked` refuses the next `respond`, and `failure` fails the next call.
const Recorder = struct {
    calls: [calls_max]Call = undefined,
    count: usize = 0,
    room: usize = std.math.maxInt(usize),
    head_blocked: bool = false,
    failure: ?connection_errors.SendError = null,

    pub fn respond(recorder: *Recorder, _: event.RequestId, response: event.Response) connection_errors.SendError!void {
        if (recorder.failure) |failure| return failure;
        if (recorder.head_blocked) return error.NoSpaceLeft;
        recorder.add(.{ .head = response });
    }

    pub fn write_body(recorder: *Recorder, _: event.RequestId, body: event.ResponseBody) connection_errors.SendError!usize {
        // RFC 9113 §6.9: a closed flow-control window takes no content.
        if (recorder.room == 0 and body.bytes.len > 0) return error.Blocked;
        const taken = @min(recorder.room, body.bytes.len);
        recorder.room -= taken;
        recorder.add(.{ .body = .{ .bytes = body.bytes[0..taken], .end = body.end and taken == body.bytes.len } });
        return taken;
    }

    pub fn write_trailers(recorder: *Recorder, _: event.RequestId, headers: []const http.Field) connection_errors.SendError!void {
        recorder.add(.{ .trailers = headers });
    }

    fn add(recorder: *Recorder, call: Call) void {
        recorder.calls[recorder.count] = call;
        recorder.count += 1;
    }

    /// Every body byte the recorder took, in order, and whether the last call ended the body.
    fn body_of(recorder: *const Recorder, out: []u8) struct { []const u8, bool } {
        var len: usize = 0;
        var ended = false;
        for (recorder.calls[0..recorder.count]) |call| switch (call) {
            .body => |body| {
                @memcpy(out[len..][0..body.bytes.len], body.bytes);
                len += body.bytes.len;
                ended = body.end;
            },
            else => {},
        };
        return .{ out[0..len], ended };
    }
};

const Fixture = struct {
    recorder: Recorder = .{},
    memory: [memory_len]u8 = undefined,
    response: ResponseWriter = undefined,

    fn start(fixture: *Fixture) *ResponseWriter {
        internal.init(&fixture.response, internal.Sink.of(Recorder, &fixture.recorder), @bitCast(@as(u128, 0)), &fixture.memory);
        return &fixture.response;
    }
};

fn expect_head(call: Call, status: u16, ends: bool) !event.Response {
    try testing.expect(call == .head);
    try testing.expectEqual(status, call.head.status);
    try testing.expectEqual(ends, call.head.end);
    return call.head;
}

fn header_value(head: event.Response, name: []const u8) ?[]const u8 {
    for (head.headers) |line| if (std.mem.eql(u8, line.name, name)) return line.value;
    return null;
}

test "decision 127: end sends the head with the whole body and its Content-Length" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    try response.header("content-type", "text/plain");
    try response.body().print("hello, {s}\n", .{"colibri"});
    try testing.expect(!response.head_sent());
    try response.end();
    try testing.expect(response.head_sent() and internal.complete(response));
    try testing.expectEqual(2, fixture.recorder.count);
    const head = try expect_head(fixture.recorder.calls[0], 200, false);
    try testing.expectEqualStrings("text/plain", header_value(head, "content-type").?);
    try testing.expectEqualStrings("15", header_value(head, "content-length").?);
    var out: [memory_len]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("hello, colibri\n", body);
    try testing.expect(ended);
}

test "RFC 9110 §8.6: end adds no Content-Length to a 204 or past the program's own" {
    var fixture: Fixture = .{};
    var response = fixture.start();
    response.status = 204;
    try response.end();
    var head = try expect_head(fixture.recorder.calls[0], 204, true);
    try testing.expectEqual(null, header_value(head, "content-length"));
    fixture = .{};
    response = fixture.start();
    try response.header("Content-Length", "2");
    try response.body().writeAll("ok");
    try response.end();
    head = try expect_head(fixture.recorder.calls[0], 200, false);
    try testing.expectEqual(1, head.headers.len);
    // An empty 200 says its length is 0.
    fixture = .{};
    response = fixture.start();
    try response.end();
    head = try expect_head(fixture.recorder.calls[0], 200, true);
    try testing.expectEqualStrings("0", header_value(head, "content-length").?);
}

test "decision 127: a header after the body, past the limit, or past the memory is refused" {
    var fixture: Fixture = .{};
    var response = fixture.start();
    _ = response.body();
    try testing.expectError(error.SectionOutOfOrder, response.header("a", "b"));
    fixture = .{};
    response = fixture.start();
    for (0..constants.limits.response_headers_max) |_| try response.header("a", "b");
    try testing.expectError(error.SectionTooLarge, response.header("a", "b"));
    fixture = .{};
    response = fixture.start();
    try testing.expectError(error.NoSpaceLeft, response.header("a", "b" ** memory_len));
}

test "decision 103: the body never writes over bytes the endpoint took, and fails past the memory" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    try writer.writeAll("abc");
    try writer.flush();
    try writer.writeAll("def");
    try writer.flush();
    // The first run the recorder holds still reads as it was taken.
    try testing.expectEqualStrings("abc", fixture.recorder.calls[1].body.bytes);
    try testing.expectError(error.WriteFailed, writer.writeAll("x" ** memory_len));
}

test "decision 127: what the endpoint does not take waits for writable, in order" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    fixture.recorder.room = 3;
    try response.body().writeAll("0123456789");
    try response.end();
    try testing.expect(!internal.complete(response));
    // Bounded: each pass gives the recorder three more bytes.
    for (0..memory_len) |_| {
        fixture.recorder.room = 3;
        if (try internal.resume_writes(response)) break;
    }
    try testing.expect(internal.complete(response));
    var out: [memory_len]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("0123456789", body);
    try testing.expect(ended);
}

test "decision 127: a head the endpoint has no room for waits, and its status stays the program's" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    fixture.recorder.head_blocked = true;
    try response.end();
    try testing.expect(!response.head_sent());
    try testing.expectEqual(0, fixture.recorder.count);
    fixture.recorder.head_blocked = false;
    try testing.expect(try internal.resume_writes(response));
    _ = try expect_head(fixture.recorder.calls[0], 200, true);
}

test "decision 127: an empty write_kept sends nothing, so the status stays the program's" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    try response.write_kept("");
    try testing.expect(!response.head_sent());
    try testing.expectEqual(0, fixture.recorder.count);
    response.status = 404;
    try response.end();
    _ = try expect_head(fixture.recorder.calls[0], 404, true);
}

test "decision 127: write_kept sends the program's bytes after the body, with no copy" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const kept: []const u8 = "bc";
    try response.body().writeAll("a");
    try response.write_kept(kept);
    try testing.expect(response.head_sent());
    try response.end();
    try testing.expectEqual(kept.ptr, fixture.recorder.calls[2].body.bytes.ptr);
    var out: [memory_len]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("abc", body);
    try testing.expect(ended);
    // A head sent before the end carries no Content-Length.
    const head = try expect_head(fixture.recorder.calls[0], 200, false);
    try testing.expectEqual(null, header_value(head, "content-length"));
}

test "RFC 9110 §6.5: trailers end the response after the body, from a copy" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    try response.body().writeAll("x");
    var value = "1".*;
    try response.trailers(&.{.{ .name = "checksum", .value = &value }});
    value[0] = '2';
    const head = try expect_head(fixture.recorder.calls[0], 200, false);
    try testing.expectEqual(null, header_value(head, "content-length"));
    try testing.expectEqualStrings("x", fixture.recorder.calls[1].body.bytes);
    try testing.expect(!fixture.recorder.calls[1].body.end);
    try testing.expectEqualStrings("1", fixture.recorder.calls[2].trailers[0].value);
    try testing.expect(internal.complete(response));
}

test "decision 127: no call after the end, and the endpoint's other errors come back" {
    var fixture: Fixture = .{};
    var response = fixture.start();
    try response.end();
    try testing.expectError(error.SectionOutOfOrder, response.end());
    try testing.expectError(error.SectionOutOfOrder, response.write_kept("a"));
    try testing.expectError(error.SectionOutOfOrder, response.trailers(&.{}));
    try testing.expectError(error.WriteFailed, response.body().writeAll("a"));
    fixture = .{};
    response = fixture.start();
    fixture.recorder.failure = error.StatusInvalid;
    response.status = 42;
    try testing.expectError(error.StatusInvalid, response.end());
}

test "decision 127: more runs than response_pieces_max wait refused" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    fixture.recorder.room = 0;
    for (0..constants.limits.response_pieces_max) |_| try response.write_kept("a");
    try testing.expectError(error.Full, response.write_kept("a"));
}
