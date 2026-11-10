//! What the tests of `ResponseWriter` share: an engine that records each call of the writer's
//! sink and takes as many bytes as a test lets it, and a writer over it. Split out of
//! `response_writer_test.zig` for length. Test-only.
const std = @import("std");
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const ResponseWriter = @import("response_writer.zig").ResponseWriter;
const internal = @import("response_writer_internal.zig");

/// The calls a test reads back. Test-only.
const calls_max = 32;
/// Octets of response memory each test gives. Test-only.
pub const memory_len = 256;
/// Octets of the longest body a test writes, which is longer than its memory when the writer
/// writes again over the runs the engine released. Test-only.
const stream_len_max = 512;
/// The runs a writer has slots for. Test-only.
pub const slots = constants.limits.response_pieces_max;

pub const Call = union(enum) {
    head: event.Response,
    body: event.ResponseBody,
    trailers: []const http.Field,
};

/// An engine that records each call. `room` is how many body bytes the next `write_body`
/// takes, `head_blocked` refuses the next `respond`, and `failure` fails the next call. It reads
/// each run of body bytes in place, as h3 does, so it holds `held` octets until a test releases
/// them (design §8 step 46). With `copies` it holds none, as h11 and h2 do. `stream` is a copy of
/// each body byte at the call that took it, since the writer writes again over a run the test
/// released.
pub const Recorder = struct {
    calls: [calls_max]Call = undefined,
    count: usize = 0,
    stream: [stream_len_max]u8 = undefined,
    stream_len: usize = 0,
    room: usize = std.math.maxInt(usize),
    head_blocked: bool = false,
    failure: ?connection_errors.SendError = null,
    copies: bool = false,
    held: usize = 0,
    release_waits: usize = 0,

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
        if (!recorder.copies) recorder.held += taken;
        @memcpy(recorder.stream[recorder.stream_len..][0..taken], body.bytes[0..taken]);
        recorder.stream_len += taken;
        recorder.add(.{ .body = .{ .bytes = body.bytes[0..taken], .end = body.end and taken == body.bytes.len } });
        return taken;
    }

    pub fn held_len(recorder: *Recorder, _: event.RequestId) usize {
        return recorder.held;
    }

    pub fn wait_release(recorder: *Recorder, _: event.RequestId) void {
        // `State.wait_release` asserts it too: a wait for a release needs octets that are held.
        std.debug.assert(recorder.held > 0);
        recorder.release_waits += 1;
    }

    pub fn write_trailers(recorder: *Recorder, _: event.RequestId, headers: []const http.Field) connection_errors.SendError!void {
        recorder.add(.{ .trailers = headers });
    }

    fn add(recorder: *Recorder, call: Call) void {
        recorder.calls[recorder.count] = call;
        recorder.count += 1;
    }

    /// Every body byte the recorder took, in order, and whether the last call ended the body.
    pub fn body_of(recorder: *const Recorder, out: []u8) struct { []const u8, bool } {
        var ended = false;
        for (recorder.calls[0..recorder.count]) |call| switch (call) {
            .body => |body| ended = body.end,
            else => {},
        };
        @memcpy(out[0..recorder.stream_len], recorder.stream[0..recorder.stream_len]);
        return .{ out[0..recorder.stream_len], ended };
    }
};

pub const Fixture = struct {
    recorder: Recorder = .{},
    memory: [memory_len]u8 = undefined,
    response: ResponseWriter = undefined,

    pub fn start(fixture: *Fixture) *ResponseWriter {
        internal.init(&fixture.response, internal.Sink.of(Recorder, &fixture.recorder), @bitCast(@as(u128, 0)), &fixture.memory);
        return &fixture.response;
    }
};
