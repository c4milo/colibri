//! The endpoint that the tests of `server.router`'s `handle` share (design §8 step 25.3): it
//! records each call, and takes as many body bytes as a test lets it. Test-only.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const connection_errors = @import("../connection/connection_errors.zig");

/// The heads and body bytes a test reads back. Test-only.
const heads_max = 8;
const body_len_max = 256;

/// An endpoint that records each head, the body bytes, the trailers, the words and the cancels. `room` is how
/// many body bytes it takes before it blocks. Test-only.
pub const Recorder = struct {
    heads: [heads_max]event.Response = undefined,
    allow: [heads_max][]const u8 = undefined,
    head_count: usize = 0,
    body: [body_len_max]u8 = undefined,
    body_len: usize = 0,
    ended: bool = false,
    user_data: usize = 0,
    cancelled: usize = 0,
    /// The name and the value of the last trailer section's first line.
    trailer_name: []const u8 = "",
    trailer_value: []const u8 = "",
    room: usize = std.math.maxInt(usize),

    pub fn respond(recorder: *Recorder, _: event.RequestId, response: event.Response) connection_errors.SendError!void {
        recorder.heads[recorder.head_count] = response;
        recorder.allow[recorder.head_count] = if (response.headers.len > 0) response.headers[0].value else "";
        recorder.head_count += 1;
        recorder.ended = response.end;
    }

    pub fn write_body(recorder: *Recorder, _: event.RequestId, body: event.ResponseBody) connection_errors.SendError!usize {
        // RFC 9113 §6.9: a closed flow-control window takes no content.
        if (recorder.room == 0 and body.bytes.len > 0) return error.Blocked;
        const taken = @min(recorder.room, body.bytes.len);
        recorder.room -= taken;
        @memcpy(recorder.body[recorder.body_len..][0..taken], body.bytes[0..taken]);
        recorder.body_len += taken;
        recorder.ended = body.end and taken == body.bytes.len;
        return taken;
    }

    pub fn write_trailers(recorder: *Recorder, _: event.RequestId, headers: []const http.Field) connection_errors.SendError!void {
        if (headers.len > 0) {
            recorder.trailer_name = headers[0].name;
            recorder.trailer_value = headers[0].value;
        }
        recorder.ended = true;
    }

    pub fn set_user_data(recorder: *Recorder, _: event.RequestId, user_data: usize) error{RequestUnknown}!void {
        recorder.user_data = user_data;
    }

    pub fn cancel(recorder: *Recorder, _: event.RequestId) void {
        recorder.cancelled += 1;
    }

    pub fn body_bytes(recorder: *const Recorder) []const u8 {
        return recorder.body[0..recorder.body_len];
    }
};

/// The version of every request of the tests. Test-only.
const h2_major = 2;
const h2_version: event.Version = .{ .major = h2_major, .minor = 0 };

/// The head of a request with `target`, of id `number`. Test-only.
pub fn request_of(number: u64, method: []const u8, target: []const u8, end: bool) event.Request {
    const split = event.split_target(target);
    return .{
        .id = @bitCast(@as(u128, number)),
        .method = method,
        .version = h2_version,
        .target = target,
        .scheme = "https",
        .authority = "example.com",
        .path = split.path,
        .query = split.query,
        .headers = undefined,
        .end = end,
    };
}
