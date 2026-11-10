//! What the tests of a long response through a struct route share (design §8 step 46): a route
//! that writes a response many times longer than `response_bytes` through `body()`, one message
//! at a time, and an engine that reads each run in place until the test acknowledges it, as h3
//! does (RFC 9000 §3.1), or copies each run at once, as h11 and h2 do. The engine records each
//! octet it took, and checks that no run it holds changes before its release. Test-only.
const std = @import("std");
const http = @import("http");
const event = @import("../event.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;

/// The messages of the longest response a test's route writes, octets of its longest message, and
/// octets of that response at most. Test-only.
pub const messages_max = 1000;
pub const message_len_max = 128;
pub const stream_len_max = messages_max * message_len_max;
/// Octets of the shortest message of a response whose messages vary, the lengths such a message
/// can have, and the step from one message's length to the next, which shares no factor with
/// that count.
pub const message_len_min = 7;
const varied_lengths = message_len_max - message_len_min + 1;
const varied_step = 37;
/// The runs the engine holds at most, as an h3 response holds 16 runs, two for each DATA frame.
const runs_max = 8;
/// The prime that `octet_at` counts modulo, so no message repeats the one before it.
const pattern_period = 251;

/// The octet at `offset` of each test's response.
pub fn octet_at(offset: usize) u8 {
    return @intCast(offset % pattern_period);
}

/// Whether `bytes` is the start of each test's response, `len` octets long.
pub fn is_stream(bytes: []const u8, len: usize) bool {
    if (bytes.len != len) return false;
    for (bytes, 0..) |octet, offset| {
        if (octet != octet_at(offset)) return false;
    }
    return true;
}

/// Octets of message `index` of a response whose messages vary: each length from
/// `message_len_min` to `message_len_max`, in an order that repeats after `varied_lengths`.
pub fn varied_len(index: usize) usize {
    return message_len_min + (index * varied_step) % varied_lengths;
}

/// Octets of the first `count` messages of a response whose messages vary.
pub fn varied_stream_len(count: usize) usize {
    var len: usize = 0;
    for (0..count) |index| len += varied_len(index);
    return len;
}

/// What a test sets for its route, and what the route did.
pub const App = struct {
    /// Octets of the response and of each message, whether each message has the length that
    /// `varied_len` gives in place of `message_len`, and whether the route flushes each message,
    /// so that each is a run of its own.
    stream_len: usize,
    message_len: usize,
    varied: bool = false,
    flush: bool = false,
    /// The calls of `on_writable`, those that found the writer with no room, the writes that
    /// failed, which the route makes again in a later call, and the flushes that failed.
    calls: usize = 0,
    roomless_calls: usize = 0,
    failed_writes: usize = 0,
    failed_flushes: usize = 0,
};

/// Writes `App.stream_len` octets, `App.message_len` at a time, and ends the response. A message
/// that does not fit is written again in the next call.
pub const Stream = struct {
    pub const State = struct { written: usize = 0, messages: usize = 0 };

    pub fn on_request(_: *App, _: *State, _: *const event.Request, _: void, _: void, _: *ResponseWriter) !void {}

    pub fn on_writable(app: *App, state: *State, response: *ResponseWriter) !void {
        app.calls += 1;
        const writer = response.body();
        if (writer.unusedCapacityLen() == 0) app.roomless_calls += 1;
        var message: [message_len_max]u8 = undefined;
        // Bounded: each pass writes one message of one octet at least.
        for (0..stream_len_max) |_| {
            if (state.written == app.stream_len) return response.end();
            const next_len = if (app.varied) varied_len(state.messages) else app.message_len;
            const len = @min(next_len, app.stream_len - state.written);
            for (message[0..len], state.written..) |*octet, offset| octet.* = octet_at(offset);
            writer.writeAll(message[0..len]) catch {
                app.failed_writes += 1;
                return;
            };
            state.written += len;
            state.messages += 1;
            if (app.flush) try flush_message(app, writer);
        }
    }
};

/// Flushes the message the route just wrote, and counts a flush that fails.
fn flush_message(app: *App, writer: *std.Io.Writer) !void {
    writer.flush() catch |failure| {
        app.failed_flushes += 1;
        return failure;
    };
}

/// An engine that takes every body byte, and holds each run in place until `acknowledge` releases
/// it when `holds` is set. It owes a `writable` once a write found no room, or once the writer
/// asked for one at a release.
pub const Holder = struct {
    holds: bool,
    stream: [stream_len_max]u8 = undefined,
    taken: usize = 0,
    acknowledged: usize = 0,
    runs: [runs_max][]const u8 = undefined,
    run_offsets: [runs_max]usize = undefined,
    runs_len: usize = 0,
    heads: usize = 0,
    ended: bool = false,
    user_data: usize = 0,
    cancelled: usize = 0,
    release_waits: usize = 0,
    owed: bool = false,
    /// Whether a run the engine held changed before its release.
    overwritten: bool = false,

    pub fn respond(holder: *Holder, _: event.RequestId, response: event.Response) connection_errors.SendError!void {
        holder.heads += 1;
        holder.ended = response.end;
    }

    pub fn write_body(holder: *Holder, _: event.RequestId, body: event.ResponseBody) connection_errors.SendError!usize {
        holder.check();
        if (body.bytes.len > 0) {
            const full = holder.holds and holder.runs_len == runs_max;
            holder.owed = holder.owed or full;
            // RFC 9000 §3.1: a run leaves only once the peer acknowledges it.
            if (full) return error.Blocked;
            @memcpy(holder.stream[holder.taken..][0..body.bytes.len], body.bytes);
            if (holder.holds) holder.hold(body.bytes);
            holder.taken += body.bytes.len;
        }
        holder.ended = body.end;
        return body.bytes.len;
    }

    pub fn write_trailers(holder: *Holder, _: event.RequestId, _: []const http.Field) connection_errors.SendError!void {
        holder.ended = true;
    }

    pub fn set_user_data(holder: *Holder, _: event.RequestId, user_data: usize) error{RequestUnknown}!void {
        holder.user_data = user_data;
    }

    pub fn cancel(holder: *Holder, _: event.RequestId) void {
        holder.cancelled += 1;
    }

    pub fn held_len(holder: *Holder, _: event.RequestId) usize {
        if (!holder.holds) return 0;
        return holder.taken - holder.acknowledged;
    }

    pub fn wait_release(holder: *Holder, _: event.RequestId) void {
        holder.release_waits += 1;
        holder.owed = true;
    }

    /// Acknowledges `count` more octets, and drops each run they cover whole.
    pub fn acknowledge(holder: *Holder, count: usize) void {
        holder.check();
        std.debug.assert(holder.acknowledged + count <= holder.taken);
        holder.acknowledged += count;
        var dropped: usize = 0;
        for (holder.runs[0..holder.runs_len], holder.run_offsets[0..holder.runs_len]) |run, offset| {
            if (offset + run.len > holder.acknowledged) break;
            dropped += 1;
        }
        const rest = holder.runs_len - dropped;
        std.mem.copyForwards([]const u8, holder.runs[0..rest], holder.runs[dropped..holder.runs_len]);
        std.mem.copyForwards(usize, holder.run_offsets[0..rest], holder.run_offsets[dropped..holder.runs_len]);
        holder.runs_len = rest;
    }

    /// The octets of the oldest run held, or 0.
    pub fn oldest_len(holder: *const Holder) usize {
        if (holder.runs_len == 0) return 0;
        return holder.run_offsets[0] + holder.runs[0].len - holder.acknowledged;
    }

    fn hold(holder: *Holder, bytes: []const u8) void {
        holder.runs[holder.runs_len] = bytes;
        holder.run_offsets[holder.runs_len] = holder.taken;
        holder.runs_len += 1;
    }

    /// Notes a held run whose octets differ from those the engine took.
    fn check(holder: *Holder) void {
        for (holder.runs[0..holder.runs_len], holder.run_offsets[0..holder.runs_len]) |run, offset| {
            if (!std.mem.eql(u8, run, holder.stream[offset..][0..run.len])) holder.overwritten = true;
        }
    }
};
