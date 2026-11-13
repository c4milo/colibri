//! What `Response`'s calls and the router share, and a program does not call (design §8 step
//! 25.2). The root exports none of it.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const Response = @import("response.zig").Response;
const ring = @import("response_ring.zig");

/// What the calls of `Response` return: the engine's errors, with their meaning, and `Full`
/// when `response_pieces_max` runs of body bytes wait for the engine or for their release, and
/// none of them takes the bytes of the call. The engine's `NoSpaceLeft` and `Blocked` never come
/// back: the response holds what the engine did not take until the request's `writable`.
/// `NoSpaceLeft` here says the entry's memory is full.
pub const Error = error{Full} || connection_errors.SendError;

/// How a program ended a response whose body a middleware wraps (design §8 step 25.6): not yet,
/// with `end`, or with `trailers`.
pub const EndAsked = enum { none, end, trailers };

/// The digits of the largest Content-Length value.
pub const length_digits_max = std.fmt.count("{d}", .{std.math.maxInt(u64)});

/// The engine's three calls that write a response, without its type, so one `Response`
/// serves every `Engine`, and the two the ring of its body reads (design §8 step 46): the octets
/// the engine still reads in place, and the wait for their release.
pub const Sink = struct {
    context: *anyopaque,
    respond: *const fn (context: *anyopaque, id: event.RequestId, response: event.ResponseHeader) connection_errors.SendError!void,
    write_body: *const fn (context: *anyopaque, id: event.RequestId, body: event.ResponseBody) connection_errors.SendError!usize,
    write_trailers: *const fn (context: *anyopaque, id: event.RequestId, headers: []const http.Field) connection_errors.SendError!void,
    held_len: *const fn (context: *anyopaque, id: event.RequestId) usize,
    wait_release: *const fn (context: *anyopaque, id: event.RequestId) void,

    /// The sink of `engine`, an `*Engine(capacity)`.
    pub fn init(comptime Engine: type, engine: *Engine) Sink {
        const calls = struct {
            fn respond(context: *anyopaque, id: event.RequestId, response: event.ResponseHeader) connection_errors.SendError!void {
                return engine_of(Engine, context).respond(id, response);
            }
            fn write_body(context: *anyopaque, id: event.RequestId, body: event.ResponseBody) connection_errors.SendError!usize {
                return engine_of(Engine, context).write_body(id, body);
            }
            fn write_trailers(context: *anyopaque, id: event.RequestId, headers: []const http.Field) connection_errors.SendError!void {
                return engine_of(Engine, context).write_trailers(id, headers);
            }
            // `Engine` has no call for these two: its state answers. A test's engine answers
            // itself, or copies each write and holds none.
            fn held_len(context: *anyopaque, id: event.RequestId) usize {
                const held_by = engine_of(Engine, context);
                if (comptime @hasField(Engine, "state")) return held_by.state.held_len(id);
                if (comptime @hasDecl(Engine, "held_len")) return held_by.held_len(id);
                return 0;
            }
            fn wait_release(context: *anyopaque, id: event.RequestId) void {
                const held_by = engine_of(Engine, context);
                if (comptime @hasField(Engine, "state")) return held_by.state.wait_release(id);
                if (comptime @hasDecl(Engine, "wait_release")) return held_by.wait_release(id);
            }
        };
        return .{
            .context = engine,
            .respond = calls.respond,
            .write_body = calls.write_body,
            .write_trailers = calls.write_trailers,
            .held_len = calls.held_len,
            .wait_release = calls.wait_release,
        };
    }
};

fn engine_of(comptime Engine: type, context: *anyopaque) *Engine {
    return @ptrCast(@alignCast(context));
}

const vtable: std.Io.Writer.VTable = .{ .drain = drain, .flush = flush, .rebase = std.Io.Writer.failingRebase };

/// Places a response for request `id` over `memory`. The response must not move after this call:
/// its body's `std.Io.Writer` finds it by its address.
pub fn init(response: *Response, sink: Sink, id: event.RequestId, memory: []u8) void {
    response.* = .{ .sink = sink, .id = id, .memory = memory, .writer = .{ .vtable = &vtable, .buffer = memory[0..0] } };
}

/// Sends what waits, on the request's `writable`. It returns whether the response is whole. Bytes
/// that a cut left in the writer, with a run in every slot, are cut again and sent.
pub fn resume_writes(response: *Response) Error!bool {
    response.release_waited = false;
    try push(response);
    if (response.cut_owed) _ = try send(response);
    return response.complete;
}

/// Whether bytes, the head or the end wait for the engine, or the response waits for the engine to
/// release bytes. A `writable` comes for each.
pub fn waiting(response: *const Response) bool {
    return response.piece_sent < response.piece_count or (response.ended and !response.complete) or response.release_waited;
}

/// Where the response stands: what moves when a program writes a byte, a run or the end (design §8
/// step 46). Two marks that are equal say that a call wrote nothing.
pub const Mark = struct {
    position: usize,
    pieces: u8,
    taken_len: u64,
    ended: bool,

    pub fn eql(left: Mark, right: Mark) bool {
        return left.position == right.position and left.pieces == right.pieces and
            left.taken_len == right.taken_len and left.ended == right.ended;
    }
};

pub fn mark(response: *const Response) Mark {
    return .{
        .position = @intFromPtr(response.writer.buffer.ptr) + response.writer.end,
        .pieces = response.piece_count,
        .taken_len = response.taken_len,
        .ended = response.ended or response.end_asked != .none,
    };
}

/// Whether a call of `on_writable` finds room in the body's writer (design §8 step 46). A full
/// region sends what it holds and takes back the memory the engine released. When none is free,
/// the response waits for the engine's `writable`.
pub fn has_room(response: *Response) Error!bool {
    if (!response.body_started) return true;
    if (response.writer.end < response.writer.buffer.len) return true;
    if (!try send(response)) return false;
    return ring.refill(response, 1);
}

/// Whether the engine took the whole response.
pub fn complete(response: *const Response) bool {
    return response.complete;
}

/// A name and a value copied into `response.memory` from `first`, and the offset after them.
pub const Copied = struct { field: http.Field, end: usize };

pub fn copy_line(response: *Response, first: usize, name: []const u8, value: []const u8) Error!Copied {
    const end = first + name.len + value.len;
    if (end > response.memory.len) return error.NoSpaceLeft;
    const name_copy = response.memory[first..][0..name.len];
    const value_copy = response.memory[first + name.len ..][0..value.len];
    @memcpy(name_copy, name);
    @memcpy(value_copy, value);
    return .{ .field = .{ .name = name_copy, .value = value_copy }, .end = end };
}

/// Closes the headers, and gives the body's writer the memory after them.
pub fn start_body(response: *Response) void {
    assert(!response.body_started);
    response.body_started = true;
    response.writer.buffer = response.memory[response.header_len..];
    response.writer.end = 0;
}

/// Makes a run of the bytes the body's writer holds, and gives the writer the memory after them.
/// With a run in every slot, the bytes go to a slot the engine released or to the newest run, or
/// they stay in the writer and the call returns `error.Full` (the owner's ruling of 2026-11-09).
pub fn cut(response: *Response) error{Full}!void {
    const written = response.writer.end;
    if (written == 0) return;
    if (response.piece_count == constants.limits.response_pieces_max) return ring.cut_full(response);
    response.pieces[response.piece_count] = response.writer.buffer[0..written];
    response.piece_count += 1;
    response.writer.buffer = response.writer.buffer[written..];
    response.writer.end = 0;
}

/// Cuts a run of the bytes the writer holds, and sends what waits. It returns false when the
/// bytes stay in the writer: the response then waits for a `writable`, which cuts again.
fn send(response: *Response) Error!bool {
    cut(response) catch return false;
    try push_open(response);
    return true;
}

/// Sends what waits while the body is open. A response that waits for a release asks the engine
/// again after the push. The engine keeps one wait for a request, and a run that it takes whole
/// ends that wait (`State.write_body`), so the first ask brings no `writable`.
pub fn push_open(response: *Response) Error!void {
    try push(response);
    if (response.release_waited) ring.wait_again(response);
}

pub fn add_piece(response: *Response, bytes: []const u8) Error!void {
    if (bytes.len == 0) return;
    if (response.piece_count == constants.limits.response_pieces_max) try free_slot(response);
    response.pieces[response.piece_count] = bytes;
    response.piece_count += 1;
}

/// The slow path of `add_piece`, with a run in every slot. The runs the engine released free
/// their slots. With none free, it sends what waits, the run that `write_kept` cut too (design
/// §8 step 46h). So the engine owes a `writable`, or it holds every run and the response waits for
/// a release. Then it returns `error.Full`, unless that push freed a slot.
fn free_slot(response: *Response) Error!void {
    ring.free_pieces(response);
    if (response.piece_count < constants.limits.response_pieces_max) return;
    try push(response);
    ring.free_pieces(response);
    if (response.piece_count < constants.limits.response_pieces_max) return;
    ring.wait_for_release(response);
    return error.Full;
}

/// Ends the body: the writer takes no more bytes.
pub fn close_body(response: *Response) void {
    assert(response.writer.end == 0);
    response.ended = true;
    response.writer.buffer = response.writer.buffer[0..0];
}

/// Copies the trailers into the writer's free region, after the body. With no room it returns
/// `error.NoSpaceLeft`, and the response may wait for the engine to release bytes.
pub fn copy_trailers(response: *Response, headers: []const http.Field) Error!void {
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    if (response.header_count + headers.len > constants.limits.response_headers_max) return error.SectionTooLarge;
    assert(response.writer.end == 0);
    const total = lines_len(headers);
    if (response.writer.buffer.len < total) try make_room(response, total);
    var first = @intFromPtr(response.writer.buffer.ptr) - @intFromPtr(response.memory.ptr);
    for (headers, 0..) |line, index| {
        const copied = try copy_line(response, first, line.name, line.value);
        response.lines[response.header_count + index] = copied.field;
        first = copied.end;
    }
    response.trailer_count = @intCast(headers.len);
    response.writer.buffer = response.writer.buffer[total..];
}

/// The slow path of `copy_trailers`: it sends the run `trailers` cut, so the engine owes a
/// `writable` or releases it, then takes back the released memory.
fn make_room(response: *Response, need: usize) Error!void {
    try push(response);
    if (!ring.refill(response, need)) return error.NoSpaceLeft;
}

/// Octets of the names and values of `headers`.
fn lines_len(headers: []const http.Field) usize {
    var total: usize = 0;
    for (headers) |line| total += line.name.len + line.value.len;
    return total;
}

/// Ends the body, and sends what waits.
pub fn end_now(response: *Response) Error!void {
    try cut(response);
    close_body(response);
    if (!response.head_out) add_content_length(response);
    try push(response);
}

/// Ends the body with the trailers that `lines` holds after the headers, and sends what waits.
pub fn trailers_now(response: *Response) Error!void {
    close_body(response);
    response.trailers_owed = true;
    try push(response);
}

/// Ends a wrapped response the way the program asked, once each wrapper wrote what it owes. A
/// response the program left open ends as `end` ends it.
pub fn end_wrapped(response: *Response) Error!void {
    assert(response.wrapped != null and !response.ended and response.body_started);
    if (response.end_asked != .trailers) return end_now(response);
    try cut(response);
    return trailers_now(response);
}

/// Copies the trailers to the end of the writer's region, where a wrapper's last bytes do not
/// reach, and keeps the body's writer before them. The region then stays where it is.
pub fn copy_trailers_last(response: *Response, headers: []const http.Field) Error!void {
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    if (response.header_count + headers.len > constants.limits.response_headers_max) return error.SectionTooLarge;
    const total = lines_len(headers);
    if (total > response.writer.buffer.len - response.writer.end) {
        try cut(response);
        try push(response);
        if (!ring.refill(response, total)) return error.NoSpaceLeft;
    }
    const region_end = @intFromPtr(response.writer.buffer.ptr + response.writer.buffer.len) - @intFromPtr(response.memory.ptr);
    var first = region_end - total;
    // Design §8 step 46: the trailers take memory the engine released.
    assert(!ring.overlaps_held(response, first, region_end));
    for (headers, 0..) |line, index| {
        const copied = try copy_line(response, first, line.name, line.value);
        response.lines[response.header_count + index] = copied.field;
        first = copied.end;
    }
    response.trailer_count = @intCast(headers.len);
    response.writer.buffer = response.writer.buffer[0 .. response.writer.buffer.len - total];
}

/// Adds Content-Length to a head that carries the whole body, unless the program set one, the
/// head has no room, or the status forbids it.
pub fn add_content_length(response: *Response) void {
    assert(!response.head_out and response.ended);
    // RFC 9110 §8.6: a server does not send Content-Length in a 1xx or 204 response.
    if (@intFromEnum(response.status) < final_min or response.status == .no_content) return;
    if (response.header_count == constants.limits.response_headers_max) return;
    for (response.lines[0..response.header_count]) |line| {
        if (std.ascii.eqlIgnoreCase(line.name, "content-length")) return;
    }
    var length: u64 = 0;
    for (response.pieces[0..response.piece_count]) |piece| length += piece.len;
    const digits = write_decimal(length, &response.length_digits);
    response.lines[response.header_count] = .{ .name = "content-length", .value = digits };
    response.header_count += 1;
}

/// Writes `value` in decimal at the end of `digits`, and returns the digits it wrote. It replaces
/// `std.fmt.bufPrint`, whose formatting cost more than the response's other bookkeeping.
fn write_decimal(value: u64, digits: *[length_digits_max]u8) []const u8 {
    var rest = value;
    var at: usize = digits.len;
    // Bounded by the digits of a u64, which `length_digits_max` counts.
    while (at > 0) {
        at -= 1;
        digits[at] = '0' + @as(u8, @intCast(rest % decimal_radix));
        rest /= decimal_radix;
        if (rest == 0) break;
    }
    assert(rest == 0);
    return digits[at..];
}

const decimal_radix = 10;

/// Sends what waits, in order: the head, each run of the body, and the end or the trailers. It
/// stops where the engine takes no more, and the request's `writable` calls it again.
pub fn push(response: *Response) Error!void {
    if (response.complete) return;
    if (!response.head_out) {
        if (!response.ended and response.piece_count == 0) return;
        if (!try push_head(response)) return;
        if (response.complete) return;
    }
    if (!try push_pieces(response)) return;
    if (!response.ended) return;
    if (response.trailers_owed) return push_trailers(response);
    // Each run went before the end: an empty run ends the body.
    const last: event.ResponseBody = .{ .bytes = &.{}, .end = true };
    _ = response.sink.write_body(response.sink.context, response.id, last) catch |failure| {
        _ = try wait_or(failure);
        return;
    };
    response.complete = true;
}

fn push_head(response: *Response) Error!bool {
    const ends = response.ended and response.piece_count == 0 and !response.trailers_owed;
    const head: event.ResponseHeader = .{ .status = response.status, .headers = response.lines[0..response.header_count], .end = ends };
    response.sink.respond(response.sink.context, response.id, head) catch |failure| return wait_or(failure);
    response.head_out = true;
    response.complete = ends;
    return true;
}

/// Writes each run the engine has not taken, and returns whether it took them all.
fn push_pieces(response: *Response) Error!bool {
    // Bounded: each pass takes one run, or returns.
    while (response.piece_sent < response.piece_count) {
        const piece = response.pieces[response.piece_sent][response.piece_offset..];
        const last = response.piece_sent + 1 == response.piece_count and response.ended and !response.trailers_owed;
        const body: event.ResponseBody = .{ .bytes = piece, .end = last };
        const taken = response.sink.write_body(response.sink.context, response.id, body) catch |failure| return wait_or(failure);
        response.taken_len += taken;
        if (taken < piece.len) {
            response.piece_offset += taken;
            return false;
        }
        response.piece_sent += 1;
        response.piece_offset = 0;
        if (last) {
            response.complete = true;
            return false;
        }
    }
    return true;
}

fn push_trailers(response: *Response) Error!void {
    const lines = response.lines[response.header_count..][0..response.trailer_count];
    response.sink.write_trailers(response.sink.context, response.id, lines) catch |failure| {
        _ = try wait_or(failure);
        return;
    };
    response.trailers_owed = false;
    response.complete = true;
}

/// False for an error that says the response waits for its `writable`, and the error otherwise.
fn wait_or(failure: connection_errors.SendError) Error!bool {
    return switch (failure) {
        error.NoSpaceLeft, error.Blocked => false,
        else => |other| other,
    };
}

/// The body writer's drain: it sends what the writer holds, then copies `data` whole into memory
/// the engine released, or fails and copies none (design §8 step 46). Memory the engine may still
/// read is never written again (decision 103). Before the body starts and after `end` the buffer
/// is empty, so every write fails: a wrapper writes nothing while the headers are open (design §8
/// step 25.6).
fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const response: *Response = @alignCast(@fieldParentPtr("writer", writer));
    const whole = send(response) catch return error.WriteFailed;
    const len = data_len(data, splat);
    if (len == 0) return 0;
    // Bytes a cut left in the writer hold its region where it is.
    const room = writer.buffer.len - writer.end;
    if (room < len and (!whole or !ring.refill(response, len))) return error.WriteFailed;
    const copied = copy_data(writer, data, splat);
    assert(copied == len);
    return copied;
}

/// The body writer's flush: it makes a run of the bytes the writer holds, and sends what waits.
/// With a run in every slot, the bytes go to the newest run, or stay in the writer until a slot
/// is free (the owner's ruling of 2026-11-09). It fails only when they stay and the writer's
/// region has no room for one more byte. Either way the route does not write them again.
fn flush(writer: *std.Io.Writer) std.Io.Writer.Error!void {
    if (writer.end == 0) return;
    const response: *Response = @alignCast(@fieldParentPtr("writer", writer));
    const whole = send(response) catch return error.WriteFailed;
    if (!whole and writer.end == writer.buffer.len) return error.WriteFailed;
}

fn copy_data(writer: *std.Io.Writer, data: []const []const u8, splat: usize) usize {
    var copied: usize = 0;
    for (data, 0..) |slice, index| {
        const times = if (index + 1 == data.len) splat else 1;
        for (0..times) |_| {
            const room = writer.buffer.len - writer.end;
            const len = @min(room, slice.len);
            @memcpy(writer.buffer[writer.end..][0..len], slice[0..len]);
            writer.end += len;
            copied += len;
            if (len < slice.len) return copied;
        }
    }
    return copied;
}

const final_min: u16 = @intFromEnum(http.Status.ok);

fn data_len(data: []const []const u8, splat: usize) usize {
    var len: usize = 0;
    for (data, 0..) |slice, index| len += slice.len * (if (index + 1 == data.len) splat else 1);
    return len;
}

const testing = std.testing;

/// Requires `write_decimal` to write what `std.fmt` writes for `value`. Test-only.
fn expect_decimal(value: u64) !void {
    var digits: [length_digits_max]u8 = undefined;
    var expected: [length_digits_max]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "{d}", .{value}), write_decimal(value, &digits));
}

fn fuzz_decimal(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: [@sizeOf(u64)]u8 = @splat(0);
    _ = smith.slice(&input);
    try expect_decimal(std.mem.readInt(u64, &input, .little));
}

test "fuzz: a Content-Length's digits are the ones std.fmt writes" {
    try testing.fuzz({}, fuzz_decimal, .{ .corpus = &.{
        @import("core").fuzz.input("\x00"),
        @import("core").fuzz.input("\xff\xff\xff\xff\xff\xff\xff\xff"),
    } });
    try @import("core").fuzz.sweep(fuzz_decimal, null);
    // The sweep reaches two octets alone, so this pass takes each power of ten, one less and one
    // more, up to the largest u64.
    var power: u64 = 1;
    for (0..length_digits_max) |_| {
        for ([_]u64{ power -% 1, power, power +% 1 }) |value| try expect_decimal(value);
        power = std.math.mul(u64, power, decimal_radix) catch break;
    }
    try expect_decimal(std.math.maxInt(u64));
}
