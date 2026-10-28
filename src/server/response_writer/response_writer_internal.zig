//! What `ResponseWriter`'s calls and the router share, and a program does not call (design §8 step
//! 25.2). The root exports none of it.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const ResponseWriter = @import("response_writer.zig").ResponseWriter;

/// What the calls of `ResponseWriter` return: the endpoint's errors, with their meaning, and `Full`
/// for more runs of body bytes than `response_pieces_max` that wait for the endpoint. The
/// endpoint's `NoSpaceLeft` and `Blocked` never come back: the writer holds what the endpoint did
/// not take until the request's `writable`. `NoSpaceLeft` here says the entry's memory is full.
pub const Error = error{Full} || connection_errors.SendError;

/// How a program ended a response whose body a middleware wraps (design §8 step 25.6): not yet,
/// with `end`, or with `trailers`.
pub const EndAsked = enum { none, end, trailers };

/// The digits of the largest Content-Length value.
pub const length_digits_max = std.fmt.count("{d}", .{std.math.maxInt(u64)});

/// The endpoint's three calls that write a response, without its type, so one `ResponseWriter`
/// serves every `EndpointOf`.
pub const Sink = struct {
    context: *anyopaque,
    respond: *const fn (context: *anyopaque, id: event.RequestId, response: event.Response) connection_errors.SendError!void,
    write_body: *const fn (context: *anyopaque, id: event.RequestId, body: event.ResponseBody) connection_errors.SendError!usize,
    write_trailers: *const fn (context: *anyopaque, id: event.RequestId, headers: []const http.Field) connection_errors.SendError!void,

    /// The sink of `endpoint`, an `*EndpointOf(capacity)`.
    pub fn of(comptime Endpoint: type, endpoint: *Endpoint) Sink {
        const calls = struct {
            fn respond(context: *anyopaque, id: event.RequestId, response: event.Response) connection_errors.SendError!void {
                return endpoint_of(Endpoint, context).respond(id, response);
            }
            fn write_body(context: *anyopaque, id: event.RequestId, body: event.ResponseBody) connection_errors.SendError!usize {
                return endpoint_of(Endpoint, context).write_body(id, body);
            }
            fn write_trailers(context: *anyopaque, id: event.RequestId, headers: []const http.Field) connection_errors.SendError!void {
                return endpoint_of(Endpoint, context).write_trailers(id, headers);
            }
        };
        return .{ .context = endpoint, .respond = calls.respond, .write_body = calls.write_body, .write_trailers = calls.write_trailers };
    }
};

fn endpoint_of(comptime Endpoint: type, context: *anyopaque) *Endpoint {
    return @ptrCast(@alignCast(context));
}

const vtable: std.Io.Writer.VTable = .{ .drain = drain, .rebase = std.Io.Writer.failingRebase };

/// Places a writer for request `id` over `memory`. The writer must not move after this call:
/// its body's `std.Io.Writer` finds it by its address.
pub fn init(response: *ResponseWriter, sink: Sink, id: event.RequestId, memory: []u8) void {
    response.* = .{ .sink = sink, .id = id, .memory = memory, .writer = .{ .vtable = &vtable, .buffer = memory[0..0] } };
}

/// Sends what waits, on the request's `writable`. It returns whether the response is whole.
pub fn resume_writes(response: *ResponseWriter) Error!bool {
    try push(response);
    return response.complete;
}

/// Whether bytes, the head or the end wait for the endpoint, which a `writable` sends.
pub fn waiting(response: *const ResponseWriter) bool {
    return response.piece_sent < response.piece_count or (response.ended and !response.complete);
}

/// Whether the endpoint took the whole response.
pub fn complete(response: *const ResponseWriter) bool {
    return response.complete;
}

/// A name and a value copied into `response.memory` from `first`, and the offset after them.
pub const Copied = struct { field: http.Field, end: usize };

pub fn copy_line(response: *ResponseWriter, first: usize, name: []const u8, value: []const u8) Error!Copied {
    const end = first + name.len + value.len;
    if (end > response.memory.len) return error.NoSpaceLeft;
    const name_copy = response.memory[first..][0..name.len];
    const value_copy = response.memory[first + name.len ..][0..value.len];
    @memcpy(name_copy, name);
    @memcpy(value_copy, value);
    return .{ .field = .{ .name = name_copy, .value = value_copy }, .end = end };
}

/// Closes the headers, and gives the body's writer the memory after them.
pub fn start_body(response: *ResponseWriter) void {
    assert(!response.body_started);
    response.body_started = true;
    response.writer.buffer = response.memory[response.header_len..];
    response.writer.end = 0;
}

/// Makes a run of the bytes the body's writer holds, and gives the writer the memory after them.
pub fn cut(response: *ResponseWriter) Error!void {
    const written = response.writer.end;
    if (written == 0) return;
    try add_piece(response, response.writer.buffer[0..written]);
    response.writer.buffer = response.writer.buffer[written..];
    response.writer.end = 0;
}

pub fn add_piece(response: *ResponseWriter, bytes: []const u8) Error!void {
    if (bytes.len == 0) return;
    // Runs the endpoint took whole free their slots.
    if (response.piece_sent == response.piece_count) {
        response.piece_sent = 0;
        response.piece_count = 0;
    }
    if (response.piece_count == constants.response_pieces_max) return error.Full;
    response.pieces[response.piece_count] = bytes;
    response.piece_count += 1;
}

/// Ends the body: the writer takes no more bytes.
pub fn close_body(response: *ResponseWriter) void {
    assert(response.writer.end == 0);
    response.ended = true;
    response.writer.buffer = response.writer.buffer[0..0];
}

pub fn copy_trailers(response: *ResponseWriter, headers: []const http.Field) Error!void {
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    if (response.header_count + headers.len > constants.response_headers_max) return error.SectionTooLarge;
    // The trailers' names and values go after the body, in the memory the writer has not used.
    const offset = @intFromPtr(response.writer.buffer.ptr) - @intFromPtr(response.memory.ptr);
    var first = offset;
    for (headers, 0..) |line, index| {
        const copied = try copy_line(response, first, line.name, line.value);
        response.lines[response.header_count + index] = copied.field;
        first = copied.end;
    }
    response.trailer_count = @intCast(headers.len);
    response.writer.buffer = response.memory[first..];
}

/// Ends the body, and sends what waits.
pub fn end_now(response: *ResponseWriter) Error!void {
    try cut(response);
    close_body(response);
    if (!response.head_out) add_content_length(response);
    try push(response);
}

/// Ends the body with the trailers that `lines` holds after the headers, and sends what waits.
pub fn trailers_now(response: *ResponseWriter) Error!void {
    close_body(response);
    response.trailers_owed = true;
    try push(response);
}

/// Ends a wrapped response the way the program asked, once each wrapper wrote what it owes. A
/// response the program left open ends as `end` ends it.
pub fn end_wrapped(response: *ResponseWriter) Error!void {
    assert(response.wrapped != null and !response.ended and response.body_started);
    if (response.end_asked != .trailers) return end_now(response);
    try cut(response);
    return trailers_now(response);
}

/// Copies the trailers to the end of `response.memory`, where a wrapper's last bytes do not reach,
/// and keeps the body's writer before them.
pub fn copy_trailers_last(response: *ResponseWriter, headers: []const http.Field) Error!void {
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    if (response.header_count + headers.len > constants.response_headers_max) return error.SectionTooLarge;
    var total: usize = 0;
    for (headers) |line| total += line.name.len + line.value.len;
    // The writer's buffer ends where the memory ends, until the body closes.
    assert(response.writer.buffer.ptr + response.writer.buffer.len == response.memory.ptr + response.memory.len);
    if (total > response.writer.buffer.len - response.writer.end) return error.NoSpaceLeft;
    var first = response.memory.len - total;
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
pub fn add_content_length(response: *ResponseWriter) void {
    assert(!response.head_out and response.ended);
    // RFC 9110 §8.6: a server does not send Content-Length in a 1xx or 204 response.
    if (response.status < final_min or response.status == no_content) return;
    if (response.header_count == constants.response_headers_max) return;
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
/// stops where the endpoint takes no more, and the request's `writable` calls it again.
pub fn push(response: *ResponseWriter) Error!void {
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

fn push_head(response: *ResponseWriter) Error!bool {
    const ends = response.ended and response.piece_count == 0 and !response.trailers_owed;
    const head: event.Response = .{ .status = response.status, .headers = response.lines[0..response.header_count], .end = ends };
    response.sink.respond(response.sink.context, response.id, head) catch |failure| return wait_or(failure);
    response.head_out = true;
    response.complete = ends;
    return true;
}

/// Writes each run the endpoint has not taken, and returns whether it took them all.
fn push_pieces(response: *ResponseWriter) Error!bool {
    // Bounded: each pass takes one run, or returns.
    while (response.piece_sent < response.piece_count) {
        const piece = response.pieces[response.piece_sent][response.piece_offset..];
        const last = response.piece_sent + 1 == response.piece_count and response.ended and !response.trailers_owed;
        const body: event.ResponseBody = .{ .bytes = piece, .end = last };
        const taken = response.sink.write_body(response.sink.context, response.id, body) catch |failure| return wait_or(failure);
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

fn push_trailers(response: *ResponseWriter) Error!void {
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

/// The body writer's drain: it sends what the writer holds, then copies what fits of `data` into
/// the memory after it. Memory the endpoint may still read is never written again (decision 103).
/// Before the body starts and after `end` the buffer is empty, so every write fails: a wrapper
/// writes nothing while the headers are open (design §8 step 25.6).
fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const response: *ResponseWriter = @alignCast(@fieldParentPtr("writer", writer));
    cut(response) catch return error.WriteFailed;
    push(response) catch return error.WriteFailed;
    const copied = copy_data(writer, data, splat);
    if (copied == 0 and data_len(data, splat) > 0) return error.WriteFailed;
    return copied;
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

const final_min: u16 = @intFromEnum(http.status.Code.ok);
const no_content: u16 = @intFromEnum(http.status.Code.no_content);

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
