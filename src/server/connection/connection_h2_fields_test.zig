//! The tests that hold the h2 half's field lines to the code they replaced, each kept here as the
//! reference.
//!
//! - `respond` and `write_trailers` copied the caller's fields into an array of `h2.hpack.Field`
//!   and gave h2 the copy, and ReleaseSafe filled the array's 4,096 octets on every call.
//!   `h2.hpack.Field` is `http.Field` now, so h2 reads the caller's fields where they are. Each
//!   call must return what the copy returns and send the same octets, at every count of lines up
//!   to `field_count_max` and one past it.
//! - A request's regular field lines were found by reading lines until one did not start with a
//!   colon (`event.Headers.of`). They are counted from the request's pseudo-header fields now, and
//!   the count must be where `Fields.of` finds the first regular line, for every set of them.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");
const internal = @import("connection_internal.zig");
const event = @import("../event.zig");

const testing = std.testing;
const connection = &support.connection;
const field_count_max = h2.core.constants.limits.field_count_max;
const ok: u16 = 200;

/// One line more than a section may carry, each with a name and a value no other line has, so
/// that a line read from the wrong place changes the octets. Test-only.
const lines: [field_count_max + 1]support.Field = made: {
    var all: [field_count_max + 1]support.Field = undefined;
    for (&all, 0..) |*line, index| {
        const pair = [_]u8{ letters[index / letters.len], letters[index % letters.len] };
        line.* = .{ .name = "x-line-" ++ pair, .value = "value " ++ pair };
    }
    break :made all;
};
/// What a line's index is spelled with, two letters a line. Test-only.
const letters = "abcdefghijklmnop";
comptime {
    std.debug.assert(lines.len <= letters.len * letters.len);
}

/// What each side of a comparison sent. Test-only.
var changed_octets: [support.output_len]u8 = undefined;
var reference_octets: [support.output_len]u8 = undefined;

/// Which call a comparison makes after the request arrived.
const Call = enum { respond, write_trailers };

/// The copy `respond` and `write_trailers` made: `fields` as an array of `h2.hpack.Field`.
fn copy_fields(fields: []const support.Field, copied: *[field_count_max]h2.hpack.Field) ![]const h2.hpack.Field {
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    if (fields.len > copied.len) return error.SectionTooLarge;
    for (fields, copied[0..fields.len]) |field, *line| line.* = .{ .name = field.name, .value = field.value };
    return copied[0..fields.len];
}

/// The reference: h2 called with the copy the old code made, in place of the caller's fields.
fn call_by_copy(call: Call, fields: []const support.Field) !void {
    var copied: [field_count_max]h2.hpack.Field = undefined;
    const converted = try copy_fields(fields, &copied);
    const session = &connection.session.h2;
    connection.output_len += switch (call) {
        .respond => try session.write_response(internal.room(connection), 1, ok, converted, true),
        .write_trailers => try session.write_trailers(internal.room(connection), 1, converted),
    };
}

/// A connection that has read a request on stream 1 and, before a trailer section, sent its
/// response's head.
fn start(call: Call) !void {
    try h2_support.start();
    _ = try support.receive_copy(try h2_support.request_frame(1, "/", true));
    if (call == .respond) return;
    try connection.respond(1, .{ .status = ok, .end = false });
    _ = support.drain();
}

/// The error a call returned, or null.
fn failure_of(result: anyerror!void) ?anyerror {
    result catch |failure| return failure;
    return null;
}

/// Whether two outcomes are the same: no error twice, or one error twice. It is written out
/// because Zig 0.16's x86_64 backend, which builds Debug on x86_64 Linux, gives false for `==`
/// between two optional errors that hold the same error.
fn same_failure(first: ?anyerror, second: ?anyerror) bool {
    const one = first orelse return second == null;
    const other = second orelse return false;
    return one == other;
}

/// Sends what the connection holds into `octets` and returns how much that was.
fn drain_into(octets: *[support.output_len]u8) usize {
    const sent = support.drain();
    @memcpy(octets[0..sent.len], sent);
    return sent.len;
}

/// Fails, printing both outcomes, when the call and the reference differ on `fields`: in what they
/// return, or in the octets the connection sends afterwards.
fn expect_same(call: Call, fields: []const support.Field) !void {
    try start(call);
    const changed = failure_of(switch (call) {
        .respond => connection.respond(1, .{ .status = ok, .headers = fields, .end = true }),
        .write_trailers => connection.write_trailers(1, fields),
    });
    const changed_sent = changed_octets[0..drain_into(&changed_octets)];
    try start(call);
    const reference = failure_of(call_by_copy(call, fields));
    const reference_sent = reference_octets[0..drain_into(&reference_octets)];
    if (same_failure(changed, reference) and std.mem.eql(u8, changed_sent, reference_sent)) return;
    std.debug.print("first difference: {t} with {d} lines: changed {any} {x}, reference {any} {x}\n", .{
        call, fields.len, changed, changed_sent, reference, reference_sent,
    });
    return error.TestUnexpectedResult;
}

test "respond sends what the copying reference sends, at every count of lines" {
    for (0..lines.len + 1) |count| try expect_same(.respond, lines[0..count]);
}

test "write_trailers sends what the copying reference sends, at every count of lines" {
    for (0..lines.len + 1) |count| try expect_same(.write_trailers, lines[0..count]);
}

test "RFC 9110 §5.4: a section of field_count_max lines is sent whole, and one line more is refused" {
    try start(.respond);
    try connection.respond(1, .{ .status = ok, .headers = lines[0..field_count_max], .end = false });
    // The head went out whole: one HEADERS frame that ends its field block (RFC 9113 §6.2).
    const head = support.drain();
    try testing.expectEqual(h2.constants.protocol.frame_type_headers, head[h2_support.type_index]);
    try testing.expect(head[h2_support.flags_index] & h2.constants.protocol.flag_end_headers != 0);
    try testing.expectEqual(head.len, h2_support.frame_len(head));
    try testing.expectError(error.SectionTooLarge, connection.write_trailers(1, &lines));
    try testing.expectEqual(0, connection.output_len);
    try connection.write_trailers(1, lines[0..field_count_max]);
}

test "RFC 9113 §5.1.1: an id that names no stream is refused before its lines are counted" {
    try start(.respond);
    try testing.expectError(error.RequestUnknown, connection.respond(0, .{ .status = ok, .headers = &lines, .end = true }));
    try testing.expectError(error.RequestUnknown, connection.write_trailers(0, &lines));
}

test "a section refused for its count leaves the reply h2 owes unwritten, and the next response follows it" {
    try h2_support.start();
    // A PING, which h2 owes an acknowledgment for (RFC 9113 §6.7), and then a request.
    var writer = h2.core.Writer.init(&h2_support.frames);
    try h2.frame.write_ping(&writer, @splat(0), false);
    const ping_len = writer.written().len;
    @memcpy(support.input[0..ping_len], h2_support.frames[0..ping_len]);
    const request = try h2_support.request_frame(1, "/", true);
    @memcpy(support.input[ping_len..][0..request.len], request);
    const received = try connection.receive(support.input[0 .. ping_len + request.len], support.now_ns);
    try testing.expectEqual(1, received.event.?.request.id.number);
    const held_len = connection.output_len;
    try testing.expectError(error.SectionTooLarge, connection.respond(1, .{ .status = ok, .headers = &lines, .end = true }));
    try testing.expectEqual(held_len, connection.output_len);
    try connection.respond(1, .{ .status = ok, .end = true });
    const sent = support.drain();
    try testing.expectEqual(h2.constants.protocol.frame_type_ping, sent[held_len + h2_support.type_index]);
}

/// The pseudo-header field lines a request can carry, as h2 admits them (RFC 9113 §8.3.1, §8.5).
/// Test-only.
const PseudoSet = []const support.Field;
const pseudo_sets = [_]PseudoSet{
    &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "http" }, .{ .name = ":path", .value = "/" }, .{ .name = ":authority", .value = "example.com" } },
    &.{ .{ .name = ":authority", .value = "example.com" }, .{ .name = ":path", .value = "/" }, .{ .name = ":scheme", .value = "http" }, .{ .name = ":method", .value = "POST" } },
    // RFC 9113 §8.3.1: `:authority` may be left out.
    &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/a" } },
    // RFC 9113 §8.5: a CONNECT request carries `:method` and `:authority` alone.
    &.{ .{ .name = ":method", .value = "CONNECT" }, .{ .name = ":authority", .value = "example.com:443" } },
};

/// Sends a HEADERS frame on stream 1 holding `pseudo` and then `regular`, and returns the event.
fn receive_request(pseudo: PseudoSet, regular: []const support.Field, end: bool) !event.ConnectionEvent {
    var block: [h2.constants.limits.frame_size_max]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(h2.constants.protocol.header_table_size_initial, .never);
    var block_writer = h2.core.Writer.init(&block);
    try encoder.begin_block(&block_writer);
    for (pseudo) |line| try encoder.write_field(&block_writer, line.name, line.value, .without_indexing);
    for (regular) |line| try encoder.write_field(&block_writer, line.name, line.value, .without_indexing);
    encoder.commit_block();
    var writer = h2.core.Writer.init(&h2_support.frames);
    const end_flag: u8 = if (end) h2.constants.protocol.flag_end_stream else 0;
    try h2.frame.write_header(&writer, .{
        .length = @intCast(block_writer.written().len),
        .type = h2.constants.protocol.frame_type_headers,
        .flags = h2.constants.protocol.flag_end_headers | end_flag,
        .stream_id = 1,
    });
    try writer.write_bytes(block_writer.written());
    return (try support.receive_copy(writer.written())).event.?;
}

/// Fails, printing both, when the event's first regular line is not where `Fields.of` finds it.
fn expect_first_as_scanned(fields: event.Headers) !void {
    const scanned = event.Headers.of(fields.section).first;
    if (fields.first == scanned) return;
    std.debug.print("first difference: the count gives {d}, the scan {d}\n", .{ fields.first, scanned });
    return error.TestUnexpectedResult;
}

test "RFC 9113 §8.3: a request's count of pseudo-header lines is where the scan finds its first regular line" {
    const regular = [_]support.Field{ .{ .name = "accept", .value = "*/*" }, .{ .name = "x-a", .value = "b" }, .{ .name = "x-c", .value = "d" } };
    for (pseudo_sets) |pseudo| {
        for (0..regular.len + 1) |count| {
            try h2_support.start();
            const arrived = try receive_request(pseudo, regular[0..count], true);
            try expect_first_as_scanned(arrived.request.headers);
            try testing.expectEqual(count, arrived.request.headers.len());
        }
    }
}

test "RFC 9113 §8.1: a trailer section's lines are all regular, as the scan finds" {
    const trailer_lines = [_]support.Field{ .{ .name = "grpc-status", .value = "0" }, .{ .name = "x-a", .value = "b" } };
    try h2_support.start();
    _ = try receive_request(pseudo_sets[0], &.{}, false);
    const arrived = try receive_request(&.{}, &trailer_lines, true);
    try expect_first_as_scanned(arrived.trailers.headers);
    try testing.expectEqual(trailer_lines.len, arrived.trailers.headers.len());
}

test "RFC 9113 §8.1: an empty trailer section has no line, as the scan finds" {
    try h2_support.start();
    _ = try receive_request(pseudo_sets[0], &.{}, false);
    const arrived = try receive_request(&.{}, &.{}, true);
    try expect_first_as_scanned(arrived.trailers.headers);
    try testing.expectEqual(0, arrived.trailers.headers.len());
}
