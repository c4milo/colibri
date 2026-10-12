//! The tests that hold the h2 half's `respond` and `write_trailers` to the code they replaced.
//! That code copied the caller's fields into an array of `h2.hpack.Field` and gave h2 the copy,
//! and ReleaseSafe filled the array's 4,096 octets on every call. `h2.hpack.Field` is `http.Field`
//! now, so h2 reads the caller's fields where they are. The copy stays here as the reference: each
//! call must return what the reference returns and send the same octets, at every count of lines
//! up to `field_count_max` and one past it.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");
const internal = @import("connection_internal.zig");

const testing = std.testing;
const connection = &support.connection;
const field_count_max = h2.core.constants.field_count_max;
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
        .respond => connection.respond(1, .{ .status = ok, .fields = fields, .end = true }),
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
    try connection.respond(1, .{ .status = ok, .fields = lines[0..field_count_max], .end = false });
    // The head went out whole: one HEADERS frame that ends its field block (RFC 9113 §6.2).
    const head = support.drain();
    try testing.expectEqual(h2.constants.frame_type_headers, head[h2_support.type_index]);
    try testing.expect(head[h2_support.flags_index] & h2.constants.flag_end_headers != 0);
    try testing.expectEqual(head.len, h2_support.frame_len(head));
    try testing.expectError(error.SectionTooLarge, connection.write_trailers(1, &lines));
    try testing.expectEqual(0, connection.output_len);
    try connection.write_trailers(1, lines[0..field_count_max]);
}

test "RFC 9113 §5.1.1: an id that names no stream is refused before its lines are counted" {
    try start(.respond);
    try testing.expectError(error.RequestUnknown, connection.respond(0, .{ .status = ok, .fields = &lines, .end = true }));
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
    try testing.expectError(error.SectionTooLarge, connection.respond(1, .{ .status = ok, .fields = &lines, .end = true }));
    try testing.expectEqual(held_len, connection.output_len);
    try connection.respond(1, .{ .status = ok, .end = true });
    const sent = support.drain();
    try testing.expectEqual(h2.constants.frame_type_ping, sent[held_len + h2_support.type_index]);
}
