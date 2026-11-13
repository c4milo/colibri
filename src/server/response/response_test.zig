//! The tests of `Response` (decision 127, design §8 step 25.2), against the recorder of
//! `response_test_support.zig`. `response_ring_test.zig` holds more tests of the
//! body's ring.
const std = @import("std");
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const internal = @import("response_internal.zig");
const support = @import("response_test_support.zig");

const testing = std.testing;
const Call = support.Call;
const Fixture = support.Fixture;
const memory_len = support.memory_len;
const slots = support.slots;

fn expect_head(call: Call, status: u16, ends: bool) !event.ResponseHeader {
    try testing.expect(call == .head);
    try testing.expectEqual(status, @intFromEnum(call.head.status));
    try testing.expectEqual(ends, call.head.end);
    return call.head;
}

fn header_value(head: event.ResponseHeader, name: []const u8) ?[]const u8 {
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
    response.status = .no_content;
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

test "decision 103: the body never writes over bytes the engine holds, and fails past the memory" {
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
    // Design §8 step 46: the response waits for the engine to release bytes.
    try testing.expectEqual(1, fixture.recorder.release_waits);
    try testing.expect(internal.waiting(response));
}

test "design §8 step 46: the body writes again over the bytes the engine released, a write whole" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    try writer.writeAll("a" ** (memory_len - 2));
    try writer.flush();
    // Three octets fit neither after the run nor before it, so none of them is written.
    try testing.expectError(error.WriteFailed, writer.writeAll("bcd"));
    try testing.expectEqual(2, writer.unusedCapacityLen());
    var out: [memory_len]u8 = undefined;
    const before, _ = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("a" ** (memory_len - 2), before);
    // The engine releases the run, and the write goes to the front of the memory, whole.
    fixture.recorder.held = 0;
    try testing.expect(try internal.resume_writes(response) == false);
    try writer.writeAll("bcd");
    try testing.expectEqual(@intFromPtr(&fixture.memory), @intFromPtr(writer.buffer.ptr));
    try response.end();
    const last = fixture.recorder.calls[fixture.recorder.count - 1].body;
    try testing.expectEqualStrings("bcd", last.bytes);
    try testing.expect(last.end);
}

test "decision 127: what the engine does not take waits for writable, in order" {
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

test "decision 127: a head the engine has no room for waits, and its status stays the program's" {
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
    response.status = .not_found;
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

test "decision 127: no call after the end, and the engine's other errors come back" {
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
    response.status = @enumFromInt(42);
    try testing.expectError(error.StatusInvalid, response.end());
}

test "decision 127: more runs than response_pieces_max wait refused" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    fixture.recorder.room = 0;
    for (0..constants.limits.response_pieces_max) |_| try response.write_kept("a");
    try testing.expectError(error.Full, response.write_kept("a"));
}

test "design §8 step 46: trailers with no room send the body first, and go once it is released" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    try writer.writeAll("a" ** 100);
    try writer.flush();
    try writer.writeAll("b" ** 150);
    const lines: []const http.Field = &.{.{ .name = "x-trailer", .value = "v" ** 20 }};
    try testing.expectError(error.NoSpaceLeft, response.trailers(lines));
    // The run cut before the trailers went to the engine, and the response waits for its release.
    var out: [memory_len]u8 = undefined;
    const sent, _ = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("a" ** 100 ++ "b" ** 150, sent);
    try testing.expectEqual(1, fixture.recorder.release_waits);
    fixture.recorder.held = 0;
    try testing.expect(try internal.resume_writes(response) == false);
    try response.trailers(lines);
    const last = fixture.recorder.calls[fixture.recorder.count - 1];
    try testing.expectEqualStrings("v" ** 20, last.trailers[0].value);
    try testing.expect(internal.complete(response));
}

test "design §8 step 46: a flush with a run in every slot adds its bytes to the newest run" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    // The engine takes no content, so each flush leaves a run in a slot.
    fixture.recorder.room = 0;
    for (0..slots) |index| {
        try writer.writeAll(&.{ 'a' + @as(u8, @intCast(index)), '.' });
        try writer.flush();
    }
    try testing.expectEqual(slots, response.piece_count);
    // The engine takes fourteen runs and one octet of the next, and holds each in place.
    fixture.recorder.room = 2 * (slots - 2) + 1;
    try testing.expect(try internal.resume_writes(response) == false);
    // No slot is free. The engine took none of the newest run, so that run takes the bytes.
    try writer.writeAll("qr");
    try writer.flush();
    try testing.expectEqual(0, writer.end);
    try testing.expectEqual(slots, response.piece_count);
    try testing.expect(!response.cut_owed);
    // The engine takes the run before the newest, and one octet of the newest. The run still
    // takes bytes at its end, and the octet the engine took stays where it was.
    fixture.recorder.room = 2;
    try testing.expect(try internal.resume_writes(response) == false);
    const calls = fixture.recorder.count;
    try writer.writeAll("st");
    try writer.flush();
    try testing.expectEqual(0, writer.end);
    try testing.expectEqual(slots, response.piece_count);
    try testing.expectEqualStrings("p", fixture.recorder.calls[calls - 1].body.bytes);
    // The rest of the run goes in one call, in the order the program wrote it.
    fixture.recorder.room = std.math.maxInt(usize);
    try testing.expect(try internal.resume_writes(response) == false);
    try testing.expectEqual(calls + 1, fixture.recorder.count);
    try testing.expectEqualStrings(".qrst", fixture.recorder.calls[calls].body.bytes);
    try response.end();
    var out: [memory_len]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.qrst", body);
    try testing.expect(ended);
}

test "design §8 step 46: a flush stays in the writer while the engine holds a run in every slot" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    // The engine takes each run whole and holds it in place.
    for (0..slots) |_| {
        try writer.writeAll("abcd");
        try writer.flush();
    }
    const calls = fixture.recorder.count;
    // No slot is free, and the engine took the newest run, which must stay as it is. The flush
    // keeps its bytes with no error, and the response waits for a release.
    try writer.writeAll("efgh");
    try writer.flush();
    try testing.expectEqual(4, writer.end);
    try testing.expectEqual(1, fixture.recorder.release_waits);
    try testing.expect(internal.waiting(response));
    try testing.expectEqualStrings("abcd", fixture.recorder.calls[calls - 1].body.bytes);
    // The next message goes after the bytes kept. Once the memory is full too, the flush fails,
    // and so does a write.
    var rest: [memory_len]u8 = @splat('i');
    const rest_len = writer.unusedCapacityLen();
    try writer.writeAll(rest[0..rest_len]);
    try testing.expectError(error.WriteFailed, writer.flush());
    try testing.expectError(error.WriteFailed, writer.writeAll("x"));
    try testing.expect(!try internal.has_room(response));
    try testing.expectEqual(calls, fixture.recorder.count);
    // The engine releases its runs. The `writable` cuts the bytes kept into one run, once.
    fixture.recorder.held = 0;
    try testing.expect(try internal.resume_writes(response) == false);
    try testing.expectEqual(0, writer.end);
    try testing.expectEqual(calls + 1, fixture.recorder.count);
    try testing.expectEqual(4 + rest_len, fixture.recorder.calls[calls].body.bytes.len);
    // The engine holds that run, and the next write goes to the memory before it.
    try writer.writeAll("yz");
    try response.end();
    var out: [memory_len + 2]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("abcd" ** slots ++ "efgh", body[0 .. 4 * slots + 4]);
    try testing.expectEqualStrings(rest[0..rest_len], body[4 * slots + 4 ..][0..rest_len]);
    try testing.expectEqualStrings("yz", body[4 * slots + 4 + rest_len ..]);
    try testing.expect(ended);
}

test "decision 127: bytes after a write_kept run stay in the writer until a slot is free" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    const kept: []const u8 = "KEPT";
    fixture.recorder.room = 0;
    for (0..slots - 1) |_| {
        try writer.writeAll("ab");
        try writer.flush();
    }
    try response.write_kept(kept);
    // The newest run is the program's, so it takes no bytes of the writer.
    try writer.writeAll("xy");
    try writer.flush();
    try testing.expectEqual(2, writer.end);
    try testing.expectError(error.Full, response.write_kept("zz"));
    // The engine takes every run and holds each: no slot is free until it releases one.
    fixture.recorder.room = std.math.maxInt(usize);
    try testing.expect(try internal.resume_writes(response) == false);
    try testing.expectEqual(2, writer.end);
    try testing.expectEqual(1, fixture.recorder.release_waits);
    try testing.expectEqual(kept.ptr, fixture.recorder.calls[slots].body.bytes.ptr);
    try testing.expectEqual(kept.len, fixture.recorder.calls[slots].body.bytes.len);
    fixture.recorder.held = 0;
    try testing.expect(try internal.resume_writes(response) == false);
    try testing.expectEqual(0, writer.end);
    try response.end();
    var out: [memory_len]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("ab" ** (slots - 1) ++ "KEPT" ++ "xy", body);
    try testing.expect(ended);
}

test "design §8 step 46: the writer's region stays after the newest run while no slot is free" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    // The engine takes four runs and releases them, so the front of the memory is free.
    for (0..4) |_| {
        try writer.writeAll("a" ** 16);
        try writer.flush();
    }
    fixture.recorder.held = 0;
    // Sixteen runs that the engine does not take fill the rest of the memory, and every slot.
    fixture.recorder.room = 0;
    for (0..slots) |_| {
        try writer.writeAll("b" ** 12);
        try writer.flush();
    }
    try testing.expectEqual(0, writer.unusedCapacityLen());
    // The front has room. A run cut there would find no slot, and the newest run does not end
    // there, so it could not take the bytes. The write waits, as it does for a full memory.
    try testing.expectError(error.WriteFailed, writer.writeAll("c" ** 8));
    try testing.expectEqual(@intFromPtr(&fixture.memory) + memory_len, @intFromPtr(writer.buffer.ptr));
    // The engine takes every run and holds each, so no slot is free yet.
    fixture.recorder.room = std.math.maxInt(usize);
    try testing.expect(try internal.resume_writes(response) == false);
    try testing.expectError(error.WriteFailed, writer.writeAll("c" ** 8));
    try testing.expectEqual(1, fixture.recorder.release_waits);
    // A release frees the slots, and the write goes to the front.
    fixture.recorder.held = 0;
    try testing.expect(try internal.resume_writes(response) == false);
    try writer.writeAll("c" ** 8);
    try testing.expectEqual(@intFromPtr(&fixture.memory), @intFromPtr(writer.buffer.ptr));
    try response.end();
    var out: [memory_len + 8]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("a" ** 64 ++ "b" ** 192 ++ "c" ** 8, body);
    try testing.expect(ended);
}
