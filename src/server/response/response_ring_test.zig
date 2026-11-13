//! The tests of the ring of a `Response`'s body (design §8 step 46), against the recorder of
//! `response_test_support.zig`: what a response does that waits for the engine to release
//! octets, or that finds a run in every slot. Split out of `response_test.zig` for length.
const std = @import("std");
const http = @import("http");
const internal = @import("response_internal.zig");
const support = @import("response_test_support.zig");

const testing = std.testing;
const Fixture = support.Fixture;
const memory_len = support.memory_len;
const slots = support.slots;

test "design §8 step 46: a response that waits for a release asks again after a push" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    try writer.writeAll("a" ** (memory_len - 8));
    try writer.flush();
    try testing.expectError(error.WriteFailed, writer.writeAll("b" ** 16));
    try testing.expectEqual(1, fixture.recorder.release_waits);
    // The engine takes each run below whole, which ends the wait it held (`State.write_body`).
    try writer.writeAll("cd");
    try writer.flush();
    try testing.expectEqual(2, fixture.recorder.release_waits);
    try response.write_kept("ef");
    try testing.expectEqual(3, fixture.recorder.release_waits);
    // A write that sends no run leaves that wait, and asks for none while no octet is held.
    fixture.recorder.held = 0;
    try writer.writeAll("b" ** 16);
    try testing.expectEqual(3, fixture.recorder.release_waits);
}

/// Fills every slot with a run of four octets that the engine takes whole and holds.
fn fill_slots(writer: *std.Io.Writer) !void {
    for (0..slots) |_| {
        try writer.writeAll("abcd");
        try writer.flush();
    }
}

test "design §8 step 46: once the bytes a cut kept went, a writable cuts no bytes before a flush" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    try fill_slots(writer);
    // No slot is free, and the engine took the newest run, so the flush keeps its bytes.
    try writer.writeAll("efgh");
    try writer.flush();
    try testing.expect(response.cut_owed);
    // A release frees the slots, and the `writable` cuts the bytes kept into a run.
    fixture.recorder.held = 0;
    try testing.expect(try internal.resume_writes(response) == false);
    try testing.expect(!response.cut_owed);
    const calls = fixture.recorder.count;
    try testing.expectEqualStrings("efgh", fixture.recorder.calls[calls - 1].body.bytes);
    // The route writes two octets and does not flush them. The next `writable` leaves them in
    // the writer: only a flush, a full region or the end sends them.
    try writer.writeAll("ij");
    try testing.expect(try internal.resume_writes(response) == false);
    try testing.expectEqual(2, writer.end);
    try testing.expectEqual(calls, fixture.recorder.count);
}

test "design §8 step 46: a write goes to the start of the memory once the oldest of sixteen runs is released" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    // Sixteen runs fill the memory and every slot, and the engine takes each whole and holds it.
    const run_len = memory_len / slots;
    try writer.writeAll("a" ** run_len);
    try writer.flush();
    for (1..slots) |_| {
        try writer.writeAll("b" ** run_len);
        try writer.flush();
    }
    try testing.expectEqual(0, writer.unusedCapacityLen());
    try testing.expectError(error.WriteFailed, writer.writeAll("c" ** 8));
    // The engine releases the oldest run alone. Its slot is free for the run cut next, so the
    // writer's region goes to the start of the memory, over the octets of that run.
    fixture.recorder.held -= run_len;
    try writer.writeAll("c" ** 8);
    try testing.expectEqual(@intFromPtr(&fixture.memory), @intFromPtr(writer.buffer.ptr));
    try testing.expectEqual(run_len, writer.buffer.len);
    try response.end();
    var out: [memory_len + 8]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("a" ** run_len ++ "b" ** (memory_len - run_len) ++ "c" ** 8, body);
    try testing.expect(ended);
}

test "design §8 step 46: a flush that keeps its bytes fails only when no octet of room is left" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    try fill_slots(writer);
    // The flush keeps its bytes, and one octet of the writer's region is free: no error.
    const filler: [memory_len]u8 = @splat('e');
    try writer.writeAll(filler[0 .. writer.unusedCapacityLen() - 1]);
    try writer.flush();
    try testing.expect(response.cut_owed);
    try testing.expectEqual(1, writer.unusedCapacityLen());
    // The last octet fills the region, and the flush fails. It keeps its bytes too.
    try writer.writeAll("f");
    try testing.expectError(error.WriteFailed, writer.flush());
    try testing.expectEqual(memory_len - 4 * slots, writer.end);
}

test "decision 127: end, trailers and write_kept return Full while a cut keeps its bytes" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    try fill_slots(writer);
    try writer.writeAll("efgh");
    try writer.flush();
    const calls = fixture.recorder.count;
    const before = internal.mark(response);
    // No run takes the bytes the writer keeps, and nothing goes out before them. Each call
    // returns `error.Full` and changes nothing of the response.
    const lines: []const http.Field = &.{.{ .name = "checksum", .value = "1" }};
    try testing.expectError(error.Full, response.end());
    try testing.expectError(error.Full, response.trailers(lines));
    try testing.expectError(error.Full, response.write_kept("KEPT"));
    try testing.expect(internal.mark(response).eql(before));
    try testing.expectEqual(4, writer.end);
    try testing.expectEqual(calls, fixture.recorder.count);
    try testing.expect(!response.ended and response.trailer_count == 0);
    try testing.expect(internal.waiting(response));
    // The engine releases the oldest run. The second call of `end` cuts the bytes kept into
    // the slot that the release freed, and ends the response.
    fixture.recorder.held -= 4;
    try response.end();
    try testing.expect(internal.complete(response));
    var out: [memory_len]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("abcd" ** slots ++ "efgh", body);
    try testing.expect(ended);
}

test "decision 127: write_kept with no free slot sends the run it cut before it waits" {
    var fixture: Fixture = .{};
    const response = fixture.start();
    const writer = response.body();
    // The engine takes fifteen runs whole and holds each.
    for (0..slots - 1) |_| {
        try writer.writeAll("ab");
        try writer.flush();
    }
    const calls = fixture.recorder.count;
    // The bytes the writer holds take the last slot, so the program's bytes find none, and the
    // call returns `error.Full`. The run it cut goes to the engine first. So the engine holds
    // every run, the response waits for a release, and a `writable` comes.
    try writer.writeAll("cd");
    try testing.expectError(error.Full, response.write_kept("KEPT"));
    try testing.expectEqual(calls + 1, fixture.recorder.count);
    try testing.expectEqualStrings("cd", fixture.recorder.calls[calls].body.bytes);
    try testing.expectEqual(1, fixture.recorder.release_waits);
    try testing.expect(internal.waiting(response));
    // The engine releases the oldest run, and the second call adds the program's bytes.
    fixture.recorder.held -= 2;
    try testing.expect(try internal.resume_writes(response) == false);
    try response.write_kept("KEPT");
    try response.end();
    var out: [memory_len]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("ab" ** (slots - 1) ++ "cd" ++ "KEPT", body);
    try testing.expect(ended);
}

test "decision 127: write_kept with no free slot goes on once the engine takes the runs that wait" {
    var fixture: Fixture = .{ .recorder = .{ .copies = true } };
    const response = fixture.start();
    // RFC 9113 §6.9: the window is closed, so each run waits in a slot.
    fixture.recorder.room = 0;
    for (0..slots) |_| try response.write_kept("a");
    try testing.expectError(error.Full, response.write_kept("b"));
    // The window opens before the request's `writable`. The call sends the runs that wait. The
    // engine copies each and releases it at once, so the slots are free for the program's bytes.
    fixture.recorder.room = std.math.maxInt(usize);
    try response.write_kept("b");
    try testing.expectEqual(0, fixture.recorder.release_waits);
    try response.end();
    var out: [memory_len]u8 = undefined;
    const body, const ended = fixture.recorder.body_of(&out);
    try testing.expectEqualStrings("a" ** slots ++ "b", body);
    try testing.expect(ended);
}
