//! The tests of the ring of a `ResponseWriter`'s body (design §8 step 46), against the recorder of
//! `response_writer_test_support.zig`: what a writer does that waits for the engine to release
//! octets, or that finds a run in every slot. Split out of `response_writer_test.zig` for length.
const std = @import("std");
const support = @import("response_writer_test_support.zig");

const testing = std.testing;
const Fixture = support.Fixture;
const memory_len = support.memory_len;

test "design §8 step 46: a writer that waits for a release asks again after a push" {
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
