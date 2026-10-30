//! The tests of the reset limits a server's `Limits` gives its h2 connections (decision 110 as
//! amended on 2026-10-17): each is where the connection ends, in place of h2's constant.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const constants = h2.constants;
const frames = &h2_support.frames;

/// The lower limits the tests set, each well under h2's constant of 100. Test-only.
const peer_resets_few: u32 = 3;
const resets_sent_few: u32 = 2;

/// Starts an h2 connection whose `Limits` are `limits`, and sets them back for the next test.
fn start_with(limits: support.Limits) !void {
    support.limits = limits;
    defer support.limits = .{};
    try h2_support.start();
}

/// Opens stream `id` with a whole request, then resets it, as a Rapid Reset peer does
/// (CVE-2023-44487). Test-only.
fn open_and_reset(id: u32) !void {
    const opened = try support.receive_copy(try h2_support.request_frame(id, "/", true));
    try testing.expectEqual(id, opened.event.?.request.id.number);
    var writer = h2.core.Writer.init(frames);
    try h2.frame.write_rst_stream(&writer, id, constants.protocol.error_cancel);
    _ = try support.receive_copy(writer.written());
}

/// Opens stream `id` without ending it, then sends a WINDOW_UPDATE of 0 on it, which h2 answers
/// with a RST_STREAM (RFC 9113 §6.9). Test-only.
fn open_and_break(id: u32) !void {
    _ = try support.receive_copy(try h2_support.request_frame(id, "/", false));
    // `write_window_update` writes no increment of 0, so the frame is built by hand.
    var writer = h2.core.Writer.init(frames);
    try h2.frame.write_header(&writer, .{
        .length = constants.protocol.window_update_len,
        .type = constants.protocol.frame_type_window_update,
        .flags = 0,
        .stream_id = id,
    });
    try writer.write_int(u32, 0);
    _ = try support.receive_copy(writer.written());
    _ = support.drain();
}

test "decision 110 as amended: Limits.peer_resets_max is where a peer that resets its streams ends the connection" {
    try start_with(.{ .peer_resets_max = peer_resets_few });
    var id: u32 = 1;
    for (0..peer_resets_few) |_| {
        try open_and_reset(id);
        id += 2;
    }
    try testing.expectEqual(null, connection.close_reason());
    // RFC 9113 §10.5: the reset past the limit is excess use, and ends the connection.
    try testing.expectError(error.ConnectionFailed, open_and_reset(id));
    try testing.expectEqual(.peer_resets, connection.close_reason().?.limit);
}

test "decision 110 as amended: Limits.resets_sent_max is where a peer whose streams the server resets ends the connection" {
    try start_with(.{ .resets_sent_max = resets_sent_few });
    var id: u32 = 1;
    for (0..resets_sent_few) |_| {
        try open_and_break(id);
        id += 2;
    }
    try testing.expectEqual(null, connection.close_reason());
    try testing.expectError(error.ConnectionFailed, open_and_break(id));
    try testing.expectEqual(.resets_sent, connection.close_reason().?.limit);
}

test "decision 110 as amended: the default Limits leave h2's constants in place" {
    try start_with(.{});
    try testing.expectEqual(constants.policy.peer_reset_rate_max, connection.session.h2.peer_resets_max);
    try testing.expectEqual(constants.policy.rst_stream_rate_max, connection.session.h2.resets_sent_max);
}
