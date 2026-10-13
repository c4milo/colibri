//! The test that holds `connection_internal.zig`'s `make_h2_session` to its claim: the h2 session
//! is made with its payload's octets left as they were, so an h2 connection must send the same
//! octets and report the same events whatever its storage held before. The test fills the whole
//! connection with one octet, runs one h2 exchange over it, and compares what came out with what
//! came out over storage filled with another.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const ok: u16 = 200;
/// The streams the exchange opens: answered with a body, answered with a trailer section, and
/// reset by the peer. Test-only.
const stream_body: u32 = 1;
const stream_trailers: u32 = 3;
const stream_reset: u32 = 5;
/// A SETTINGS frame with no setting in it (RFC 9113 §6.5). Test-only.
const empty_settings = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
/// The octets a PING carries. Test-only.
const ping_octet: u8 = 'p';

/// Octets a run's record holds: everything the connection sent, and one octet a reported event.
const record_len_max = 16_384;

/// What one run sent and reported, in order. Test-only.
const Record = struct {
    octets: [record_len_max]u8 = undefined,
    len: usize = 0,

    fn add(record: *Record, octets: []const u8) !void {
        if (octets.len > record.octets.len - record.len) return error.TestUnexpectedResult;
        @memcpy(record.octets[record.len..][0..octets.len], octets);
        record.len += octets.len;
    }

    fn written(record: *const Record) []const u8 {
        return record.octets[0..record.len];
    }
};

/// Feeds `octets` to the connection, reads every event it reports, and records the events'
/// kinds and then what it sends.
fn feed(record: *Record, octets: []const u8) !void {
    var received = try support.receive_copy(octets);
    for (0..h2.constants.concurrent_streams_max) |_| {
        const reported = received.event orelse break;
        try record.add(&.{@intFromEnum(reported)});
        received = try connection.receive(&.{}, support.now_ns);
    }
    try record.add(support.drain());
}

/// Builds one frame with `write` into the frames buffer the h2 tests share, and returns it.
fn frame_of(comptime write: fn (*h2.core.Writer) anyerror!void) ![]const u8 {
    var writer = h2.core.Writer.init(&h2_support.frames);
    try write(&writer);
    return writer.written();
}

fn ping(writer: *h2.core.Writer) anyerror!void {
    try h2.frame.write_ping(writer, @splat(ping_octet), false);
}

fn reset_stream(writer: *h2.core.Writer) anyerror!void {
    try h2.frame.write_rst_stream(writer, stream_reset, h2.constants.error_cancel);
}

/// One h2 exchange over the connection: requests answered with a body and with a trailer
/// section, a PING, a SETTINGS frame, a stream the peer resets, and a shutdown.
fn run_exchange(record: *Record) !void {
    try h2_support.start();
    try feed(record, try h2_support.request_frame(stream_body, "/one", true));
    try connection.respond(stream_body, .{ .status = ok, .end = false });
    _ = try connection.write_body(stream_body, .{ .octets = "hello", .end = true });
    try record.add(support.drain());
    try feed(record, try frame_of(ping));
    try feed(record, try h2_support.request_frame(stream_trailers, "/three", true));
    try connection.respond(stream_trailers, .{ .status = ok, .end = false });
    try connection.write_trailers(stream_trailers, &.{.{ .name = "grpc-status", .value = "0" }});
    try record.add(support.drain());
    try feed(record, empty_settings);
    try feed(record, try h2_support.request_frame(stream_reset, "/five", false));
    try feed(record, try frame_of(reset_stream));
    connection.shutdown();
    try feed(record, &.{});
}

/// What each run's storage is filled with before it starts: zeros, ones, the 0xAA ReleaseSafe
/// writes for `undefined`, and another pattern.
const fill_ones: u8 = std.math.maxInt(u8);
const fill_undefined: u8 = 0b1010_1010;
const fill_pattern: u8 = 0b0101_1100;
const fills = [_]u8{ 0, fill_ones, fill_undefined, fill_pattern };

test "an h2 connection sends and reports the same whatever its storage held before" {
    var first: Record = .{};
    @memset(std.mem.asBytes(connection), fills[0]);
    try run_exchange(&first);
    try testing.expect(first.len > 0);
    for (fills[1..]) |fill| {
        var again: Record = .{};
        @memset(std.mem.asBytes(connection), fill);
        try run_exchange(&again);
        if (std.mem.eql(u8, first.written(), again.written())) continue;
        std.debug.print("first difference: storage filled with {x} gives {x}, with {x} gives {x}\n", .{
            fill, again.written(), fills[0], first.written(),
        });
        return error.TestUnexpectedResult;
    }
}
