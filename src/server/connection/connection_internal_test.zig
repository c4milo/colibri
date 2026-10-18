//! The tests of `make_h2_session` and `make_h11_session` in `connection_internal.zig`. Each one
//! leaves its session's payload unfilled. So a connection must send the same octets and report
//! the same events, whatever its storage held before. Each test fills the whole connection with
//! one octet and runs one exchange over it. Then it compares the output with the output over
//! storage filled with another octet.
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

/// Fails when `run` sends or reports anything else over storage filled with each of `fills` than
/// over storage filled with the first.
fn expect_same_over_fills(comptime run: fn (*Record) anyerror!void) !void {
    var first: Record = .{};
    @memset(std.mem.asBytes(connection), fills[0]);
    try run(&first);
    try testing.expect(first.len > 0);
    for (fills[1..]) |fill| {
        var again: Record = .{};
        @memset(std.mem.asBytes(connection), fill);
        try run(&again);
        if (std.mem.eql(u8, first.written(), again.written())) continue;
        std.debug.print("first difference: storage filled with {x} gives {x}, with {x} gives {x}\n", .{
            fill, again.written(), fills[0], first.written(),
        });
        return error.TestUnexpectedResult;
    }
}

test "an h2 connection sends and reports the same whatever its storage held before" {
    try expect_same_over_fills(run_exchange);
}

/// The h11 exchange's requests. The test answers the first with a body, and the second, which has
/// content, with chunks and a trailer section. Two more arrive in one read, and the last asks for
/// the close. Test-only.
const h11_get = "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n";
const h11_post = "POST /two HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";
const h11_fourth = "GET /four HTTP/1.1\r\nHost: example.test\r\n\r\n";
const h11_pipelined = "GET /three HTTP/1.1\r\nHost: example.test\r\n\r\n" ++ h11_fourth;
const h11_close = "GET /five HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";

/// Feeds `octets` to an h11 connection as a program does. Each call passes the octets the last
/// call left, until a call takes none and reports nothing. Records the kind of each event, and
/// then what the connection sends.
fn feed_h11(record: *Record, octets: []const u8) !void {
    @memcpy(support.input[0..octets.len], octets);
    var at: usize = 0;
    for (0..h11_calls_max) |_| {
        const received = try connection.receive(support.input[at..octets.len], support.now_ns);
        at += received.consumed;
        if (received.event) |reported| {
            try record.add(&.{@intFromEnum(reported)});
        } else if (received.consumed == 0) {
            break;
        }
    }
    try record.add(support.drain());
}
/// More calls than one exchange's reads take. Test-only.
const h11_calls_max: usize = 32;

/// One h11 exchange over the connection, in cleartext. Each call answers `connection.current_id`,
/// the request the connection read last, as a program's call would.
fn run_h11_exchange(record: *Record) !void {
    try support.start_cleartext(.h11);
    try feed_h11(record, h11_get);
    try connection.respond(connection.current_id, .{ .status = ok, .end = false });
    _ = try connection.write_body(connection.current_id, .{ .octets = "hello", .end = true });
    try record.add(support.drain());
    try feed_h11(record, h11_post);
    try connection.respond(connection.current_id, .{ .status = ok, .end = false });
    _ = try connection.write_body(connection.current_id, .{ .octets = "chunked", .end = false });
    try connection.write_trailers(connection.current_id, &.{.{ .name = "x-done", .value = "1" }});
    try record.add(support.drain());
    // The second request waits unread until the first is answered, and then the program passes
    // its octets again.
    try feed_h11(record, h11_pipelined);
    try connection.respond(connection.current_id, .{ .status = ok, .end = true });
    try feed_h11(record, h11_fourth);
    try connection.respond(connection.current_id, .{ .status = ok, .end = true });
    try record.add(support.drain());
    try feed_h11(record, h11_close);
    try connection.respond(connection.current_id, .{ .status = ok, .end = true });
    try feed_h11(record, &.{});
}

test "an h11 connection sends and reports the same whatever its storage held before" {
    try expect_same_over_fills(run_h11_exchange);
}
