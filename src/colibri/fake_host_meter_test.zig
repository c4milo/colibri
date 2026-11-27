//! The test of an h2 stream whose window opens slowly under a `.hosted` `colibri.Server`, on a
//! fake host (decision 110 as amended, decision 176). A connection's `send` gives its socket the
//! bytes the engine lends at once, before the engine reads the connection again. So the stream's
//! send meter never waits on the output, and the engine cuts the stream at the send rate.
const std = @import("std");
const server = @import("server");
const support = @import("test_support.zig");
const host_support = @import("fake_host_send_test_support.zig");

const testing = std.testing;
const in_flight = &host_support.in_flight;

/// The client's preface (RFC 9113 §3.4), with a SETTINGS_INITIAL_WINDOW_SIZE (0x4) of 0, so a
/// stream's window opens by WINDOW_UPDATE alone (§6.9.2), then the acknowledgment of the server's
/// SETTINGS.
const preface_no_window = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" ++ "\x00\x00\x06\x04\x00\x00\x00\x00\x00" ++
    "\x00\x04\x00\x00\x00\x00" ++ "\x00\x00\x00\x04\x01\x00\x00\x00\x00";
/// A HEADERS frame on stream 1 ending it: `:method: GET` and `:scheme: http` from the static
/// table, and `:path: /stream` as a literal on the static name 4 (RFC 7541 §6.1, §6.2.1).
const get_stream = "\x00\x00\x0b\x01\x05\x00\x00\x00\x01" ++ "\x82\x86\x44\x07/stream";
/// A WINDOW_UPDATE of one byte on stream 1 (RFC 9113 §6.9).
const window_update = "\x00\x00\x04\x08\x00\x00\x00\x00\x01" ++ "\x00\x00\x00\x01";
/// A RST_STREAM on stream 1 with CANCEL, 0x8 (RFC 9113 §6.4, §7).
const reset_cancel = "\x00\x00\x04\x03\x00\x00\x00\x00\x01" ++ "\x00\x00\x00\x08";
/// The seconds the peer opens its window for at most: past decision 110's default grace period
/// and window, 10 s each. `/stream` holds more than a byte for each.
const seconds_max: u64 = 40;

/// What the server sent, in order. Test-only.
var sent: [sent_len_max]u8 = undefined;
var sent_len: usize = 0;
const sent_len_max = 65_536;

/// Gives the receive in flight `octets`, then turns at the support's instant, each send in flight
/// taking all it was given, until no send is in flight after a turn. Test-only.
fn exchange(octets: []const u8) !void {
    const receive = in_flight.find(.receive) orelse return error.OperationMissing;
    @memcpy(receive.kind.receive.buffer[0..octets.len], octets);
    in_flight.complete(receive.id, .{ .received = @intCast(octets.len) });
    // Bounded: each turn sends what the engine lent, or ends the loop.
    for (0..host_support.turns_max) |_| {
        _ = host_support.turn(host_support.operations_len);
        const send = in_flight.find(.send) orelse return;
        const bytes = send.kind.send.bytes;
        @memcpy(sent[sent_len..][0..bytes.len], bytes);
        sent_len += bytes.len;
        in_flight.complete(send.id, .{ .sent = @intCast(bytes.len) });
    }
    return error.TestUnexpectedResult;
}

test "decision 110 as amended: under a hosted server an h2 stream whose window opens an octet a second is cut" {
    var counter: support.Counter = .{};
    try host_support.start(&counter, .{ .h11 = false });
    sent_len = 0;
    _ = host_support.turn(host_support.operations_len);
    try exchange(preface_no_window);
    try exchange(get_stream);
    for (1..seconds_max) |second| {
        host_support.now_ns = second * server.constants.nanoseconds_per_second;
        try exchange(window_update);
        if (std.mem.indexOf(u8, sent[0..sent_len], reset_cancel) != null) return host_support.stop();
    }
    return error.TestUnexpectedResult;
}
