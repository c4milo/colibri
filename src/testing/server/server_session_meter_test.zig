//! The test of an h2 stream whose window opens slowly, in design §9's server session (decision
//! 110 as amended, decision 176): each step lends what it wrote before it reads again, so the
//! stream's send meter never waits on the output, and the engine cuts the stream at the send rate.
const std = @import("std");
const server = @import("server");
const h2 = @import("h2");
const session_module = @import("server_session.zig");
const server_mode = @import("server_mode.zig");

const testing = std.testing;
/// A session of one entry. Test-only.
const Session = session_module.Session(1);

/// The session, its configuration and its buffers, outside any stack frame. Test-only.
var test_session: Session align(@alignOf(Session)) = undefined;
var test_config: server.Config align(@alignOf(server.Config)) = .{ .cpu_features = .none() };
var test_input: [input_len]u8 = undefined;
const input_len = 256;
/// What the socket sent: each lend whole, as a socket whose sends complete at once. Test-only.
var test_sent: [sent_len_max]u8 = undefined;
var sent_len: usize = 0;
const sent_len_max = 65_536;

/// The client preface with a SETTINGS_INITIAL_WINDOW_SIZE (0x4) of 0, so a stream's window opens
/// by WINDOW_UPDATE alone (RFC 9113 §6.9.2), then the acknowledgment of the server's SETTINGS.
const preface_no_window = h2.constants.protocol.client_preface ++ "\x00\x00\x06\x04\x00\x00\x00\x00\x00" ++
    "\x00\x04\x00\x00\x00\x00" ++ "\x00\x00\x00\x04\x01\x00\x00\x00\x00";
/// A HEADERS frame on stream 1 ending it, whose block is the static table's `:method: GET`,
/// `:scheme: http` and `:path: /` (RFC 7541 §6.1, Appendix A).
const get_frame = "\x00\x00\x03\x01\x05\x00\x00\x00\x01" ++ "\x82\x86\x84";
/// A WINDOW_UPDATE of one octet on stream 1 (RFC 9113 §6.9).
const window_update = "\x00\x00\x04\x08\x00\x00\x00\x00\x01" ++ "\x00\x00\x00\x01";
/// A RST_STREAM on stream 1 with CANCEL, 0x8 (RFC 9113 §6.4, §7).
const reset_cancel = "\x00\x00\x04\x03\x00\x00\x00\x00\x01" ++ "\x00\x00\x00\x08";
/// The seconds the peer opens its window for at most: past decision 110's default grace period
/// and window, 10 s each. The answer is longer than one octet for each of them.
const seconds_max: u64 = 40;
const body_len: u32 = 1024;

/// Steps the entry over `octets` at `now_ns`. Each lend goes out whole, and the entry is stepped
/// again until it lends nothing. Test-only.
fn step_at(octets: []const u8, now_ns: u64) void {
    @memcpy(test_input[0..octets.len], octets);
    var input: []u8 = test_input[0..octets.len];
    // Bounded: each pass sends a lend, or ends the loop.
    for (0..input_len) |_| {
        input = input[test_session.step(0, input, now_ns).consumed..];
        const lent = test_session.lend(0);
        @memcpy(test_sent[sent_len..][0..lent.len], lent);
        sent_len += lent.len;
        if (lent.len == 0) return;
        test_session.sent(0, lent.len, now_ns);
    }
}

test "decision 110 as amended: an h2 stream whose window opens an octet a second is cut at the send rate" {
    server_mode.set_answer_body(body_len);
    defer server_mode.reset_answer_body();
    test_config = .{ .cpu_features = .none(), .protocols = .{ .h11 = false } };
    try test_session.init(&test_config, .{ .unix_seconds = 0, .monotonic_ns = 0 });
    try testing.expect(test_session.accept(0, false, null, 0));
    sent_len = 0;
    step_at(preface_no_window, 0);
    step_at(get_frame, 0);
    try testing.expectEqual(1, test_session.entries[0].answers.owed_count);
    for (1..seconds_max) |second| {
        const now_ns = second * server.constants.nanoseconds_per_second;
        test_session.on_instant(now_ns);
        step_at("", now_ns);
        if (test_session.entries[0].answers.owed_count == 0) break;
        step_at(window_update, now_ns);
    }
    // The engine reset the stream, and the session forgot its answer.
    try testing.expectEqual(0, test_session.entries[0].answers.owed_count);
    try testing.expect(std.mem.indexOf(u8, test_sent[0..sent_len], reset_cancel) != null);
}
