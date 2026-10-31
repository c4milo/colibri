//! The vectors of `spec/lean/Colibri/Quic/BbrStates.lean`: the draws of each probe wait and the
//! volumes BBRv3's states compare with the octets in flight (design §8 step 29b.2).
const std = @import("std");
const testing = std.testing;
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_inflight = @import("recovery_bbr_inflight.zig");
const recovery_bbr_wait = @import("recovery_bbr_wait.zig");
const recovery_delivery = @import("../recovery_delivery.zig");

const Bbr = recovery_bbr.Bbr;

const test_start_ns: u64 = 1_000_000_000;
const test_initial_window_len: u64 = 12_000;

const Tokens = std.mem.TokenIterator(u8, .scalar);
const decimal: u8 = 10;

fn field(fields: *Tokens) !u64 {
    return std.fmt.parseUnsigned(u64, fields.next() orelse return error.TestVectorShort, decimal);
}

/// A path whose maximum datagram is `datagram_len`, for the volumes alone. Test-only.
fn test_path(datagram_len: u64) recovery_bbr.Path {
    return .{
        .now_ns = test_start_ns,
        .in_flight_len = 0,
        .delivered_len = 0,
        .window_limited = false,
        .in_recovery = false,
        .datagram_len = datagram_len,
        .initial_window_len = test_initial_window_len,
        .send_quantum_len = 0,
    };
}

fn expect_draw_line(fields: *Tokens) !void {
    const drawn = recovery_bbr_wait.draw(try field(fields), try field(fields));
    try testing.expectEqual(try field(fields), drawn.rounds_start);
    try testing.expectEqual(try field(fields), drawn.wait_ns);
}

fn expect_headroom_line(fields: *Tokens) !void {
    var state: Bbr = undefined;
    state.init(test_start_ns, test_initial_window_len, 0);
    state.inflight_longterm_len = try field(fields);
    const path = test_path(try field(fields));
    try testing.expectEqual(try field(fields), recovery_bbr_inflight.inflight_with_headroom(&state, path));
}

fn expect_too_high_line(fields: *Tokens) !void {
    var sample: recovery_delivery.Sample = std.mem.zeroes(recovery_delivery.Sample);
    sample.lost_len = try field(fields);
    sample.tx_in_flight_len = try field(fields);
    const answer = fields.next() orelse return error.TestVectorShort;
    try testing.expectEqual(std.mem.eql(u8, answer, "true"), recovery_bbr_inflight.is_inflight_too_high(sample));
}

fn expect_bdp_line(fields: *Tokens) !void {
    var state: Bbr = undefined;
    state.init(test_start_ns, test_initial_window_len, 0);
    const bw = try field(fields);
    state.model.min_rtt_ns = try field(fields);
    const gain = try field(fields);
    try testing.expectEqual(try field(fields), recovery_bbr_inflight.bdp_multiple(&state, test_path(1), bw, gain));
}

test "spec/lean/Colibri/Quic/BbrStates.lean: the draws and volumes give the proved definitions' answers" {
    var lines = std.mem.splitScalar(u8, @embedFile("bbr_states_vectors.txt"), '\n');
    var checked: usize = 0;
    // Bounded: the embedded file has a fixed number of lines.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = fields.next().?;
        if (std.mem.eql(u8, kind, "draw")) {
            try expect_draw_line(&fields);
        } else if (std.mem.eql(u8, kind, "headroom")) {
            try expect_headroom_line(&fields);
        } else if (std.mem.eql(u8, kind, "toohigh")) {
            try expect_too_high_line(&fields);
        } else if (std.mem.eql(u8, kind, "bdp")) {
            try expect_bdp_line(&fields);
        } else {
            return error.TestVectorKind;
        }
        try testing.expectEqual(null, fields.next());
        checked += 1;
    }
    try testing.expectEqual(142, checked);
}
