//! A program that runs `colibri.tls` and declares no chapulin hook. chapulin's module defines
//! `ch_assert_fail`, so the program links (decision 172). tools/consumer_check.sh builds it, and
//! never runs it.
const std = @import("std");
const tls = @import("colibri").tls;

var config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var client: tls.record.Client align(@alignOf(tls.record.Client)) = undefined;

const empty_sequence = [_]u8{ 0x30, 0 };
const now_seconds: u64 = 1_800_000_000;

/// A source the program never draws from, because no check runs it.
var source_state: u8 = 0;
const source: std.Random = .{ .ptr = &source_state, .fillFn = fill_source };

fn fill_source(_: *anyopaque, buffer: []u8) void {
    _ = buffer;
    @panic("a program no check runs draws nothing");
}

pub fn main() !void {
    const anchors = [_]tls.Anchor{.{ .subject = &empty_sequence, .spki = &empty_sequence }};
    try config.init(.{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "example.test" } }, .alpn = &.{"h2"}, .cpu = .{ .probe = .{ .aes_clmul = .no, .dit = .not_known, .sha256 = .no, .sha512 = .no, .sha3 = .no, .sve2 = .no, .ssse3 = .no, .sse4_1 = .no, .avx2 = .no, .vaes = .no, .midr = null }, .timing = .not_stated } });
    try client.start(&config, source, now_seconds, null);
}
