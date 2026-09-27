//! A program that links colibri's `tls` and defines `ch_assert_fail` but no `ch_rand_bytes`: the
//! other half of design §8 step 16's check. chapulin is built `RAND=extern`, so the program must
//! not link, and the linker must name the hook it lacks. tools/consumer_check.sh builds it and
//! requires that failure.
const std = @import("std");
const tls = @import("tls");

var config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var client: tls.record.Client align(@alignOf(tls.record.Client)) = undefined;

const empty_sequence = [_]u8{ 0x30, 0 };
const now_seconds: u64 = 1_800_000_000;

fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}

pub fn main() !void {
    const anchors = [_]tls.Anchor{.{ .subject = &empty_sequence, .spki = &empty_sequence }};
    try config.init(.{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "example.test" } }, .alpn = &.{"h2"} });
    try client.start(&config, now_seconds, null);
}
