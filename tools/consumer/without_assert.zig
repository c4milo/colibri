//! A program that links colibri's `tls` and defines no `ch_assert_fail`, chapulin's one hook: the
//! other half of design §8 step 16's check. The program must not link, and the linker must name the
//! hook it lacks. tools/consumer_check.sh builds it and requires that failure.
const std = @import("std");
const tls = @import("tls");

var config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var client: tls.record.Client align(@alignOf(tls.record.Client)) = undefined;

const empty_sequence = [_]u8{ 0x30, 0 };
const now_seconds: u64 = 1_800_000_000;

/// A source the program never draws from, because it never links.
var source_state: u8 = 0;
const source: std.Random = .{ .ptr = &source_state, .fillFn = fill_source };

fn fill_source(_: *anyopaque, buffer: []u8) void {
    _ = buffer;
    @panic("a program that does not link draws nothing");
}

pub fn main() !void {
    const anchors = [_]tls.Anchor{.{ .subject = &empty_sequence, .spki = &empty_sequence }};
    try config.init(.{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "example.test" } }, .alpn = &.{"h2"} });
    try client.start(&config, source, now_seconds, null);
}
