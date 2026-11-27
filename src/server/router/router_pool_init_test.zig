//! The tests of `Router.init` (decision 158 ruling 1, https://github.com/c4milo/colibri/issues/148).
//! Each test fills a router's bytes with `filler`, as a program's memory may hold anything, then
//! starts it with `init`.
const std = @import("std");
const builtin = @import("builtin");
const router_module = @import("router.zig");
const router_call = @import("router_call.zig");

const testing = std.testing;

/// What the tests write over a router's bytes before `init`.
const filler: u8 = 0x55;

/// The entries of each router the tests start: more than one, so `init` writes past the first.
const requests = 2;
/// Each buffer of the small router: room enough that each nested field holds one.
const small_bytes = 64;
/// Each buffer of the large router: large enough that `.{}` copies its default from a constant, as
/// a program's router does.
const large_bytes = 65536;

/// A router with a header copy, so that each field `init` writes one field down holds a buffer.
const Sample = router_module.Router(void, router_call.sample_table, .{ .requests = requests, .response_bytes = small_bytes, .body_bytes = small_bytes, .header_bytes = small_bytes });
var sample: Sample align(@alignOf(Sample)) = undefined;

/// A router of large buffers. No test starts it with `.{}`, so the test binary holds no constant of
/// its default.
const Large = router_module.Router(void, router_call.sample_table, .{ .requests = requests, .response_bytes = large_bytes, .body_bytes = large_bytes, .header_bytes = large_bytes });
var large: Large align(@alignOf(Large)) = undefined;

test "decision 158 ruling 1: init frees each entry and writes each field a request reads first" {
    @memset(std.mem.asBytes(&sample), filler);
    sample.init();
    // The default value of a small router, which `.{}` copies.
    const fresh: Sample = .{};
    for (sample.entries, fresh.entries) |entry, expected| {
        try testing.expect(!entry.used);
        try testing.expectEqual(0, entry.chain_ran);
        try testing.expect(std.meta.eql(expected.request_context, entry.request_context));
        try testing.expectEqual(0, entry.body.held_len);
        try testing.expectEqual(expected.body.cursor.reader.vtable, entry.body.cursor.reader.vtable);
        try testing.expect(std.meta.eql(expected.held.writers, entry.held.writers));
        try testing.expectEqual(0, entry.header.lines.octets.len);
        try testing.expectEqual(0, entry.header.lines.lines.len);
    }
    try testing.expect(std.meta.eql(fresh.answers, sample.answers));
    try testing.expectEqual(0, sample.parameters.count);
    try testing.expectEqual(0, sample.query.parameters.count);
    try testing.expectEqual(fresh.failing_body.vtable, sample.failing_body.vtable);
}

test "decision 158 ruling 1: outside Debug, init writes no octet of an entry's buffers" {
    // Debug fills each `undefined` field with 0xaa, which shows a read of a field never written.
    if (builtin.mode == .Debug) return error.SkipZigTest;
    @memset(std.mem.asBytes(&large), filler);
    large.init();
    for (&large.entries) |*entry| {
        try expect_filled(&entry.memory);
        try expect_filled(&entry.body.held);
        try expect_filled(&entry.header.octets);
    }
    try expect_filled(&large.parameters.storage);
    try expect_filled(&large.query.storage);
    try testing.expect(!large.entries[0].used);
}

fn expect_filled(octets: []const u8) !void {
    for (octets) |octet| try testing.expectEqual(filler, octet);
}
