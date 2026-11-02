//! The tests of the time of h11's drop through the pool (decision 146): `cancel` starts it,
//! `deadline_ns` names its end, and `on_instant` fails the connection when it runs out.
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const pool_module = @import("pool.zig");
const pool_support = @import("pool_test_support.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const Exchange = support.Exchange;
const Event = pool_module.Event;

/// The pool's configuration and the events it reported, outside any stack frame. Test-only.
var config: pool_module.Config align(@alignOf(pool_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 64;

/// RFC 9110 §4.2.1: the port of an "http" origin whose URI names none.
const http_port: u16 = 80;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]pool_module.Address{pool_module.Address.of(&loopback, 0)};
/// A drop limit no default has, so a test sees that `Config.timeouts` reaches the connection.
const drop_ns: u64 = 7;

fn get(body: []u8) Exchange {
    return .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = body } };
}

fn count(tag: std.meta.Tag(Event)) usize {
    var counted: usize = 0;
    for (events[0..events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

/// Reads the pool until it reports nothing, and starts the connection an `open` event asks for.
fn collect(pool: anytype) !void {
    // Bounded: each pass reports an event, and a test's events are few.
    for (0..support.events_max) |_| {
        const reported = pool.receive(.none, support.now_ns).event orelse return;
        if (events_len == events.len) return error.TestUnexpectedResult;
        events[events_len] = reported;
        events_len += 1;
        if (reported == .open) try pool.start_tcp(pool_support.connection_of(pool, .tcp), support.stream.random(), 0, null);
    }
    return error.TestUnexpectedResult;
}

test {
    inline for (pool_support.pools) |Pool| _ = Tests(Pool);
}

fn Tests(comptime Pool: type) type {
    return struct {
        var pool: Pool align(@alignOf(Pool)) = undefined;
        var pool_memory: [Pool.memory_bytes(.{})]u8 align(Pool.memory_alignment) = undefined;

        test "decision 146: the pool names the end of an h11 drop, and fails its connection there" {
            config = .{
                .authority = support.authority,
                .protocols = pool_support.versions_for(&pool, support.only(.h11)),
                .timeouts = .{ .drop_ns = drop_ns },
            };
            try pool.init(&pool_memory, &config, .{ .addresses = &addresses, .port = http_port }, null);
            events_len = 0;
            var exchange = get(&bodies[0]);
            const id = try pool.request(&exchange.request, &exchange.response);
            try collect(&pool);
            try testing.expectEqual(1, count(.connected));
            var output: [1024]u8 = undefined;
            try testing.expect(pool.send_stream(pool_support.connection_of(pool, .tcp), &output, support.now_ns) > 0);
            try testing.expectEqual(null, pool.deadline_ns());
            pool.cancel(id, support.now_ns);
            try testing.expectEqual(support.now_ns + drop_ns, pool.deadline_ns().?);
            pool.on_instant(support.now_ns + drop_ns - 1);
            try collect(&pool);
            try testing.expectEqual(0, count(.close));
            pool.on_instant(support.now_ns + drop_ns);
            try collect(&pool);
            try testing.expectEqual(1, count(.close));
            try testing.expectEqual(null, pool.deadline_ns());
        }
    };
}
