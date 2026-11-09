//! The test of a struct route that answers each request octet while its client still sends, over
//! h3 (decision 127 as amended, design §8 step 46): the router runs on the engine that the QUIC
//! tests drive, with an h3 client in the same process. Each reply is longer than the route's
//! response memory, so the route writes most of it from `on_writable` once the client
//! acknowledged the runs before it (RFC 9000 §3.1).
const std = @import("std");
const quic = @import("quic");
const event = @import("../event.zig");
const quic_support = @import("../quic/quic_test_support.zig");
const duplex = @import("router_duplex_test_support.zig");

const testing = std.testing;
const engine = &quic_support.engine_support.engine;

/// The request body, one octet a piece, and the octets of each reply: `memories_per_reply` times
/// the route's response memory. Test-only.
const pieces = "abc";
const memories_per_reply = 8;
const reply_len = memories_per_reply * duplex.response_bytes;
/// The rounds a test pumps for each piece at most.
const rounds_max = 128;
const ok_code: u16 = 200;

/// The router and its route's settings, which the program hook reaches. Test-only.
var router: duplex.Pool align(@alignOf(duplex.Pool)) = .{};
var app: duplex.App align(@alignOf(duplex.App)) = .{ .reply_len = reply_len };

/// Passes each event the engine reports to the router, as a program's loop does.
fn take(reported: event.Event) void {
    _ = router.handle(&app, engine, reported);
}

/// Moves datagrams both ways until the client received `target` octets, or the rounds ran out.
fn pump_until(fetch: *const quic_support.Fetch, target: usize) !void {
    // Bounded: each round moves time on and moves datagrams both ways.
    for (0..rounds_max) |_| {
        if (fetch.received_len >= target or fetch.ended) return;
        try quic_support.pump(1);
    }
}

test "decision 127 as amended: a struct route answers each octet before the body ends, over h3" {
    try quic_support.start_engine(null);
    try quic_support.connect();
    router = .{};
    app = .{ .reply_len = reply_len };
    quic_support.seen_support.program = take;
    defer quic_support.seen_support.program = null;
    // The request's DATA frame holds every piece, and the client supplies one piece at a time.
    const fetch = try quic_support.stage_request("POST", "/duplex", &.{}, pieces, &.{});
    for (1..pieces.len + 1) |count| {
        const end = fetch.prefix_len + count;
        try quic.Connection.supply(&quic_support.client, .{ .value = fetch.id }, end, count == pieces.len);
        try pump_until(fetch, count * reply_len);
        try testing.expect(duplex.is_reply(quic_support.content_of(fetch), count * reply_len));
    }
    try pump_until(fetch, std.math.maxInt(usize));
    try testing.expect(fetch.ended);
    try testing.expectEqual(ok_code, fetch.status);
    try testing.expect(app.open_calls > 0);
    // Calls that wrote nothing while the body was open waited, and cancelled nothing.
    try testing.expect(app.idle_calls > 0);
}
