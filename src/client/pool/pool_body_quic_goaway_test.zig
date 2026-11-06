//! The test of a streamed h3 PUT that a GOAWAY alone refuses after a piece was taken (decision
//! 153 ruling 3). Split from `pool_body_quic_test.zig`, which holds the other tests of streamed
//! bodies over h3 at the pool.
const std = @import("std");
const connection_support = @import("../connection/connection_test_support.zig");
const quic_support = @import("../quic/quic_test_support.zig");
const fixture = @import("pool_quic_test_support.zig");
const pool_module = @import("pool.zig");

const testing = std.testing;
const pool = &fixture.pool;
const pump = fixture.pump;

/// The first piece of the PUT's body. Test-only.
const first = "hello";

fn count(tag: std.meta.Tag(pool_module.Event)) usize {
    var counted: usize = 0;
    for (fixture.events[0..fixture.events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

test "decision 153 ruling 3: a GOAWAY at or below a taken h3 PUT's stream refuses it, and the PUT ends closed" {
    var given = fixture.configured(true);
    given.protocols = .{ .h11 = false, .h2 = false };
    try fixture.start_configured(&quic_support.alpn_h3, fixture.values_at(fixture.https_port), given, fixture.receive_storage());
    quic_support.server_answers = false;
    var put: connection_support.Exchange = .{ .request = .{ .method = "PUT", .path = "/object", .streamed = .{ .request = true } }, .response = .{ .body = &fixture.bodies[0] } };
    const put_id = try pool.request(&put.request, &put.response);
    var get = fixture.get(&fixture.bodies[1]);
    const get_id = try pool.request(&get.request, &get.response);
    try pool.write_body(put_id, first, false);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, count(.body_taken));
    pool.cancel(get_id, quic_support.now_ns);
    // RFC 9114 §5.2: "Requests or pushes with the indicated identifier or greater are rejected".
    // The server's GOAWAY names the PUT's own stream and resets no stream. `shutdown` sends the
    // lowest identifier it sent before, so the test names that identifier first.
    const put_stream = quic_support.answers[0].id;
    quic_support.server_h3.goaway_sent = put_stream;
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try testing.expectEqual(put_stream, quic_support.server_h3.goaway_sent.?);
    pool.shutdown();
    // RFC 9114 §5.2: the client cancels the refused stream, so the PUT finishes within a few
    // rounds and not at the idle timeout (RFC 9000 §10.1).
    for (0..quic_support.rounds_default) |_| {
        if (count(.finished) > 0) break;
        try pump(1);
    }
    try testing.expectEqual(1, count(.finished));
    try pump(fixture.rounds_past_probe);
    // Decision 153 ruling 3: a piece of the PUT was taken, so the refused PUT does not move to
    // TCP and ends closed. The cancelled GET has no event.
    try testing.expectEqual(1, count(.finished));
    try testing.expectEqual(put_id, fixture.nth(.finished, 0).?.finished.id);
    try testing.expectEqual(.closed, put.response.result);
    try testing.expectEqual(1, count(.open));
    try testing.expectEqual(pool_module.Transport.quic, fixture.opened(0).?.transport);
    try testing.expectEqual(1, count(.close));
}
