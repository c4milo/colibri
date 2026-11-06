//! The tests of a streamed request body over h3 at the pool (decision 153, design §8 step 39e):
//! each piece goes out in a DATA frame of its own, its `body_taken` event comes once the server
//! acknowledged it, since QUIC sends a lost octet again by its offset (RFC 9000 §13.3), and a
//! server that needs no more of the body stops it (RFC 9114 §4.1).
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const quic_support = @import("../quic/quic_test_support.zig");
const connection_support = @import("../connection/connection_test_support.zig");
const fixture = @import("pool_quic_test_support.zig");
const pool_module = @import("pool.zig");

const testing = std.testing;
const pool = &fixture.pool;
const pump = fixture.pump;

/// Three pieces, and the whole body. Test-only.
const first = "hello";
const second = "abcdefghijklmnopqrstuvwxyz";
const third = "!";
const pieces = [_][]const u8{ first, second, third };
const whole = first ++ second ++ third;

/// A pool that speaks h3 alone, with a streamed PUT written to its server, which holds its answer.
fn start(put: *connection_support.Exchange) !pool_module.RequestId {
    var given = fixture.configured(true);
    given.protocols = .{ .h11 = false, .h2 = false };
    try fixture.start_configured(&quic_support.alpn_h3, fixture.values_at(fixture.https_port), given, fixture.receive_storage());
    quic_support.server_answers = false;
    put.* = .{ .request = .{ .method = "PUT", .path = "/object", .streamed = .{ .request = true } }, .response = .{ .body = &fixture.bodies[0] } };
    const id = try pool.request(&put.request, &put.response);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, quic_support.answers_len);
    return id;
}

fn count(tag: std.meta.Tag(pool_module.Event)) usize {
    var counted: usize = 0;
    for (fixture.events[0..fixture.events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

test "RFC 9114 §4.1: streamed pieces go out in DATA frames of their own, and the server reads the body whole" {
    var put: connection_support.Exchange = undefined;
    const id = try start(&put);
    for (pieces, 1..) |piece, handed| {
        try pool.write_body(id, piece, handed == pieces.len);
        try pump(quic_support.rounds_default);
        try testing.expectEqual(handed, count(.body_taken));
    }
    const answer = &quic_support.answers[0];
    try testing.expectEqual(whole.len, answer.received);
    try testing.expectEqual(std.hash.Crc32.hash(whole), answer.received_crc.final());
    try testing.expect(answer.ended);
    quic_support.server_answers = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, put.response.result);
    try testing.expectEqual(whole.len, put.response.body_sent);
}

test "RFC 9000 §13.3: a piece over h3 is taken once the server acknowledged it, and not once it was sent" {
    var put: connection_support.Exchange = undefined;
    const id = try start(&put);
    try pool.write_body(id, pieces[1], false);
    // The datagrams that carry the piece are lost, so the server acknowledges none of it.
    fixture.blocked = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(0, count(.body_taken));
    try testing.expectError(error.PieceHeld, pool.write_body(id, pieces[2], true));
    // QUIC sends the piece again, read from the program's memory, and the server acknowledges it.
    fixture.blocked = false;
    try pump(fixture.rounds_past_probe);
    try testing.expectEqual(1, count(.body_taken));
    try testing.expectEqual(pieces[1].len, quic_support.answers[0].received);
    try testing.expectEqual(std.hash.Crc32.hash(pieces[1]), quic_support.answers[0].received_crc.final());
}

test "RFC 9114 §4.1: a server that asks the client to stop sending ends the body, and the exchange still finishes" {
    var put: connection_support.Exchange = undefined;
    const id = try start(&put);
    try pool.write_body(id, pieces[0], false);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, count(.body_taken));
    // RFC 9114 §4.1: "The error code H3_NO_ERROR SHOULD be used when requesting that the client
    // stop sending on the request stream."
    const stream: quic.stream.StreamId = .{ .value = quic_support.answers[0].id };
    try quic.connection_stream_send.stop_sending(&quic_support.server, stream, h3.constants.protocol.error_no_error);
    try pump(quic_support.rounds_default);
    try testing.expectError(error.BodyStopped, pool.write_body(id, pieces[1], true));
    // RFC 9114 §4.1: "Clients MUST NOT discard complete responses as a result of having their
    // request terminated abruptly".
    quic_support.server_answers = true;
    quic_support.answer_early = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, put.response.result);
    try testing.expectEqual(pieces[0].len, put.response.body_sent);
}
