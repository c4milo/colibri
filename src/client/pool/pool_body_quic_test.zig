//! The tests of streamed bodies over h3 at the pool (decision 153, design §8 steps 39e and 39f).
//! Each request piece goes out in a DATA frame of its own, its `body_taken` event comes once the
//! server acknowledged it, since QUIC sends a lost octet again by its offset (RFC 9000 §13.3), and
//! a server that needs no more of the body stops it (RFC 9114 §4.1). Each response piece stays in
//! QUIC, which gives the server no credit for it until the program releases it (RFC 9000 §4.1).
//! A request body goes on after the response's head (design §8 step 39g).
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const quic_support = @import("../quic/quic_test_support.zig");
const connection_support = @import("../connection/connection_test_support.zig");
const fixture = @import("pool_quic_test_support.zig");
const pool_module = @import("pool.zig");
const event = @import("../event.zig");

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
    return start_streamed(put, .{ .request = true });
}

/// As `start`, with the bodies `streamed` names going in pieces.
fn start_streamed(put: *connection_support.Exchange, streamed: event.Streamed) !pool_module.RequestId {
    var given = fixture.configured(true);
    given.protocols = .{ .h11 = false, .h2 = false };
    try fixture.start_configured(&quic_support.alpn_h3, fixture.values_at(fixture.https_port), given, fixture.receive_storage());
    quic_support.server_answers = false;
    put.* = .{ .request = .{ .method = "PUT", .path = "/object", .streamed = streamed }, .response = .{ .body = &fixture.bodies[0] } };
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

test "RFC 9000 §13.3: a piece handed at the last one's `body_taken` waits for its own acknowledgment" {
    var put: connection_support.Exchange = undefined;
    const id = try start(&put);
    try pool.write_body(id, pieces[0], false);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, count(.body_taken));
    // The program hands the next piece as it reads the event, and calls `receive` again before
    // the piece goes out: the server acknowledged every octet the stream holds so far.
    try pool.write_body(id, pieces[1], false);
    const received = pool.receive(.none, quic_support.now_ns);
    try testing.expectEqual(null, received.event);
    try testing.expectError(error.PieceHeld, pool.write_body(id, pieces[2], true));
    try pump(quic_support.rounds_default);
    try testing.expectEqual(2, count(.body_taken));
    try testing.expectEqual(pieces[0].len + pieces[1].len, quic_support.answers[0].received);
}

test "RFC 9000 §3.5: a piece handed before the server stopped the body is taken once QUIC reset the stream" {
    var put: connection_support.Exchange = undefined;
    const id = try start(&put);
    try pool.write_body(id, pieces[0], false);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, count(.body_taken));
    const stream: quic.stream.StreamId = .{ .value = quic_support.answers[0].id };
    try quic.connection_stream_send.stop_sending(&quic_support.server, stream, h3.constants.protocol.error_no_error);
    // The program hands the next piece, and the STOP_SENDING arrives before the piece goes out.
    try pool.write_body(id, pieces[1], false);
    const len = (try quic_support.server_send(&fixture.datagram)).?;
    @memcpy(fixture.crossing[0..len], fixture.datagram[0..len]);
    try fixture.deliver(fixture.crossing[0..len]);
    // QUIC reset the stream's sending part (RFC 9000 §3.5), so it reads none of the piece.
    try fixture.collect();
    try testing.expectEqual(2, count(.body_taken));
    try testing.expectError(error.BodyStopped, pool.write_body(id, pieces[2], true));
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

test "RFC 9114 §4.1.1: a response that ends before the request body resets the request stream, and the exchange finishes" {
    var put: connection_support.Exchange = undefined;
    const id = try start(&put);
    try pool.write_body(id, pieces[0], false);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, count(.body_taken));
    // The server answers whole while the request body is still open, so the stream's sending part
    // would stay open without the client's reset.
    quic_support.server_answers = true;
    quic_support.answer_early = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, count(.finished));
    try testing.expectEqual(.response, put.response.result);
    try testing.expectError(error.UnknownRequest, pool.write_body(id, pieces[1], true));
}

/// A receive pool smaller than the response, so the stream's window holds the server back
/// (decision 61). Test-only.
var small_pool: quic.stream.stream_incoming.Pool(small_pool_len) align(@alignOf(quic.stream.stream_incoming.Pool(small_pool_len))) = undefined;
const small_pool_len: usize = 65_536;
/// The response's content, and where each of its pieces lands: one h3 read's worth (decision 80).
var content: [content_len]u8 = undefined;
const content_len: usize = 163_840;
var response_piece: [response_piece_len]u8 = undefined;
const response_piece_len: usize = 16_384;

/// What the pieces of the response added up to, and how many there were. Test-only.
const Read = struct {
    crc: std.hash.Crc32 = .init(),
    len: usize = 0,
    pieces: usize = 0,
    finished: bool = false,
};

/// Keeps and releases the piece each new `body` event since event `from` reported into `body`,
/// and notes the exchange's end. A piece is released before the next comes, and before the
/// exchange finishes.
fn read_new(id: pool_module.RequestId, body: []const u8, from: usize, read: *Read) !void {
    var held = false;
    for (fixture.events[from..fixture.events_len]) |reported| {
        switch (reported) {
            .body => |piece| {
                // Decision 153 ruling 7: no piece comes while one is held, nor the end.
                try testing.expect(!held);
                try testing.expectEqual(id, piece.id);
                read.crc.update(body[0..piece.len]);
                read.len += piece.len;
                read.pieces += 1;
                held = true;
            },
            .finished => {
                try testing.expect(!held);
                read.finished = true;
            },
            else => {},
        }
    }
    if (held) pool.release_body(id);
}

test "RFC 9000 §4.1: a server faster than the program waits for the stream's credit, which comes back as each piece is released" {
    for (&content, 0..) |*octet, index| octet.* = @truncate(index);
    var given = fixture.configured(true);
    given.protocols = .{ .h11 = false, .h2 = false };
    try fixture.start_configured(&quic_support.alpn_h3, fixture.values_at(fixture.https_port), given, small_pool.storage());
    quic_support.answer_content = &content;
    var get: connection_support.Exchange = .{ .request = .{ .method = "GET", .path = "/stream", .streamed = .{ .response = true } }, .response = .{ .body = &response_piece } };
    const id = try pool.request(&get.request, &get.response);
    const read_body: []const u8 = &response_piece;
    try pump(fixture.rounds_past_probe);
    try testing.expectEqual(1, count(.headers));
    try testing.expectEqual(1, count(.body));
    // RFC 9000 §4.1: the server gets no more credit while the program holds the piece. QUIC
    // measures both limits from what it consumed, so the server spent the connection's window,
    // which its control stream shares, and the stream's limit did not move.
    const server = &quic_support.server;
    const stream = server.streams.lookup(.{ .value = quic_support.answers[0].id }).live;
    try testing.expectEqual(small_pool_len, stream.send_flow.limit);
    try testing.expectEqual(small_pool_len, server.send_flow.limit);
    try testing.expectEqual(server.send_flow.limit, server.send_flow.used);
    var read: Read = .{};
    try read_new(id, read_body, 0, &read);
    // The next piece is in QUIC already, so the release reports it with no datagram.
    var from = fixture.events_len;
    try fixture.collect();
    try testing.expectEqual(2, count(.body));
    for (0..rounds_max) |_| {
        const seen = fixture.events_len;
        try read_new(id, read_body, from, &read);
        from = seen;
        if (read.finished) break;
        try pump(1);
    }
    try testing.expect(read.finished);
    try testing.expect(read.pieces >= content_len / response_piece_len);
    try testing.expectEqual(content_len, read.len);
    try testing.expectEqual(std.hash.Crc32.hash(&content), read.crc.final());
    try testing.expectEqual(.response, get.response.result);
}

/// Rounds of releasing a piece and moving datagrams that the test of flow control takes at most.
const rounds_max: usize = 256;

test "decision 153 ruling 7: a cancel gives back the request piece and the response piece at once" {
    var exchange: connection_support.Exchange = undefined;
    const id = try start_streamed(&exchange, .{ .request = true, .response = true });
    // The server answers at the head, and leaves the response open.
    quic_support.server_answers = true;
    quic_support.answer_early = true;
    quic_support.answer_open = true;
    try pool.write_body(id, pieces[0], false);
    fixture.blocked = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, count(.body));
    try testing.expectEqual(0, count(.body_taken));
    pool.cancel(id, quic_support.now_ns);
    fixture.blocked = false;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(0, count(.body_taken));
    try testing.expectEqual(0, count(.finished));
    try testing.expectError(error.UnknownRequest, pool.write_body(id, pieces[1], true));
}

test "RFC 9114 §4.1: over h3 a request body goes on after the response's head, and both bodies arrive whole" {
    var exchange: connection_support.Exchange = undefined;
    const id = try start_streamed(&exchange, .{ .request = true, .response = true });
    const read_body: []const u8 = exchange.response.body;
    // The server answers at the request's head, before its content, and leaves its stream open.
    quic_support.server_answers = true;
    quic_support.answer_early = true;
    quic_support.answer_open = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, count(.headers));
    var read: Read = .{};
    try read_new(id, read_body, 0, &read);
    var from = fixture.events_len;
    for (pieces, 1..) |handed_piece, handed| {
        try pool.write_body(id, handed_piece, handed == pieces.len);
        try pump(quic_support.rounds_default);
        try testing.expectEqual(handed, count(.body_taken));
    }
    const answer = &quic_support.answers[0];
    try testing.expectEqual(whole.len, answer.received);
    try testing.expectEqual(std.hash.Crc32.hash(whole), answer.received_crc.final());
    // The server ends its response once it read the request whole.
    try quic.connection_stream_send.supply(&quic_support.server, .{ .value = answer.id }, answer.prefix_len + answer.content.len, true);
    for (0..rounds_max) |_| {
        const seen = fixture.events_len;
        try read_new(id, read_body, from, &read);
        from = seen;
        if (read.finished) break;
        try pump(1);
    }
    try testing.expect(read.finished);
    try testing.expectEqual(std.hash.Crc32.hash(quic_support.answer_content), read.crc.final());
    try testing.expectEqual(.response, exchange.response.result);
    try testing.expectEqual(whole.len, exchange.response.body_sent);
}

/// The most `receive` calls in a row that report an event and take no octet, for the fixture's
/// pool. Test-only.
const events_bound = pool_module.ConnectionPool.receive_events_without_input_max(.{});
/// Where each piece of the test of the event bound lands, and the content it reads: more pieces
/// than the bound, all in QUIC before the first release. Test-only.
var small_piece: [small_piece_len]u8 = undefined;
const small_piece_len: usize = 16;
var bound_content: [(events_bound + 1) * small_piece_len]u8 = undefined;

/// Releases the piece of exchange `id`, then reads with no input until the next piece or the end.
/// Returns that event, and requires the run of calls to stay within `events_bound`.
fn next_after_release(id: pool_module.RequestId) !pool_module.Event {
    pool.release_body(id);
    for (0..events_bound) |_| {
        const received = pool.receive(.none, quic_support.now_ns);
        try testing.expectEqual(0, received.consumed);
        const reported = received.event orelse return error.TestUnexpectedResult;
        if (reported == .body or reported == .finished) return reported;
    }
    return error.TestUnexpectedResult;
}

test "decision 153 ruling 7: each release starts a new run of the receive calls that take no input" {
    for (&bound_content, 0..) |*octet, index| octet.* = @truncate(index);
    var given = fixture.configured(true);
    given.protocols = .{ .h11 = false, .h2 = false };
    try fixture.start_configured(&quic_support.alpn_h3, fixture.values_at(fixture.https_port), given, fixture.receive_storage());
    quic_support.answer_content = &bound_content;
    var get: connection_support.Exchange = .{ .request = .{ .method = "GET", .path = "/stream", .streamed = .{ .response = true } }, .response = .{ .body = &small_piece } };
    const id = try pool.request(&get.request, &get.response);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, count(.body));
    var crc: std.hash.Crc32 = .init();
    crc.update(&small_piece);
    var pieces_read: usize = 1;
    // Every piece after the first comes from QUIC with no datagram, one run after each release.
    for (0..bound_content.len) |_| {
        const reported = try next_after_release(id);
        if (reported == .finished) break;
        crc.update(small_piece[0..reported.body.len]);
        pieces_read += 1;
    }
    try testing.expect(pieces_read > events_bound);
    try testing.expectEqual(std.hash.Crc32.hash(&bound_content), crc.final());
    try testing.expectEqual(.response, get.response.result);
}
