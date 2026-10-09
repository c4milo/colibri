//! The tests of `writable` over h3 (`endpoint_held.zig`, decision 119): a response that found no
//! room for its head, its content or its trailer section is reported `writable` once the peer's
//! acknowledgments free room for it, once for each time it found none.
const std = @import("std");
const http = @import("http");
const support = @import("../quic/quic_test_support.zig");
const server_constants = @import("../constants.zig");
const tcp_support = @import("../connection/connection_test_support.zig");

const testing = std.testing;
const endpoint_support = support.endpoint_support;
const endpoint = &endpoint_support.endpoint;

const early_hints: u16 = 103;
const ok: u16 = 200;
/// The word the test's program sets for its request.
const word: usize = 0x77;
/// A short run of content, which one DATA frame carries.
const piece = "content";
const accepts_gzip = [_]http.Field{.{ .name = "accept-encoding", .value = "gzip" }};

/// A GET the endpoint reported, with `word` set for it.
fn open_get(fields: []const http.Field) !@import("../event.zig").Id {
    try support.connect();
    const fetch = try support.request_with_fields("GET", "/", fields);
    try support.pump(support.rounds_default);
    const id = endpoint_support.id_of(fetch.id);
    try endpoint.set_user_data(id, word);
    return id;
}

/// A client datagram that acknowledges nothing reaches the connection, before any of the response
/// went out: the slot's room counter moves, every run stays held, and no `writable` comes.
fn expect_no_room() !void {
    _ = try support.request("GET", "/other", "");
    try support.deliver_unread();
    support.collect();
    try testing.expectEqual(null, support.nth(.writable, 0));
}

/// Pumps a round at a time until the endpoint reports `writable`, so the caller writes at the
/// instant it comes.
fn await_writable() !void {
    // Bounded: acknowledgments free room within a few rounds.
    for (0..rounds_max) |_| {
        if (support.nth(.writable, 0) != null) return;
        try support.pump(1);
    }
    return error.TestExpectedWritable;
}

const rounds_max: usize = 256;

/// The one `writable` the endpoint reported, which carries the request's word.
fn expect_writable_once(number: u64) !void {
    const writable = support.nth(.writable, 0) orelse return error.TestExpectedWritable;
    try testing.expectEqual(number, writable.id);
    try testing.expectEqual(word, writable.user_data);
    // Room moves again in more rounds, and no second `writable` comes without a write that
    // found none.
    try support.pump(support.rounds_default);
    try testing.expectEqual(null, support.nth(.writable, 1));
}

test "decision 119: content past a response's runs waits, and writable comes once acknowledged" {
    try support.start_endpoint(null);
    const id = try open_get(&.{});
    try endpoint.respond(id, .{ .status = ok, .end = false });
    // RFC 9000 §3.1: each DATA frame holds two runs until the client acknowledges them.
    const blocked = for (0..server_constants.quic_response_pieces_max) |_| {
        _ = endpoint.write_body(id, .{ .octets = piece, .end = false }) catch |failure| break failure;
    } else return error.TestExpectedBlocked;
    try testing.expectEqual(error.Blocked, blocked);
    // No room moved yet, so nothing is writable, and room that moves frees no run.
    support.collect();
    try testing.expectEqual(null, support.nth(.writable, 0));
    try expect_no_room();
    // The response takes content the instant `writable` comes.
    try await_writable();
    _ = try endpoint.write_body(id, .{ .octets = piece, .end = true });
    try expect_writable_once(id.number);
    try support.pump(support.rounds_default);
    try testing.expectEqual(word, support.nth(.done, 0).?.user_data);
}

test "decision 119: a head past a response's runs waits, and writable comes once acknowledged" {
    try support.start_endpoint(null);
    const id = try open_get(&.{});
    // RFC 9110 §15.2: interim responses, each a HEADERS frame the response keeps until the client
    // acknowledges it, fill every run.
    for (0..server_constants.quic_response_pieces_max) |_| {
        try endpoint.respond(id, .{ .status = early_hints, .end = false });
    }
    try testing.expectError(error.NoSpaceLeft, endpoint.respond(id, .{ .status = ok, .end = true }));
    try await_writable();
    try endpoint.respond(id, .{ .status = ok, .end = true });
    try expect_writable_once(id.number);
}

test "decision 119: trailers past a response's runs wait, and writable comes once acknowledged" {
    try support.start_endpoint(null);
    const id = try open_get(&.{});
    // RFC 9110 §15.2: interim responses and the final one fill every run but none.
    for (0..server_constants.quic_response_pieces_max - 1) |_| {
        try endpoint.respond(id, .{ .status = early_hints, .end = false });
    }
    try endpoint.respond(id, .{ .status = ok, .end = false });
    const trailer = [_]http.Field{.{ .name = "checksum", .value = "1" }};
    try testing.expectError(error.NoSpaceLeft, endpoint.write_trailers(id, &trailer));
    try expect_no_room();
    try await_writable();
    try endpoint.write_trailers(id, &trailer);
    try expect_writable_once(id.number);
}

/// The endpoint starts again, coding responses in gzip (decision 101).
fn start_coding() !void {
    try support.start_endpoint(null);
    tcp_support.fill_incompressible();
    tcp_support.pool.reset(.none());
    endpoint_support.endpoint_config.codings = &tcp_support.codings;
    endpoint_support.endpoint_config.encoders = tcp_support.pool.encoders();
    try endpoint_support.restart();
}

test "decision 101: coded content past the encoder's ring waits, and writable comes once acknowledged" {
    try start_coding();
    const id = try open_get(&accepts_gzip);
    try endpoint.respond(id, .{ .status = ok, .end = false, .codable = true });
    const content = tcp_support.incompressible[0..];
    const taken = try endpoint.write_body(id, .{ .octets = content, .end = true });
    // The ring holds less than the content, and frees none of it before acknowledgments.
    try testing.expect(taken < content.len);
    support.collect();
    try testing.expectEqual(null, support.nth(.writable, 0));
    try await_writable();
    try testing.expect(try endpoint.write_body(id, .{ .octets = content[taken..], .end = true }) > 0);
}

test "RFC 9110 §6.5: a coded response's trailers wait for its last octets, and writable says when" {
    try start_coding();
    const id = try open_get(&accepts_gzip);
    try endpoint.respond(id, .{ .status = ok, .end = false, .codable = true });
    // The content ends where the ring filled, and the encoder's last octets wait for room.
    _ = try endpoint.write_body(id, .{ .octets = tcp_support.incompressible[0..], .end = false });
    const trailer = [_]http.Field{.{ .name = "checksum", .value = "1" }};
    try testing.expectError(error.Blocked, endpoint.write_trailers(id, &trailer));
    // Acknowledgments free the ring, the encoder writes its last octets, and then the trailer
    // section has its room.
    try await_writable();
    try endpoint.write_trailers(id, &trailer);
    try expect_writable_once(id.number);
}

/// The response goes out, and the client's acknowledgment of it frees its runs before the
/// endpoint reads an event of the connection.
fn free_runs_unread() !void {
    try support.pump(1);
    try support.deliver_unread();
}

/// After a write that found room again, no `writable` comes.
fn expect_no_writable() !void {
    try support.pump(support.rounds_default);
    try testing.expectEqual(null, support.nth(.writable, 0));
}

test "decision 119: content that found room again before the next event leaves nothing to report" {
    try support.start_endpoint(null);
    const id = try open_get(&.{});
    try endpoint.respond(id, .{ .status = ok, .end = false });
    const blocked = for (0..server_constants.quic_response_pieces_max) |_| {
        _ = endpoint.write_body(id, .{ .octets = piece, .end = false }) catch |failure| break failure;
    } else return error.TestExpectedBlocked;
    try testing.expectEqual(error.Blocked, blocked);
    try free_runs_unread();
    _ = try endpoint.write_body(id, .{ .octets = piece, .end = true });
    try expect_no_writable();
}

test "decision 119: a head or trailers that found room again before the next event leave nothing to report" {
    const trailer = [_]http.Field{.{ .name = "checksum", .value = "1" }};
    for ([_]bool{ false, true }) |trailers| {
        try support.start_endpoint(null);
        const id = try open_get(&.{});
        // RFC 9110 §15.2: interim responses fill every run but the one the final head takes.
        for (0..server_constants.quic_response_pieces_max - 1) |_| {
            try endpoint.respond(id, .{ .status = early_hints, .end = false });
        }
        if (trailers) {
            try endpoint.respond(id, .{ .status = ok, .end = false });
            try testing.expectError(error.NoSpaceLeft, endpoint.write_trailers(id, &trailer));
            try free_runs_unread();
            try endpoint.write_trailers(id, &trailer);
        } else {
            try endpoint.respond(id, .{ .status = early_hints, .end = false });
            try testing.expectError(error.NoSpaceLeft, endpoint.respond(id, .{ .status = ok, .end = true }));
            try free_runs_unread();
            try endpoint.respond(id, .{ .status = ok, .end = true });
        }
        try expect_no_writable();
    }
}

test "decision 119: an answer's datagrams go out from send_datagram alone, every one in turn" {
    try support.start_endpoint(null);
    const id = try open_get(&.{});
    try endpoint.respond(id, .{ .status = ok, .end = false });
    _ = try endpoint.write_body(id, .{ .octets = &long_value, .end = true });
    // No `receive` comes between: the answer itself queued the slot to send, and a slot that
    // sent is asked again while it owes more.
    var output: [@import("quic").constants.datagram_len_max]u8 = undefined;
    var datagrams: usize = 0;
    // Bounded: the response fits a few datagrams.
    for (0..rounds_max) |_| {
        _ = endpoint.send_datagram(&output, support.now_ns) orelse break;
        datagrams += 1;
    }
    try testing.expect(datagrams > 1);
}

test "decision 119: a head larger than the room earlier heads leave waits until they are acknowledged" {
    try support.start_endpoint(null);
    const id = try open_get(&.{});
    const links = [_]http.Field{.{ .name = "link", .value = &long_value }};
    // RFC 9110 §15.2: interim responses whose fields fill most of the frames a response keeps.
    for (0..interim_heads) |_| try endpoint.respond(id, .{ .status = early_hints, .fields = &links, .end = false });
    try testing.expectError(error.NoSpaceLeft, endpoint.respond(id, .{ .status = ok, .fields = &links, .end = true }));
    // A datagram that acknowledges nothing frees no room for it, though a run is free.
    try expect_no_room();
    try await_writable();
    try endpoint.respond(id, .{ .status = ok, .fields = &links, .end = true });
    try expect_writable_once(id.number);
}

/// Interim heads, each with a field line of `long_value`, which leave less room than one more
/// head needs.
const interim_heads: usize = 2;
const long_value: [long_value_len]u8 = @splat('x');
const long_value_len: usize = 3000;
