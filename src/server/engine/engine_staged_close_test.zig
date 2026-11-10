//! The tests of the staged close in the engine's TCP slots (decision 160, RFC 9112 §9.6): an h11
//! response written before a request body that does not fit `discard_len_max` goes out whole,
//! then `half_close`, then the engine discards what the peer sends, and reports `close` once
//! `half_close_ns` has passed, unless the peer closes first.
const std = @import("std");
const http = @import("http");
const tls_provider = @import("tls_provider");
const server_constants = @import("../constants.zig");
const support = @import("engine_tcp_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");

const testing = std.testing;
const engine = &support.engine;

/// RFC 9110 §15.5.6: 405 (Method Not Allowed), as a router answers a method a route lacks.
const method_not_allowed: http.Status = .method_not_allowed;

/// The head of a POST whose body is one octet past the bound, so the server closes in stages.
const past_bound_head = std.fmt.comptimePrint("POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: {d}\r\n\r\n", .{server_constants.limits.discard_len_max + 1});

/// Octets of the body the client keeps sending while it waits for the answer.
const body_part_len: usize = 4096;
const body_part: [body_part_len]u8 = @splat('x');

/// Reads the head of `past_bound_head` from the connection `handle` names, and answers it 405
/// before its body.
fn answer_early(handle: anytype, sealed: bool) !void {
    if (sealed) _ = try support.give_sealed(handle, past_bound_head) else _ = support.give(handle, past_bound_head);
    const request = support.nth(.request, 0).?;
    try engine.respond(support.id_of(handle, request.number), .{ .status = method_not_allowed, .end = true });
    support.collect();
}

test "decision 160: a body past the bound gets the 405 whole, then half_close, then close after half_close_ns" {
    try support.start(null, .{});
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    try answer_early(handle, false);
    // RFC 9112 §9.6: the response goes out whole before the write side closes.
    try testing.expect(std.mem.startsWith(u8, support.sent_of(handle.slot), "HTTP/1.1 405 Method Not Allowed\r\n"));
    try testing.expect(std.mem.endsWith(u8, support.sent_of(handle.slot), "\r\n\r\n"));
    // RFC 9110 §10.1.1: the Content-Length is past the bound, so the 405 says that the server closes.
    try testing.expect(std.mem.indexOf(u8, support.sent_of(handle.slot), "\r\nConnection: close\r\n") != null);
    try testing.expect(support.index_of(.send).? < support.index_of(.half_close).?);
    try testing.expectEqual(null, support.nth(.close, 0));
    const end_ns = support.instant_ns + server_constants.limits.half_close_ns;
    try testing.expectEqual(end_ns, engine.deadline_ns().?);
    // The client keeps writing while it reads the answer, and the engine discards what it sends.
    const sent_len = support.sent_of(handle.slot).len;
    try testing.expectEqual(0, support.give(handle, &body_part));
    try testing.expectEqual(sent_len, support.sent_of(handle.slot).len);
    support.instant_ns = end_ns - 1;
    engine.on_instant(support.instant_ns);
    support.collect();
    try testing.expectEqual(null, support.nth(.close, 0));
    // The client never closes, so the engine closes at the bound.
    support.instant_ns = end_ns;
    engine.on_instant(support.instant_ns);
    support.collect();
    try testing.expect(support.index_of(.half_close).? < support.index_of(.close).?);
    try testing.expect(support.index_of(.close).? < support.index_of(.ended).?);
    const ended = support.nth(.ended, 0).?;
    try testing.expect(!ended.failed);
    try testing.expectEqual(1, count_of(.half_close));
}

test "decision 160: a peer that closes after half_close ends the connection, with no close" {
    try support.start(null, .{});
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    try answer_early(handle, false);
    try testing.expect(support.nth(.half_close, 0) != null);
    engine.transport_closed(handle);
    support.collect();
    try testing.expectEqual(null, support.nth(.close, 0));
    try testing.expect(!support.nth(.ended, 0).?.failed);
}

test "decision 160: a chunked body that passes the bound gets the staged close" {
    try support.start(null, .{});
    const handle = engine.accept(.{ .tls = false }, support.now_ns).?;
    // A chunk of 1 MiB, longer than the bound.
    _ = support.give(handle, "POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\n");
    const request = support.nth(.request, 0).?;
    try engine.respond(support.id_of(handle, request.number), .{ .status = method_not_allowed, .end = true });
    support.collect();
    // The rest of the body is discarded until it passes the bound.
    const parts = server_constants.limits.discard_len_max / body_part.len + 1;
    for (0..parts) |_| _ = support.give(handle, &body_part);
    try testing.expect(support.nth(.half_close, 0) != null);
    try testing.expectEqual(null, support.nth(.close, 0));
}

test "decision 160: over TLS, the close_notify goes out before half_close, and records after it are discarded" {
    try support.start(support.identity(), .{});
    const handle = engine.accept(.{}, support.now_ns).?;
    try support.start_client(&tcp_support.protocols_h11);
    try testing.expect(try support.handshake(handle));
    try answer_early(handle, true);
    const opened = try support.open_sent(handle.slot);
    try testing.expect(std.mem.startsWith(u8, opened, "HTTP/1.1 405 Method Not Allowed\r\n"));
    // RFC 9846 §6.1: the close_notify closes this side's write direction first.
    try testing.expect(support.client_saw_alert);
    try testing.expect(support.nth(.half_close, 0) != null);
    try testing.expectEqual(0, try support.give_sealed(handle, &body_part));
    try testing.expectEqual(null, support.nth(.close, 0));
    support.instant_ns += server_constants.limits.half_close_ns;
    engine.on_instant(support.instant_ns);
    support.collect();
    try testing.expect(support.nth(.close, 0) != null);
}

/// Takes the sealed response into room that holds its one record and no close_notify after it,
/// and requires the engine to owe no `half_close` yet (RFC 9846 §6.1).
fn take_response_alone(handle: anytype) !void {
    const slot = handle.slot;
    const record_len = engine.tcp[slot].output_len + record_overhead_len;
    const room = support.sent[slot][support.sent_len[slot]..][0..record_len];
    try testing.expectEqual(record_len, engine.send_stream(handle, room, support.instant_ns));
    support.sent_len[slot] += record_len;
    support.collect();
    try testing.expectEqual(null, support.nth(.half_close, 0));
}

/// The octets a TLS 1.3 record adds to its plaintext: its header, its content type and its AEAD
/// tag, 16 octets for each suite colibri offers (RFC 9846 §5.2).
const record_overhead_len: usize = tls_provider.constants.protocol.record_header_len + content_type_len + aead_tag_len;
const content_type_len: usize = 1;
const aead_tag_len: usize = 16;

/// How many events of `kind` the engine reported.
fn count_of(kind: support.Kind) usize {
    var count: usize = 0;
    for (support.seen[0..support.seen_len]) |entry| count += @intFromBool(entry.kind == kind);
    return count;
}

test "decision 160: half_close waits until the program took the response, and over TLS the close_notify" {
    for ([_]bool{ false, true }) |sealed| {
        try support.start(if (sealed) support.identity() else null, .{});
        const handle = engine.accept(.{ .tls = sealed }, support.now_ns).?;
        if (sealed) {
            try support.start_client(&tcp_support.protocols_h11);
            try testing.expect(try support.handshake(handle));
        }
        // The program does not take the octets at its `send`, as one whose socket is full.
        support.flushing = false;
        try answer_early(handle, sealed);
        try testing.expectEqual(null, support.nth(.half_close, 0));
        if (sealed) try take_response_alone(handle);
        support.flush(handle);
        support.collect();
        try testing.expect(support.nth(.half_close, 0) != null);
        if (sealed) {
            _ = try support.open_sent(handle.slot);
            // RFC 9846 §6.1: the close_notify went out before the write side closed.
            try testing.expect(support.client_saw_alert);
        }
    }
}

test "decision 160: over TLS, records past the plaintext buffer are discarded after half_close" {
    try support.start(support.identity(), .{});
    const handle = engine.accept(.{}, support.now_ns).?;
    try support.start_client(&tcp_support.protocols_h11);
    try testing.expect(try support.handshake(handle));
    try answer_early(handle, true);
    try testing.expect(support.nth(.half_close, 0) != null);
    const parts = server_constants.limits.plaintext_in_len / body_part_len + 1;
    for (0..parts) |_| try testing.expectEqual(0, try support.give_sealed(handle, &body_part));
    try testing.expectEqual(null, support.nth(.close, 0));
}
