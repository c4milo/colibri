//! The tests of content codings over h3 (`quic_coding.zig`, decision 101): a coded response goes
//! out from its encoder's ring in place, the ring frees what the peer acknowledged, and the
//! response ends once the encoder has finished. Its encoder goes back once the peer acknowledged
//! every octet, or once the response is cancelled.
const std = @import("std");
const quic = @import("quic");
const support = @import("quic_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const server_constants = @import("../constants.zig");

const testing = std.testing;
const connection = &support.connection;
const Field = support.Field;

const early_hints: u16 = 103;
const ok: u16 = 200;
const encoders_all: usize = 2;
const accepts_gzip = [_]Field{.{ .name = "accept-encoding", .value = "gzip" }};

/// A server that codes content and a client, connected, with a GET that accepts gzip read.
fn coded_get() !*support.Fetch {
    try support.start_coding();
    try support.connect();
    const fetch = try support.request_with_fields("GET", "/", &accepts_gzip);
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.request, 0).?.id);
    return fetch;
}

test "decision 101: an h3 response is coded into DATA frames, and its encoder goes back once acknowledged" {
    const fetch = try coded_get();
    // RFC 9110 §15.2: an interim response goes out as it is, and the final one is coded.
    try connection.respond(fetch.id, .{ .status = early_hints, .end = false, .codable = true });
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(encoders_all - 1, tcp_support.pool.free_count());
    try testing.expectEqual(11, try connection.write_body(fetch.id, .{ .octets = "hello world", .end = true }));
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, fetch.interims);
    try testing.expect(fetch.ended and fetch.gzip and fetch.varies);
    try testing.expectEqualStrings("hello world", try tcp_support.decode(.gzip, support.content_of(fetch)));
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}

test "decision 101: coded content past the ring waits for acknowledgments, and the coding then ends" {
    tcp_support.fill_incompressible();
    const fetch = try coded_get();
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    const content = tcp_support.incompressible[0..];
    var taken = try connection.write_body(fetch.id, .{ .octets = content, .end = true });
    // The ring holds less than the content coded, and QUIC frees none of it before acknowledgments.
    try testing.expect(taken > 0 and taken < content.len);
    try testing.expectError(error.Blocked, connection.write_body(fetch.id, .{ .octets = content[taken..], .end = true }));
    // Bounded: each round's acknowledgments free the ring for more.
    for (0..rounds_max) |_| {
        try support.pump(1);
        if (taken == content.len) {
            if (support.nth(.done, 0) != null) break;
            continue;
        }
        taken += connection.write_body(fetch.id, .{ .octets = content[taken..], .end = true }) catch 0;
        if (taken < content.len) continue;
        // RFC 9110 §6.4.1, §6.5: the content ended, so neither content nor trailers follow.
        try testing.expectError(error.SectionOutOfOrder, connection.write_body(fetch.id, .{ .octets = "x", .end = true }));
        try testing.expectError(error.SectionOutOfOrder, connection.write_trailers(fetch.id, &.{}));
    }
    try testing.expect(fetch.ended and fetch.gzip);
    try testing.expectEqualSlices(u8, content, try tcp_support.decode(.gzip, support.content_of(fetch)));
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}

const rounds_max: usize = 256;

test "decision 101: a coded h3 response's trailer section follows its last coded octet" {
    const fetch = try coded_get();
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(5, try connection.write_body(fetch.id, .{ .octets = "hello", .end = false }));
    const trailer = [_]Field{.{ .name = "checksum", .value = "1" }};
    try connection.write_trailers(fetch.id, &trailer);
    try support.pump(support.rounds_default);
    try testing.expect(fetch.ended);
    try testing.expectEqualStrings("hello", try tcp_support.decode(.gzip, support.content_of(fetch)));
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}

test "decision 101: a coded h3 response the caller cancels, or the client stops, gives its encoder back" {
    tcp_support.fill_incompressible();
    const fetch = try coded_get();
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    _ = try connection.write_body(fetch.id, .{ .octets = tcp_support.incompressible[0..], .end = false });
    connection.cancel(fetch.id);
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
    const second = try support.request_with_fields("GET", "/second", &accepts_gzip);
    try support.pump(support.rounds_default);
    try connection.respond(second.id, .{ .status = ok, .end = false, .codable = true });
    _ = try connection.write_body(second.id, .{ .octets = tcp_support.incompressible[0..], .end = false });
    try testing.expectEqual(encoders_all - 1, tcp_support.pool.free_count());
    // RFC 9000 §3.5: the client's STOP_SENDING resets the response, and QUIC reads its ring no more.
    try support.stop_fetch(second);
    try support.pump(support.rounds_default);
    try testing.expectEqual(second.id, support.nth(.cancelled, 0).?.id);
    try testing.expect(support.nth(.cancelled, 0).?.reason.? == .peer_reset);
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}

test "RFC 9110 §6.5: an h3 trailer section waits for the encoder's last octets, which wait for acknowledgments" {
    tcp_support.fill_incompressible();
    const fetch = try coded_get();
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    const taken = try connection.write_body(fetch.id, .{ .octets = tcp_support.incompressible[0..], .end = false });
    const trailer = [_]Field{.{ .name = "checksum", .value = "1" }};
    try testing.expectError(error.Blocked, connection.write_trailers(fetch.id, &trailer));
    // Bounded: each round's acknowledgments free the ring for the encoder's last octets.
    const written = for (0..rounds_max) |_| {
        try support.pump(1);
        connection.write_trailers(fetch.id, &trailer) catch |failure| {
            try testing.expectEqual(error.Blocked, failure);
            continue;
        };
        break true;
    } else false;
    try testing.expect(written);
    try support.pump(support.rounds_default);
    try testing.expect(fetch.ended);
    try testing.expectEqualSlices(u8, tcp_support.incompressible[0..taken], try tcp_support.decode(.gzip, support.content_of(fetch)));
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}

test "decision 101: a closed transport gives back the encoders of the coded responses it held" {
    const fetch = try coded_get();
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    _ = try connection.write_body(fetch.id, .{ .octets = "hello", .end = false });
    try testing.expectEqual(encoders_all - 1, tcp_support.pool.free_count());
    connection.transport_closed();
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}

test "RFC 9000 §10.2: a connection the peer closes gives back the encoders of its coded responses" {
    const fetch = try coded_get();
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    _ = try connection.write_body(fetch.id, .{ .octets = "hello", .end = false });
    try testing.expectEqual(encoders_all - 1, tcp_support.pool.free_count());
    quic.connection_close.owe(&support.client, quic.connection_close.transport(quic.error_code.no_error, null));
    try support.pump(support.rounds_default);
    try testing.expect(connection.stopped);
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}

test "RFC 9000 §3.1: a coded response the peer acknowledged is done, and gives its encoder back, while its request stays open" {
    try support.start_coding();
    try support.connect();
    const fetch = try support.request_open_with_fields("GET", "/", &accepts_gzip);
    try support.pump(support.rounds_default);
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(5, try connection.write_body(fetch.id, .{ .octets = "hello", .end = true }));
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
    try testing.expect(connection.requests.of(fetch.id) != null);
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}

test "RFC 9000 §3.1: a coded response whose runs wait for acknowledgments takes no content until then" {
    tcp_support.fill_incompressible();
    const fetch = try coded_get();
    // RFC 9110 §15.2: interim responses before the final one, each a HEADERS frame the response
    // keeps until acknowledged. With the final head and the frame of the gzip header, they fill
    // every run a response holds.
    for (0..server_constants.quic_response_pieces_max - held_by_head_and_header) |_| {
        try connection.respond(fetch.id, .{ .status = early_hints, .end = false });
    }
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    const content = tcp_support.incompressible[0..];
    try testing.expectEqual(small_write_len, try connection.write_body(fetch.id, .{ .octets = content[0..small_write_len], .end = false }));
    try testing.expectError(error.Blocked, connection.write_body(fetch.id, .{ .octets = content[small_write_len..], .end = true }));
    var taken: usize = small_write_len;
    // Bounded: each round's acknowledgments free runs and the ring.
    for (0..rounds_max) |_| {
        try support.pump(1);
        if (taken == content.len) {
            if (support.nth(.done, 0) != null) break;
            continue;
        }
        taken += connection.write_body(fetch.id, .{ .octets = content[taken..], .end = true }) catch 0;
    }
    try testing.expectEqualSlices(u8, content, try tcp_support.decode(.gzip, support.content_of(fetch)));
    try testing.expectEqual(encoders_all, tcp_support.pool.free_count());
}

/// The runs the final head and the DATA frame of the gzip header hold: one, then two.
const held_by_head_and_header: usize = 3;
/// A write the encoder takes whole and holds back, having written the gzip header alone.
const small_write_len: usize = 100;
