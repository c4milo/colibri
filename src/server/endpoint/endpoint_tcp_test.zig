//! The tests of the endpoint's TCP slots (`endpoint_held_tcp.zig`, decision 119): a connection the
//! program accepted speaks h11 or h2, in cleartext as its first octets choose and over TLS as ALPN
//! does, every request ends once before its connection's `ended`, and a handle of a connection
//! that ended names nothing.
const std = @import("std");
const h2 = @import("h2");
const support = @import("endpoint_tcp_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");

const testing = std.testing;
const endpoint = &support.endpoint;

const ok: u16 = 200;
const get_h11 = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

test "RFC 9112 §9.6: an h11 request in cleartext is answered, done, sent, closed, and ended" {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    try testing.expectEqual(0, support.give(handle, get_h11));
    const request = support.nth(.request, 0).?;
    try testing.expectEqual(handle, request.connection);
    try endpoint.respond(support.id_of(handle, request.number), .{ .status = ok, .end = true });
    support.collect();
    try testing.expect(std.mem.startsWith(u8, support.sent_of(handle.slot), "HTTP/1.1 200"));
    // INV-30: the request ends first, then its octets go out, and then the connection closes.
    const done = support.index_of(.done).?;
    try testing.expect(done < support.index_of(.send).?);
    try testing.expect(support.index_of(.send).? < support.index_of(.close).?);
    try testing.expect(support.index_of(.close).? < support.index_of(.ended).?);
    try testing.expect(!support.nth(.ended, 0).?.failed);
}

test "decision 119 as amended: an h11 head in cleartext that two reads carry is read once whole" {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    // The endpoint polls the slot with no octets between the program's two passes.
    const first = get_h11[0.."GET / HT".len];
    try testing.expectEqual(first.len, support.give(handle, first));
    try testing.expectEqual(null, support.nth(.request, 0));
    try testing.expectEqual(0, support.give(handle, get_h11));
    try testing.expectEqual(handle, support.nth(.request, 0).?.connection);
}

test "RFC 9113 §3.3: an h2 preface in cleartext chooses h2, and a request on stream 1 is answered" {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, h2_support.client_preface);
    _ = support.give(handle, try h2_support.request_frame(1, "/", true));
    const request = support.nth(.request, 0).?;
    try testing.expectEqual(1, request.number);
    try endpoint.respond(support.id_of(handle, 1), .{ .status = ok, .end = true });
    support.collect();
    // RFC 9113 §3.4: the server's preface, a SETTINGS frame, goes first, then the response.
    try testing.expectEqual(h2.constants.frame_type_settings, support.sent_of(handle.slot)[h2_support.type_index]);
    try testing.expectEqual(1, support.nth(.done, 0).?.number);
    try testing.expectEqual(null, support.nth(.close, 0));
}

test "RFC 7301 §3.2: over TLS, ALPN chooses h2 by default, h11 with h2 turned off, and SNI is read" {
    for ([_]bool{ true, false }) |with_h2| {
        try support.start(support.identity(), .{ .h2 = with_h2 });
        const handle = endpoint.accept(.tls, support.now_ns).?;
        try support.start_client(&tcp_support.protocols_both);
        try testing.expect(try support.handshake(handle));
        const chosen = endpoint.tcp[handle.slot].protocol().?;
        const expected: @TypeOf(chosen) = if (with_h2) .h2 else .h11;
        try testing.expectEqual(expected, chosen);
        try testing.expectEqualStrings("localhost", endpoint.server_name(handle).?);
    }
}

test "RFC 9113 §3.3, decision 117: a TLS client that selects no protocol is refused with h11 off" {
    try support.start(support.identity(), .{ .h11 = false });
    const handle = endpoint.accept(.tls, support.now_ns).?;
    try support.start_client(&.{});
    _ = try support.handshake(handle);
    support.collect();
    // No request is read, and the connection closes, failed.
    try testing.expectEqual(null, support.nth(.request, 0));
    try testing.expect(support.index_of(.close).? < support.index_of(.ended).?);
    try testing.expect(support.nth(.ended, 0).?.failed);
}

test "decision 119: one endpoint holds a cleartext slot and a TLS slot, each read as it is" {
    try support.start(support.identity(), .{});
    const cleartext = endpoint.accept(.cleartext, support.now_ns).?;
    const secure = endpoint.accept(.tls, support.now_ns).?;
    try testing.expect(cleartext.slot != secure.slot);
    _ = support.give(cleartext, get_h11);
    try testing.expectEqual(cleartext, support.nth(.request, 0).?.connection);
    try testing.expectEqual(null, endpoint.server_name(cleartext));
    try support.start_client(&tcp_support.protocols_both);
    try testing.expect(try support.handshake(secure));
    try testing.expectEqualStrings("localhost", endpoint.server_name(secure).?);
}

test "decision 119: the handle of a connection that ended names nothing once its slot is reused" {
    try support.start(null, .{});
    const first = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(first, get_h11);
    const id = support.id_of(first, support.nth(.request, 0).?.number);
    endpoint.transport_closed(first);
    support.collect();
    try testing.expectEqual(first, support.nth(.ended, 0).?.connection);
    // Both slots are free, and the next connection takes the one the first held.
    _ = endpoint.accept(.cleartext, support.now_ns).?;
    const second = endpoint.accept(.cleartext, support.now_ns).?;
    try testing.expect(second.slot == first.slot or second.generation != first.generation);
    const before = support.seen_len;
    try testing.expectEqual(0, support.give(first, get_h11));
    try testing.expectEqual(before, support.seen_len);
    var output: [16]u8 = undefined;
    try testing.expectEqual(0, endpoint.send_stream(first, &output, support.now_ns));
    try testing.expectError(error.RequestUnknown, endpoint.respond(id, .{ .status = ok, .end = true }));
    try testing.expectError(error.ConnectionUnknown, endpoint.set_deadlines(first, .{}));
    try testing.expectEqual(null, endpoint.server_name(first));
    endpoint.transport_closed(first);
}

test "decision 119: accept starts nothing with every TCP slot held, after shutdown, or with no TCP version" {
    try support.start(null, .{});
    for (0..support.tcp_slots) |_| _ = endpoint.accept(.cleartext, support.now_ns).?;
    try testing.expectEqual(null, endpoint.accept(.cleartext, support.now_ns));
    try support.start(null, .{});
    endpoint.shutdown(support.now_ns);
    try testing.expectEqual(null, endpoint.accept(.cleartext, support.now_ns));
    // RFC 9114 §3.1: h3 alone leaves a TCP connection nothing to speak, and with no identity the
    // QUIC slot serves nothing either.
    try testing.expectError(error.NoVersion, support.start(null, .{ .h11 = false, .h2 = false }));
}

test "decision 119: TCP slots owe no datagram, and an endpoint that serves no QUIC drops datagrams" {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, get_h11);
    var output: [@import("quic").constants.datagram_len_max]u8 = undefined;
    try testing.expectEqual(null, endpoint.send_datagram(&output, support.now_ns));
    // With no identity the QUIC slot serves nothing: a datagram is consumed, and starts nothing.
    var datagram: [@import("quic").constants.datagram_len_min]u8 = @splat(0xc0);
    const from = @import("quic").PeerAddress.of(&.{ 127, 0, 0, 1 }, 50_000);
    const received = endpoint.receive(.{ .datagram = .{ .octets = &datagram, .from = from } }, support.now_ns);
    try testing.expectEqual(datagram.len, received.consumed);
    try testing.expectEqual(null, endpoint.send_datagram(&output, support.now_ns));
    try testing.expect(!endpoint.live[support.tcp_slots]);
}

test "decision 119: a TCP connection borrows the endpoint's h11 decoders, its Alt-Svc and its codings" {
    try support.start(support.identity(), .{});
    support.config.decoded = &decoded_storage;
    support.config.h3_alternative = .{ .port = 443 };
    try support.endpoint.init(&support.config, tcp_support.stream.random(), tcp_support.now_seconds, support.now_ns);
    for ([_]*const @TypeOf(endpoint.tcp_configs.cleartext){ &endpoint.tcp_configs.cleartext, &endpoint.tcp_configs.secure }) |borrowed| {
        try testing.expectEqual(decoded_storage.len, borrowed.decoded.len);
        try testing.expectEqual(443, borrowed.h3_alternative.?.port);
        try testing.expectEqual(support.config.versions, borrowed.versions);
    }
    try testing.expect(endpoint.tcp_configs.secure.tls != null and endpoint.tcp_configs.cleartext.tls == null);
}

var decoded_storage: [decoded_len]u8 = undefined;
const decoded_len: usize = 16;

test "RFC 9846 §6.1: over TLS, h11's close sends the close_notify before the endpoint's close" {
    try support.start(support.identity(), .{ .h2 = false });
    const handle = endpoint.accept(.tls, support.now_ns).?;
    try support.start_client(&tcp_support.protocols_both);
    try testing.expect(try support.handshake(handle));
    _ = try support.give_sealed(handle, get_h11);
    try endpoint.respond(support.id_of(handle, support.nth(.request, 0).?.number), .{ .status = ok, .end = true });
    support.collect();
    try testing.expect(support.nth(.close, 0) != null);
    _ = try support.open_sent(handle.slot);
    try testing.expect(support.client_saw_alert);
}

test "RFC 9846 §5.2: a forged record over TLS sends the alert once, closes, and fails" {
    try support.start(support.identity(), .{});
    const handle = endpoint.accept(.tls, support.now_ns).?;
    try support.start_client(&tcp_support.protocols_both);
    try testing.expect(try support.handshake(handle));
    const sends_before = count(.send);
    // An application_data header over octets no key sealed (RFC 9846 §5.2).
    _ = support.give(handle, "\x17\x03\x03\x00\x20" ++ "\x00" ** 32);
    support.collect();
    try testing.expectEqual(sends_before + 1, count(.send));
    try testing.expect(support.index_of(.close).? < support.index_of(.ended).?);
    try testing.expect(support.nth(.ended, 0).?.failed);
}

fn count(kind: std.meta.Tag(@import("../event.zig").Event)) usize {
    var n: usize = 0;
    while (support.nth(kind, n) != null) n += 1;
    return n;
}

test "RFC 9846 §6.1: a TLS connection shut down with no request sends its close_notify, and closes" {
    try support.start(support.identity(), .{ .h2 = false });
    const handle = endpoint.accept(.tls, support.now_ns).?;
    try support.start_client(&tcp_support.protocols_both);
    try testing.expect(try support.handshake(handle));
    support.collect();
    endpoint.shutdown(support.now_ns);
    support.collect();
    try testing.expect(support.nth(.close, 0) != null);
    _ = try support.open_sent(handle.slot);
    try testing.expect(support.client_saw_alert);
}
