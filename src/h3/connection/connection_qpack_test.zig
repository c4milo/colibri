//! The tests of QPACK's dynamic table through the h3 connection (RFC 9204 §2): entries the
//! encoder inserts, acknowledgments on the decoder stream, a blocked section that waits in `quic`
//! (decision 80), and h3's streams dropping what the peer acknowledged (decision 78). The harness
//! is `connection_test.zig`'s.
const std = @import("std");
const quic = @import("quic");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const connection_local = @import("connection_local.zig");
const harness = @import("connection_test.zig");

const Event = connection_module.Event;
const Line = harness.Line;
const testing = std.testing;

const client = &harness.client;
const server = &harness.server;
const exchange = harness.exchange;
const next = harness.next;

/// A client whose decoder allows a table and blocked streams, so the server's encoder uses them.
const table_capacity: u64 = 4096;
const table_blocked_streams: u64 = 16;
const table_client: connection_module.Options = .{ .role = .client, .qpack = .{ .max_table_capacity = table_capacity, .blocked_streams = table_blocked_streams } };

/// A response with a line the static table lacks, which the encoder inserts.
const custom_lines = [_]Line{ .{ ":status", "200" }, .{ "x-custom", "value-that-repeats" } };

/// A request, and the server's response to it with `custom_lines`, sent but not yet exchanged.
fn request_and_respond() !u64 {
    const id = try harness.request(&harness.get_lines, "");
    try exchange();
    _ = (try next(server)).?.request;
    _ = (try next(server)).?.end;
    try harness.respond(id, &custom_lines, "");
    return id;
}

test "RFC 9204 §2.1: a line the static table lacks is inserted once, and the decoder acknowledges it" {
    try harness.pair(table_client, .{ .role = .server });
    for (0..2) |_| {
        const id = try request_and_respond();
        try exchange();
        const response = (try next(client)).?.response;
        try testing.expectEqual(id, response.stream_id);
        try testing.expectEqualStrings("value-that-repeats", client.h3.field_section().find("x-custom").?.value);
        try testing.expectEqual(Event{ .end = id }, (try next(client)).?);
        try testing.expectEqual(null, try next(client));
    }
    try testing.expectEqual(1, server.h3.encoder.table.insert_count());
    try testing.expectEqual(1, client.h3.decoder.table.insert_count());
    // §4.4: the client's decoder stream carries what it owes, and the server's encoder reads it.
    try exchange();
    try testing.expectEqual(null, try next(server));
    try testing.expectEqual(1, server.h3.encoder.state.known_received);
}

test "RFC 9204 §2.2.1: a section that arrives before its entries waits in quic, then decodes" {
    try harness.pair(table_client, .{ .role = .server });
    // The encoder stream goes after every other stream, so the response arrives first.
    const encoder_id = server.h3.local.encoder_id.?;
    try quic.connection_stream_send.set_priority(&server.transport, .{ .value = encoder_id }, 255);
    const id = try request_and_respond();
    try harness.transfer_frames(server, client, 1);
    try testing.expectEqual(null, try next(client));
    try testing.expect(client.h3.requests.find(id).?.blocked_at != null);
    // The section is still unread in `quic` (decision 80).
    try testing.expect(!client.transport.streams.lookup(.{ .value = id }).live.incoming.is_empty());
    try exchange();
    try testing.expectEqual(200, (try next(client)).?.response.response.status.code);
    try testing.expectEqual(Event{ .end = id }, (try next(client)).?);
}

test "RFC 9204 §2.2.2.2: a stream reset while its section waits is cancelled on the decoder stream" {
    try harness.pair(table_client, .{ .role = .server });
    try quic.connection_stream_send.set_priority(&server.transport, .{ .value = server.h3.local.encoder_id.? }, 255);
    const id = try harness.request(&harness.get_lines, "");
    try exchange();
    _ = (try next(server)).?.request;
    // The response's header section goes out on a stream the server has not ended.
    var writer = server.writer_for(id);
    try server.h3.write_response(&server.transport, id, try harness.section_of(&harness.test_section, &custom_lines), &.{}, &writer);
    try server.commit(id, writer.written(), false);
    try harness.transfer_frames(server, client, 1);
    try testing.expectEqual(null, try next(client));
    server.h3.cancel(&server.transport, id, constants.error_request_cancelled);
    try exchange();
    try testing.expectEqual(Event{ .reset = .{ .stream_id = id, .error_code = constants.error_request_cancelled } }, (try next(client)).?);
    // The client's decoder no longer holds the stream, and its cancellation went out.
    try testing.expectEqual(0, client.h3.decoder.blocked_len);
    try testing.expectEqual(null, try next(client));
    try testing.expect(!client.h3.decoder.owes());
}

test "a trailer section inserts nothing into the dynamic table" {
    // The server allows a table, so the client's encoder inserts the request's lines.
    try harness.pair(.{ .role = .client }, .{ .role = .server, .qpack = table_client.qpack });
    const section = try harness.section_of(&harness.test_section, &harness.get_lines);
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, section, &.{}, &writer);
    const inserted = client.h3.encoder.table.insert_count();
    try testing.expect(inserted > 0);
    try client.h3.write_trailers(&client.transport, id, try harness.section_of(&harness.test_section, &custom_lines[1..].*), &writer);
    try testing.expectEqual(inserted, client.h3.encoder.table.insert_count());
}

test "decision 78: h3's encoder stream drops what the peer acknowledged when room runs short" {
    try harness.pair(table_client, .{ .role = .server });
    const local = &server.h3.local;
    const id = local.encoder_id.?;
    // Fill the buffer until less than one insert's room is left, and send it all.
    var filler: [constants.encoder_buffer_len]u8 = @splat(0);
    const fill_len = local.encoder.free().remaining_len() - 1;
    try local.encoder.write(filler[0..fill_len]);
    try quic.connection_stream_send.supply(&server.transport, .{ .value = id }, local.encoder.end_offset(), false);
    try harness.transfer(server, client);
    const framed = local.encoder.end_offset();
    try testing.expectEqual(0, local.encoder.start_offset);
    // No packet carried the octets here, so `quic` counts every framed one acknowledged.
    const room = try connection_local.encoder_room(&server.h3, &server.transport);
    try testing.expectEqual(framed, local.encoder.start_offset);
    try testing.expectEqual(constants.encoder_buffer_len, room.remaining_len());
}
