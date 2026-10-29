//! The tests of the order new stream octets go out in (RFC 9000 §2.3), in
//! `connection_stream_send.zig`: a lower priority value first, and streams of one value taking
//! turns. The connections and the provider are `connection_stream_send_test.zig`'s.
const std = @import("std");
const stream_module = @import("../../stream/stream.zig");
const send = @import("../connection_send.zig");
const stream_send = @import("connection_stream_send.zig");
const send_test = @import("connection_stream_send_test.zig");
const stream_ranges = @import("connection_stream_ranges.zig");
const recovery_sent = @import("../../recovery/recovery_sent.zig");

const StreamId = stream_module.StreamId;
const Body = send_test.Body;
const testing = std.testing;

/// A priority below the default, which goes first. Test-only.
const urgent: u8 = 0;
/// Streams that take turns. Each body needs three packets, so one turn leaves two. Test-only.
const turn_streams: usize = 3;

fn next_stream_id(body: *Body) !u64 {
    const sent = (try send_test.send_from(body, send_test.datagram.len)).?;
    return sent.packets[0].stream_id;
}

/// The stream of each STREAM frame sent, in the order the frames went out, across packets: a
/// packet carries several (decision 131). Test-only.
const Order = struct {
    body: *Body,
    record: ?recovery_sent.Record = null,
    index: usize = 0,

    fn next(order: *Order) !u64 {
        if (order.record == null or order.index == stream_ranges.count(order.record.?)) {
            const sent = (try send_test.send_from(order.body, send_test.datagram.len)).?;
            order.record = try send_test.record_kept(sent);
            order.index = 0;
        }
        defer order.index += 1;
        return stream_ranges.at(&send_test.client, order.record.?, order.index).stream_id;
    }
};

test "RFC 9000 §2.3: a stream with a lower priority value sends first" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.short_body_len };
    const later = try send_test.open_supplied(send_test.short_body_len, true);
    const sooner = try send_test.open_supplied(send_test.short_body_len, true);
    try stream_send.set_priority(&send_test.client, sooner, urgent);
    var order: Order = .{ .body = &body };
    try testing.expectEqual(sooner.value, try order.next());
    try testing.expectEqual(later.value, try order.next());
}

test "RFC 9000 §2.3: streams of one priority take turns" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.long_body_len };
    var ids: [turn_streams]StreamId = undefined;
    for (&ids) |*id| id.* = try send_test.open_supplied(send_test.long_body_len, true);
    // Each body needs several frames, and no stream sends twice before every other sent once.
    var order: Order = .{ .body = &body };
    for (ids) |id| try testing.expectEqual(id.value, try order.next());
    // A stream set before the others goes first in the next packet, until it has nothing left.
    const urgent_id = ids[turn_streams - 1];
    try stream_send.set_priority(&send_test.client, urgent_id, urgent);
    order = .{ .body = &body };
    try testing.expectEqual(urgent_id.value, try order.next());
    // Bounded by the frames one long body takes.
    const after = for (0..send_test.long_body_len) |_| {
        const id = try order.next();
        if (id != urgent_id.value) break id;
    } else return error.TestExpectedAnotherStream;
    try testing.expectEqual(0, send_test.stream_of(urgent_id).outgoing.unframed_len());
    try testing.expectEqual(ids[0].value, after);
}

test "RFC 9000 §2.1: a priority is set only on a stream this endpoint may send on" {
    send_test.open_pair(.{});
    const peer_unidirectional = StreamId.of(.server, .unidirectional, 0);
    _ = try send_test.client.streams.open_peer(peer_unidirectional);
    try testing.expectError(error.NotWritable, stream_send.set_priority(&send_test.client, peer_unidirectional, urgent));
    try testing.expectError(error.NotWritable, stream_send.set_priority(&send_test.client, StreamId.of(.client, .bidirectional, 0), urgent));
}

/// Octets the provider has for every stream, fewer than an urgent stream supplied. Test-only.
const provider_len: u64 = 50;

test "RFC 9000 §2.3: a stream first in order with nothing to read gives way to the next" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = provider_len };
    // The urgent stream said its octets reach further than the provider can read yet.
    const dry = try send_test.open_supplied(send_test.short_body_len, true);
    try stream_send.set_priority(&send_test.client, dry, urgent);
    try testing.expectEqual(dry.value, try next_stream_id(&body));
    // It ranks first and frames nothing, so a stream of the default priority sends instead.
    const ready = try send_test.open_supplied(provider_len, true);
    try testing.expectEqual(ready.value, try next_stream_id(&body));
}
