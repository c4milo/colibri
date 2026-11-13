//! The tests of `stream_table.zig`: identifiers in order, the stream limits of RFC 9000 §4.6,
//! streams that close, and the bits of the slots each walk reads.
const std = @import("std");
const constants = @import("../constants.zig");
const stream_id = @import("stream_id.zig");
const stream_table = @import("stream_table.zig");

const Streams = stream_table.Streams;
const StreamId = stream_id.StreamId;
const Initiator = stream_id.Initiator;
const Directionality = stream_id.Directionality;
const connection_error_code = stream_table.connection_error_code;
const testing = std.testing;

/// The table the tests drive, and the limits they start it with. Test-only.
threadlocal var test_streams: Streams align(@alignOf(Streams)) = undefined;
const test_limit = 8;
const both_limits: [constants.protocol.stream_directionalities]u64 = @splat(test_limit);

/// A stream the peer initiates, of `directionality` and index `index`. Test-only.
fn peer_id(role: Initiator, directionality: Directionality, index: u64) StreamId {
    return StreamId.init(role.peer(), directionality, index);
}

test "§2.1: this endpoint's streams take the next index of their type" {
    test_streams.init(.client, both_limits, both_limits);
    try testing.expectEqual(0, test_streams.len());
    const first = try test_streams.open_local(.bidirectional);
    // RFC 9000 §2.1: a client's bidirectional streams are 0, 4, 8 and so on.
    try testing.expectEqual(0, first.id);
    try testing.expectEqual(4, (try test_streams.open_local(.bidirectional)).id);
    // The unidirectional space counts on its own, starting at 2 for a client.
    try testing.expectEqual(2, (try test_streams.open_local(.unidirectional)).id);
    try testing.expectEqual(6, (try test_streams.open_local(.unidirectional)).id);
    try testing.expectEqual(4, test_streams.len());
}

test "§3.2: a peer's stream creates every lower-numbered stream of its type" {
    test_streams.init(.server, both_limits, both_limits);
    // The peer names its fourth bidirectional stream, index 3, which is identifier 12.
    const named = peer_id(.server, .bidirectional, 3);
    const stream = try test_streams.open_peer(named);
    try testing.expectEqual(named.value, stream.id);
    // RFC 9000 §3.2: every lower-numbered stream of the type exists too, so both endpoints
    // agree on the creation order.
    try testing.expectEqual(4, test_streams.len());
    for (0..4) |index| {
        const lower = peer_id(.server, .bidirectional, index);
        try testing.expect(test_streams.lookup(lower) == .live);
    }
    // The other types were not touched.
    try testing.expect(test_streams.lookup(peer_id(.server, .unidirectional, 0)) == .unopened);
    // A frame for a stream that already exists is that stream, which `lookup` answers; the
    // caller never asks this one to open it again.
    try testing.expect(test_streams.lookup(peer_id(.server, .bidirectional, 1)) == .live);
    // One above the highest opens only the streams between.
    _ = try test_streams.open_peer(peer_id(.server, .bidirectional, 5));
    try testing.expectEqual(6, test_streams.len());
    // A stream that opened and closed reads as closed, and the ones between are not reopened.
    const closed = peer_id(.server, .bidirectional, 2);
    const stream_2 = test_streams.lookup(closed).live;
    _ = stream_2.receiving.on(.received_reset);
    _ = stream_2.receiving.on(.application_read_reset);
    _ = stream_2.sending.on(.sent_reset);
    _ = stream_2.sending.on(.reset_acknowledged);
    test_streams.close(closed);
    try testing.expect(test_streams.lookup(closed) == .closed);
    _ = try test_streams.open_peer(peer_id(.server, .bidirectional, 6));
    try testing.expect(test_streams.lookup(closed) == .closed);
}

test "§4.6: a peer past the advertised limit ends the connection" {
    test_streams.init(.server, both_limits, both_limits);
    // The limit counts streams, so index test_limit - 1 is the last admitted.
    _ = try test_streams.open_peer(peer_id(.server, .unidirectional, test_limit - 1));
    try testing.expectEqual(test_limit, test_streams.len());
    const past = peer_id(.server, .unidirectional, test_limit);
    try testing.expectError(error.StreamLimitReached, test_streams.open_peer(past));
    // RFC 9000 §20.1: STREAM_LIMIT_ERROR is 0x04.
    try testing.expectEqual(0x04, connection_error_code(error.StreamLimitReached));
    // Nothing was opened by the refusal.
    try testing.expectEqual(test_limit, test_streams.len());
    try testing.expect(test_streams.lookup(past) == .unopened);
}

test "§4.6: this endpoint stops at the peer's limit and says it is blocked" {
    test_streams.init(.client, both_limits, both_limits);
    for (0..test_limit) |_| _ = try test_streams.open_local(.bidirectional);
    try testing.expectError(error.StreamLimitReached, test_streams.open_local(.bidirectional));
    // RFC 9000 §19.14: the frame names the limit that blocked it, once.
    try testing.expectEqual(test_limit, test_streams.blocked_frame_limit(.bidirectional).?);
    try testing.expectEqual(null, test_streams.blocked_frame_limit(.bidirectional));
    // The other directionality has its own limit and is not blocked.
    try testing.expectEqual(null, test_streams.blocked_frame_limit(.unidirectional));
    _ = try test_streams.open_local(.unidirectional);
    // RFC 9000 §4.6: a MAX_STREAMS frame that does not increase the limit is ignored.
    try testing.expect(!test_streams.raise_local_limit(.bidirectional, test_limit));
    try testing.expect(test_streams.raise_local_limit(.bidirectional, test_limit + 1));
    try testing.expectEqual(4 * test_limit, (try test_streams.open_local(.bidirectional)).id);
}

test "§3: a stream that both halves finished is closed, and reads as closed after" {
    test_streams.init(.client, both_limits, both_limits);
    const stream = try test_streams.open_local(.unidirectional);
    const id = stream.stream_identifier();
    // A unidirectional stream this endpoint opened has no receiving half to finish.
    try testing.expect(!id.is_receivable_by(.client));
    _ = stream.sending.on(.sent_fin);
    _ = stream.sending.on(.all_data_acknowledged);
    test_streams.close(id);
    try testing.expect(test_streams.lookup(id) == .closed);
    try testing.expectEqual(0, test_streams.len());
    // An identifier the type never reached is unopened, not closed.
    try testing.expect(test_streams.lookup(StreamId.init(.client, .unidirectional, 5)) == .unopened);
}

test "§4.6, §3.2: the advertised limit never exceeds what the table can hold" {
    const past_table: [constants.protocol.stream_directionalities]u64 = @splat(constants.limits.streams_per_connection_max + 100);
    test_streams.init(.server, both_limits, past_table);
    // §3.2's implicit creation makes an advertised limit a promise to hold that many streams,
    // so the table's capacity is what is advertised instead.
    try testing.expectEqual(constants.limits.streams_per_connection_max, test_streams.peer_limit[0].limit);
    // The peer may fill the table and no more, and filling it is not an error.
    const last = peer_id(.server, .bidirectional, constants.limits.streams_per_connection_max - 1);
    _ = try test_streams.open_peer(last);
    try testing.expectEqual(constants.limits.streams_per_connection_max, test_streams.len());
    const past = peer_id(.server, .bidirectional, constants.limits.streams_per_connection_max);
    try testing.expectError(error.StreamLimitReached, test_streams.open_peer(past));
}

test "§4.6: more room for the peer is offered as its streams close" {
    test_streams.init(.server, both_limits, both_limits);
    _ = try test_streams.open_peer(peer_id(.server, .unidirectional, test_limit - 1));
    // Nothing has been finished with, so there is no more room to offer.
    try testing.expectEqual(null, test_streams.peer_limit_frame(.unidirectional, 0));
    // Half the limit's worth of streams end, which is worth telling the peer about.
    for (0..test_limit / 2) |index| {
        const id = peer_id(.server, .unidirectional, index);
        const stream = test_streams.lookup(id).live;
        _ = stream.receiving.on(.received_reset);
        _ = stream.receiving.on(.application_read_reset);
        // Closing a stream the peer opened is what gives its count back.
        test_streams.close(id);
    }
    try testing.expectEqual(test_limit + test_limit / 2, test_streams.peer_limit_frame(.unidirectional, 0).?);
}

test "design §8 step 29d.10: a stream this endpoint receives on is marked from open to close" {
    test_streams.init(.server, both_limits, both_limits);
    const marks = &test_streams.may_owe_credit;
    const id = peer_id(.server, .unidirectional, 1);
    // §3.2: the frame opens index 0 too, and the endpoint receives on both.
    _ = try test_streams.open_peer(id);
    const opened = marks.count();
    try testing.expectEqual(2, opened);
    // §2.1: a unidirectional stream this endpoint opens only sends, and a bidirectional one
    // receives too.
    _ = try test_streams.open_local(.unidirectional);
    try testing.expectEqual(opened, marks.count());
    _ = try test_streams.open_local(.bidirectional);
    try testing.expectEqual(opened + 1, marks.count());
    const stream = test_streams.lookup(id).live;
    _ = stream.receiving.on(.received_reset);
    _ = stream.receiving.on(.application_read_reset);
    test_streams.close(id);
    try testing.expectEqual(opened, marks.count());
}

test "design §8 step 29d.16: a stream this endpoint sends on is marked from open to close" {
    test_streams.init(.server, both_limits, both_limits);
    const marks = &test_streams.may_send_new;
    // §2.1: a unidirectional stream the peer opens only receives, and a bidirectional one sends
    // too. §3.2: the frame opens index 0 as well.
    _ = try test_streams.open_peer(peer_id(.server, .unidirectional, 1));
    try testing.expectEqual(0, marks.count());
    const id = peer_id(.server, .bidirectional, 0);
    _ = try test_streams.open_peer(id);
    try testing.expectEqual(1, marks.count());
    // A stream this endpoint opens sends, whatever its type.
    _ = try test_streams.open_local(.unidirectional);
    _ = try test_streams.open_local(.bidirectional);
    try testing.expectEqual(3, marks.count());
    const stream = test_streams.lookup(id).live;
    _ = stream.receiving.on(.received_reset);
    _ = stream.receiving.on(.application_read_reset);
    _ = stream.sending.on(.sent_reset);
    _ = stream.sending.on(.reset_acknowledged);
    test_streams.close(id);
    try testing.expectEqual(2, marks.count());
}
