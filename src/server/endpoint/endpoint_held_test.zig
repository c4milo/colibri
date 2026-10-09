//! The tests of what the endpoint owes its program (`endpoint_held.zig`, decision 119): each
//! request's word on its later events, the program's own cancel, the one ending of every request
//! even when its connection stops first (INV-30), and the connection's `ended` after them.
const std = @import("std");
const quic = @import("quic");
const event = @import("../event.zig");
const support = @import("../quic/quic_test_support.zig");

const testing = std.testing;
const endpoint_support = support.endpoint_support;
const seen_support = support.seen_support;
const endpoint = &endpoint_support.endpoint;

const ok: u16 = 200;
/// Words a test's program sets for its requests.
const first_word: usize = 0x5eed;
const second_word: usize = 0xbead;

/// Where the first event of `kind` the server reported is among them all.
fn index_of(kind: std.meta.Tag(event.Event)) ?usize {
    for (seen_support.seen[0..seen_support.seen_len], 0..) |entry, index| {
        if (entry.kind == kind) return index;
    }
    return null;
}

test "decision 119: a request's word comes back on each later event of it, its ending last" {
    try support.start_endpoint(null);
    try support.connect();
    const fetch = try support.request_open("POST", "/upload", "");
    try support.pump(support.rounds_default);
    const id = endpoint_support.id_of(fetch.id);
    try endpoint.set_user_data(id, first_word);
    // The client ends its request, which the server reports as the end of its content.
    try quic.connection_stream_send.supply(&support.client, .{ .value = fetch.id }, fetch.prefix_len, true);
    try support.pump(support.rounds_default);
    const end = support.nth(.body, 0).?;
    try testing.expect(end.end);
    try testing.expectEqual(first_word, end.user_data);
    try endpoint.respond(id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(first_word, support.nth(.done, 0).?.user_data);
    // INV-30: the ending was the request's last event, and its id names nothing now.
    try testing.expectError(error.RequestUnknown, endpoint.set_user_data(id, 0));
    try testing.expectError(error.RequestUnknown, endpoint.respond(id, .{ .status = ok, .end = true }));
}

test "decision 119: the program's own cancel ends its request with cancelled, and nothing of it follows" {
    try support.start_endpoint(null);
    try support.connect();
    const fetch = try support.request_open("GET", "/slow", "");
    try support.pump(support.rounds_default);
    const id = endpoint_support.id_of(fetch.id);
    try endpoint.set_user_data(id, first_word);
    endpoint.cancel(id);
    // A cancelled request takes no answer, and a second cancel of it is ignored.
    try testing.expectError(error.RequestUnknown, endpoint.respond(id, .{ .status = ok, .end = true }));
    endpoint.cancel(id);
    try support.pump(support.rounds_default);
    const cancelled = support.nth(.cancelled, 0).?;
    try testing.expectEqual(event.CancelReason.program, cancelled.reason.?);
    try testing.expectEqual(first_word, cancelled.user_data);
    try testing.expectEqual(null, support.nth(.cancelled, 1));
    try testing.expectEqual(null, support.nth(.done, 0));
}

test "INV-30: requests open when their connection fails end with cancelled, and its ended follows" {
    try support.start_endpoint(null);
    try support.connect();
    const first = try support.request_open("GET", "/a", "");
    const second = try support.request_open("GET", "/b", "");
    try support.pump(support.rounds_default);
    const first_id = endpoint_support.id_of(first.id);
    try endpoint.set_user_data(first_id, first_word);
    try endpoint.set_user_data(endpoint_support.id_of(second.id), second_word);
    try testing.expectEqualStrings("localhost", endpoint.server_name(first_id.connection).?);
    // colibri fails the connection, which owes the program the end of each request it held.
    endpoint_support.fail_live();
    // RFC 9000 §10.2: the closing state lasts three PTOs, which these rounds pass.
    try support.pump(support.rounds_default * 8);
    var words: [2]usize = undefined;
    for (&words, 0..) |*word, n| {
        const cancelled = support.nth(.cancelled, n).?;
        try testing.expectEqual(event.CancelReason.closed, cancelled.reason.?);
        word.* = cancelled.user_data;
    }
    std.mem.sort(usize, &words, {}, std.sort.asc(usize));
    try testing.expectEqualSlices(usize, &.{ first_word, second_word }, &words);
    // The connection's `ended` comes after its requests' endings, and names the failure.
    try testing.expectEqual(1, endpoint_support.ended_len);
    try testing.expect(index_of(.ended).? > index_of(.cancelled).?);
    const ended = endpoint_support.ended[0];
    try testing.expectEqual(first_id.connection, ended.connection);
    try testing.expect(ended.failed and ended.reason == null);
    // Its handle names nothing from here on.
    try testing.expectError(error.ConnectionUnknown, endpoint.set_deadlines(ended.connection, .{}));
    try testing.expectEqual(null, endpoint.server_name(ended.connection));
}

test "INV-30: a response acknowledged before its connection failed still ends with done" {
    try support.start_endpoint(null);
    try support.connect();
    const fetch = try support.request("GET", "/a", "");
    try support.pump(support.rounds_default);
    const id = endpoint_support.id_of(fetch.id);
    try endpoint.set_user_data(id, first_word);
    try endpoint.respond(id, .{ .status = ok, .end = true });
    // The response goes out, and the client's acknowledgment of it reaches the connection unread.
    try support.pump(1);
    try support.deliver_unread();
    try testing.expectEqual(1, support.served.owed.len);
    endpoint_support.fail_live();
    support.collect();
    try testing.expectEqual(first_word, support.nth(.done, 0).?.user_data);
    try testing.expectEqual(null, support.nth(.cancelled, 0));
    try support.pump(support.rounds_default * 8);
    try testing.expectEqual(1, endpoint_support.ended_len);
    try testing.expect(endpoint_support.ended[0].failed);
}

test "INV-31: a deadline the next event starts is the endpoint's, after a read of the deadline" {
    try support.start_endpoint(null);
    try support.connect();
    const fetch = try support.request("GET", "/a", "");
    try support.pump(support.rounds_default);
    const id = endpoint_support.id_of(fetch.id);
    try endpoint.respond(id, .{ .status = ok, .end = false });
    _ = try endpoint.write_body(id, .{ .octets = &content, .end = true });
    // The program reads the deadline after it answers. The next `receive` observes the answer's
    // send deadline (decision 110), and `collect` compares the endpoint's deadline with a scan.
    _ = endpoint.deadline_ns();
    support.collect();
    support.now_ns += support.round_ns;
    support.collect();
}

/// A response's content, which stays in place until the request ends (decision 103).
const content: [content_len]u8 = @splat('c');
const content_len: usize = 4096;

test "INV-30: a connection whose send fails ends its open requests at the next event" {
    try support.start_endpoint(null);
    try support.connect();
    const fetch = try support.request("GET", "/a", "");
    try support.pump(support.rounds_default);
    const id = endpoint_support.id_of(fetch.id);
    try endpoint.set_user_data(id, first_word);
    // RFC 9000 §12.3: a sender whose packet number reaches 2^62-1 "MUST close the connection", so
    // the answer's send fails it.
    quic.connection.space_at(&support.served.transport, .application).next_packet_number = quic.constants.packet_number_max + 1;
    try endpoint.respond(id, .{ .status = ok, .end = true });
    try support.pump(1);
    const cancelled = support.nth(.cancelled, 0).?;
    try testing.expectEqual(event.CancelReason.closed, cancelled.reason.?);
    try testing.expectEqual(first_word, cancelled.user_data);
}
