//! The requests one QUIC connection of the server holds (design §8 step 17b): a record for each
//! request stream the client opened, with the response it carries until the stream closes, and
//! the `done` and `cancelled` events the connection owes the caller. A request's id is its
//! stream's (decision 103).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const quic_response = @import("quic_response.zig");
const coding_rules = @import("../coding/coding_rules.zig");
const coding_response = @import("../coding/coding_response.zig");

const Id = event.Id;

/// One request stream, from its request's head until the stream closes.
pub const Request = struct {
    in_use: bool,
    stream_id: u64,
    /// The request's end went to the caller: its content ended, or its trailer section came.
    ended: bool,
    /// The final response's head went out, and the stream's last octet is supplied, its FIN.
    answered: bool,
    finished: bool,
    /// The request ended for the caller: its `done` or `cancelled` event is owed or went out,
    /// or the caller cancelled it. Nothing more is reported of it.
    over: bool,
    /// The response's frames and the runs of the caller's octets, until the peer acknowledges
    /// them.
    response: quic_response.Pieces,
    /// What the request asked of the codings the server applies, and the coded response, whose
    /// runs are its encoder's ring (decision 101).
    asked: coding_rules.Asked,
    coded: ?coding_response.Coded,
};

pub const Requests = struct {
    records: [constants.quic_requests_max]Request,

    pub fn init(requests: *Requests) void {
        for (&requests.records) |*record| record.in_use = false;
    }

    /// A record for the request on `stream_id`, or null when every record is in use.
    pub fn take(requests: *Requests, stream_id: u64) ?*Request {
        assert(requests.of(stream_id) == null);
        for (&requests.records) |*record| {
            if (record.in_use) continue;
            record.* = .{
                .in_use = true,
                .stream_id = stream_id,
                .ended = false,
                .answered = false,
                .finished = false,
                .over = false,
                .response = undefined,
                .asked = .{},
                .coded = null,
            };
            record.response.init();
            return record;
        }
        return null;
    }

    /// The record of the request on `stream_id`, or null.
    pub fn of(requests: *Requests, stream_id: u64) ?*Request {
        for (&requests.records) |*record| {
            if (record.in_use and record.stream_id == stream_id) return record;
        }
        return null;
    }

    /// Whether no request is held.
    pub fn idle(requests: *const Requests) bool {
        for (&requests.records) |*record| {
            if (record.in_use) return false;
        }
        return true;
    }
};

/// An event the connection owes the caller for a request that ended: its response is done, or it
/// was cancelled.
pub const Ending = struct {
    kind: enum { done, cancelled },
    id: Id,
};

/// The events owed, oldest first. Each request owes one at most, so the ring has room for every
/// request the connection holds.
pub const Owed = struct {
    endings: [constants.quic_requests_max]Ending = undefined,
    first: usize = 0,
    len: usize = 0,

    pub fn push(owed: *Owed, ending: Ending) void {
        assert(owed.len < owed.endings.len);
        owed.endings[(owed.first + owed.len) % owed.endings.len] = ending;
        owed.len += 1;
    }

    /// The oldest event owed, as the caller reads it, or null.
    pub fn take(owed: *Owed) ?event.Event {
        if (owed.len == 0) return null;
        const ending = owed.endings[owed.first];
        owed.first = (owed.first + 1) % owed.endings.len;
        owed.len -= 1;
        return switch (ending.kind) {
            .done => .{ .done = .{ .id = ending.id } },
            // RFC 9000 §3.5: the peer's STOP_SENDING reset the response's stream.
            .cancelled => .{ .cancelled = .{ .id = ending.id, .reason = .peer_reset } },
        };
    }

    pub fn clear(owed: *Owed) void {
        owed.first = 0;
        owed.len = 0;
    }
};

const testing = std.testing;

/// The records the tests fill. Test-only.
threadlocal var test_requests: Requests align(@alignOf(Requests)) = undefined;

test "a record is taken for each request stream, found by its stream, and freed for the next" {
    const requests = &test_requests;
    requests.init();
    try testing.expect(requests.idle());
    for (0..constants.quic_requests_max) |index| {
        const stream_id: u64 = index * 4;
        try testing.expectEqual(stream_id, requests.take(stream_id).?.stream_id);
    }
    try testing.expectEqual(null, requests.take(constants.quic_requests_max * 4));
    const second = requests.of(4).?;
    second.in_use = false;
    try testing.expectEqual(null, requests.of(4));
    try testing.expect(requests.take(1000) != null);
    try testing.expect(!requests.idle());
}

test "decision 103: the endings owed come out in order, as the events the caller reads" {
    var owed: Owed = .{};
    try testing.expectEqual(null, owed.take());
    owed.push(.{ .kind = .done, .id = 8 });
    owed.push(.{ .kind = .cancelled, .id = 4 });
    try testing.expectEqual(8, owed.take().?.done.id);
    try testing.expectEqual(4, owed.take().?.cancelled.id);
    try testing.expectEqual(null, owed.take());
    // A ring that starts partway round wraps past its end.
    for (0..constants.quic_requests_max) |index| owed.push(.{ .kind = .done, .id = index });
    for (0..constants.quic_requests_max) |index| try testing.expectEqual(index, owed.take().?.done.id);
}
