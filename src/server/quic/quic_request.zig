//! The requests one QUIC connection of the server holds (design §8 step 17b): a record for each
//! request stream the client opened, with the response it carries until the stream closes, and
//! the `done` and `cancelled` events the connection owes the caller. A request's id is its
//! stream's (decision 103).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const deadline = @import("../deadline.zig");
const quic_response = @import("quic_response.zig");
const coding_rules = @import("../coding/coding_rules.zig");
const coding_response = @import("../coding/coding_response.zig");

const Number = event.Number;

/// One request stream, from its request's head until the stream closes. `Requests.held` says
/// which records are in use.
pub const Request = struct {
    stream_id: u64,
    /// The request's end went to the caller: its content ended, or its trailer section came.
    ended: bool,
    /// The final response's head went out, and the stream's last octet is supplied, its FIN.
    answered: bool,
    finished: bool,
    /// The request ended for the caller: its `done` or `cancelled` event is owed or went out,
    /// or the caller cancelled it. Nothing more is reported of it.
    over: bool,
    /// The request expects a 100 (Continue) the connection has not written (RFC 9110 §10.1.1,
    /// `quic_continue.zig`).
    continue_owed: bool,
    /// The response's frames and the runs of the caller's octets, until the peer acknowledges
    /// them.
    response: quic_response.Pieces,
    /// What the request asked of the codings the server applies, and the coded response, whose
    /// runs are its encoder's ring (decision 101). The connection sets `asked.method` whether or
    /// not it codes content, because `write_body` drops the content of a response to HEAD.
    asked: coding_rules.Asked,
    coded: ?coding_response.Coded,
};

pub const Requests = struct {
    /// The records in use, and the stream of each, apart from the records: each record holds its
    /// response's kept frames, more than 8 KiB, and a walk that read a flag in each would touch
    /// every record after each datagram (design §8 step 29d.4).
    held: Held,
    /// The records whose response a call of the caller's changed since the last settle, which a
    /// `receive` at the instant the connection settled at settles alone (design §8 step 29d.7).
    changed: Held,
    stream_ids: [constants.limits.quic_requests_max]u64,
    records: [constants.limits.quic_requests_max]Request,

    pub const Held = std.StaticBitSet(constants.limits.quic_requests_max);

    pub fn init(requests: *Requests) void {
        requests.held = .initEmpty();
        requests.changed = .initEmpty();
    }

    /// A record for the request on `stream_id`, or null when every record is in use.
    pub fn take(requests: *Requests, stream_id: u64) ?*Request {
        assert(requests.of(stream_id) == null);
        const index = requests.held.complement().findFirstSet() orelse return null;
        requests.held.set(index);
        requests.stream_ids[index] = stream_id;
        const record = &requests.records[index];
        make_record(record, stream_id);
        record.response.init();
        return record;
    }

    /// Frees `record` for a later request.
    pub fn free(requests: *Requests, record: *const Request) void {
        const index = requests.index_of(record);
        assert(requests.held.isSet(index));
        requests.held.unset(index);
    }

    /// Notes that a call of the caller's changed the response of `record`.
    pub fn mark(requests: *Requests, record: *const Request) void {
        const index = requests.index_of(record);
        assert(requests.held.isSet(index));
        requests.changed.set(index);
    }

    /// Whether `record` is in use.
    pub fn holds(requests: *const Requests, record: *const Request) bool {
        return requests.held.isSet(requests.index_of(record));
    }

    /// The records in use, in the order of their places. Each `next` reads the bit set alone, and
    /// a record freed during the walk is not visited again.
    pub fn walk(requests: *Requests) Walk {
        return .{ .requests = requests, .rest = requests.held };
    }

    pub const Walk = struct {
        requests: *Requests,
        rest: Held,

        pub fn next(walk_state: *Walk) ?*Request {
            const index = walk_state.rest.findFirstSet() orelse return null;
            walk_state.rest.unset(index);
            return &walk_state.requests.records[index];
        }
    };

    /// Writes a fresh record for the request on `stream_id` and leaves its response pieces as
    /// they are. ReleaseSafe fills a field written as `undefined` with 0xAA, which for
    /// `quic_response.Pieces` is its 8 KiB of kept frames and its run table on every request.
    /// Runtime safety is off in this function alone, at the owner's ruling of 2026-10-26.
    /// `Pieces.init` then writes every field a read reaches, which `quic_response.zig`'s tests
    /// hold: pieces read the same whatever their storage held before.
    fn make_record(record: *Request, stream_id: u64) void {
        @setRuntimeSafety(false);
        record.* = .{
            .stream_id = stream_id,
            .ended = false,
            .answered = false,
            .finished = false,
            .over = false,
            .continue_owed = false,
            .response = undefined,
            .asked = .{},
            .coded = null,
        };
    }

    /// The record of the request on `stream_id`, or null.
    pub fn of(requests: *Requests, stream_id: u64) ?*Request {
        var held = requests.held.iterator(.{});
        // Bounded by the records.
        while (held.next()) |index| {
            if (requests.stream_ids[index] == stream_id) return &requests.records[index];
        }
        return null;
    }

    /// Whether no request is held.
    pub fn idle(requests: *const Requests) bool {
        return requests.held.count() == 0;
    }

    /// Where `record` sits among the records, which the tables kept beside them are indexed by.
    pub fn index_of(requests: *const Requests, record: *const Request) usize {
        const index = (@intFromPtr(record) - @intFromPtr(&requests.records[0])) / @sizeOf(Request);
        assert(index < requests.records.len and record == &requests.records[index]);
        return index;
    }

    /// Whether the caller still hears of any request: one whose head arrived and which is not
    /// over. A record that is over only waits for its stream to close.
    pub fn any_open(requests: *const Requests) bool {
        var held = requests.held.iterator(.{});
        // Bounded by the records.
        while (held.next()) |index| {
            if (!requests.records[index].over) return true;
        }
        return false;
    }
};

/// An event the connection owes the caller for a request that ended: its response is done, or it
/// was cancelled.
pub const Ending = struct {
    kind: union(enum) { done, cancelled: event.CancelReason },
    id: Number,
};

/// The events owed, oldest first. Each request owes one at most, so the ring has room for every
/// request the connection holds.
pub const Owed = struct {
    endings: [constants.limits.quic_requests_max]Ending = undefined,
    first: usize = 0,
    len: usize = 0,

    pub fn push(owed: *Owed, ending: Ending) void {
        assert(owed.len < owed.endings.len);
        owed.endings[(owed.first + owed.len) % owed.endings.len] = ending;
        owed.len += 1;
    }

    /// The oldest event owed, as the caller reads it, or null.
    pub fn take(owed: *Owed) ?event.ConnectionEvent {
        if (owed.len == 0) return null;
        const ending = owed.endings[owed.first];
        owed.first = (owed.first + 1) % owed.endings.len;
        owed.len -= 1;
        return switch (ending.kind) {
            .done => .{ .done = .{ .id = event.id_of(ending.id) } },
            .cancelled => |reason| .{ .cancelled = .{ .id = event.id_of(ending.id), .reason = reason } },
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
    for (0..constants.limits.quic_requests_max) |index| {
        const stream_id: u64 = index * 4;
        try testing.expectEqual(stream_id, requests.take(stream_id).?.stream_id);
    }
    try testing.expectEqual(null, requests.take(constants.limits.quic_requests_max * 4));
    const second = requests.of(4).?;
    try testing.expect(requests.holds(second));
    requests.free(second);
    try testing.expect(!requests.holds(second));
    try testing.expectEqual(null, requests.of(4));
    try testing.expect(requests.take(1000) != null);
    try testing.expect(!requests.idle());
    try testing.expectEqual(1, requests.index_of(requests.of(1000).?));
}

test "decision 103: the endings owed come out in order, as the events the caller reads" {
    var owed: Owed = .{};
    try testing.expectEqual(null, owed.take());
    owed.push(.{ .kind = .done, .id = 8 });
    owed.push(.{ .kind = .{ .cancelled = .{ .timeout = .body } }, .id = 4 });
    try testing.expectEqual(8, owed.take().?.done.id.number);
    const cancelled = owed.take().?.cancelled;
    try testing.expectEqual(4, cancelled.id.number);
    try testing.expectEqual(deadline.Timeout.body, cancelled.reason.timeout);
    try testing.expectEqual(null, owed.take());
    // A ring that starts partway round wraps past its end.
    for (0..constants.limits.quic_requests_max) |index| owed.push(.{ .kind = .done, .id = index });
    for (0..constants.limits.quic_requests_max) |index| try testing.expectEqual(index, owed.take().?.done.id.number);
}
