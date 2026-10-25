//! What the server of a QUIC test reported, kept past the call that reported it: each event's
//! kind, its request, the word the program set for it, and a request's path, a body event's
//! length and end, or why a request was cancelled. Split off `quic_test_support.zig` for length.
//! Test-only.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");
const endpoint_support = @import("quic_endpoint_test_support.zig");

const Event = event.Event;

/// The kind of what the server reported. A request's `finished` counts as `done` when its
/// response was sent and as `cancelled` when it was not, so a test reads the two apart.
pub const Kind = enum { request, body, trailers, cancelled, done, writable, send, close, ended, closed };

fn kind_of(reported: Event) Kind {
    return switch (reported) {
        .finished => |finished| switch (finished.result) {
            .sent => .done,
            .cancelled => .cancelled,
        },
        inline else => |_, tag| @field(Kind, @tagName(tag)),
    };
}

/// The event the endpoint would report for what a connection reported: its `done` and its
/// `cancelled` as `finished` (decision 126).
pub fn as_event(reported: event.ConnectionEvent) Event {
    return switch (reported) {
        .request => |head| .{ .request = head },
        .body => |body| .{ .body = body },
        .trailers => |trailers| .{ .trailers = trailers },
        .done => |done| .{ .finished = .{ .id = done.id, .user_data = done.user_data, .result = .sent } },
        .cancelled => |cancelled| .{ .finished = .{ .id = cancelled.id, .user_data = cancelled.user_data, .result = .{ .cancelled = cancelled.reason } } },
    };
}

/// What the server reported, kept past the call that reported it: its kind, its request, and a
/// request's path, a body event's length and end, or why a request was cancelled.
pub const Seen = struct {
    kind: Kind,
    id: u64,
    /// The connection a request's id named, through an endpoint (decision 119).
    connection: event.ConnectionHandle = .{ .slot = 0, .generation = 0 },
    path: [path_len_max]u8 = undefined,
    path_len: usize = 0,
    /// A request's query, or none.
    query: [path_len_max]u8 = undefined,
    query_len: usize = 0,
    len: usize = 0,
    end: bool = false,
    reason: ?event.CancelReason = null,
    /// The word the event carried back (decision 119).
    user_data: usize = 0,

    pub fn path_of(entry: *const Seen) []const u8 {
        return entry.path[0..entry.path_len];
    }

    pub fn query_of(entry: *const Seen) []const u8 {
        return entry.query[0..entry.query_len];
    }
};
const path_len_max: usize = 256;
pub const seen_max: usize = 256;
pub var seen: [seen_max]Seen align(@alignOf(Seen)) = undefined;
pub var seen_len: usize = 0;

/// Keeps `reported`, and hands an event only the endpoint reports to `endpoint_support`.
pub fn keep(reported: Event) void {
    assert(seen_len < seen.len);
    const entry = &seen[seen_len];
    entry.* = .{ .kind = kind_of(reported), .id = 0 };
    switch (reported) {
        .request => |head| {
            entry.id = head.id.number;
            entry.connection = head.id.connection;
            const path = head.path orelse "";
            @memcpy(entry.path[0..path.len], path);
            entry.path_len = path.len;
            const query = head.query orelse "";
            @memcpy(entry.query[0..query.len], query);
            entry.query_len = query.len;
        },
        .body => |body| {
            entry.id = body.id.number;
            entry.user_data = body.user_data;
            entry.len = body.bytes.len;
            entry.end = body.end;
        },
        .trailers => |trailers| {
            entry.id = trailers.id.number;
            entry.user_data = trailers.user_data;
        },
        .finished => |finished| {
            entry.id = finished.id.number;
            entry.user_data = finished.user_data;
            if (finished.result == .cancelled) entry.reason = finished.result.cancelled;
        },
        .writable => |writable| {
            entry.id = writable.id.number;
            entry.user_data = writable.user_data;
        },
        .send, .close, .ended, .closed => endpoint_support.note(reported),
    }
    seen_len += 1;
}

/// The `n`th event of `kind` the server reported, or null.
pub fn nth(kind: Kind, n: usize) ?*const Seen {
    var count: usize = 0;
    for (seen[0..seen_len]) |*entry| {
        if (entry.kind != kind) continue;
        if (count == n) return entry;
        count += 1;
    }
    return null;
}
