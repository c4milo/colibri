//! What the server of a QUIC test reported, kept past the call that reported it: each event's
//! kind, its request, the word the program set for it, and a request's path, a body event's
//! length and end, or why a request was cancelled. Split off `quic_test_support.zig` for length.
//! Test-only.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");
const endpoint_support = @import("quic_endpoint_test_support.zig");

const Event = event.Event;

/// What the server reported, kept past the call that reported it: its kind, its request, and a
/// request's path, a body event's length and end, or why a request was cancelled.
pub const Seen = struct {
    kind: std.meta.Tag(Event),
    id: u64,
    /// The connection a request's id named, through an endpoint (decision 119).
    connection: event.ConnectionHandle = .{ .slot = 0, .generation = 0 },
    path: [path_len_max]u8 = undefined,
    path_len: usize = 0,
    len: usize = 0,
    end: bool = false,
    reason: ?event.CancelReason = null,
    /// The word the event carried back (decision 119).
    user_data: usize = 0,

    pub fn path_of(entry: *const Seen) []const u8 {
        return entry.path[0..entry.path_len];
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
    entry.* = .{ .kind = reported, .id = 0 };
    switch (reported) {
        .request => |head| {
            entry.id = head.id.number;
            entry.connection = head.id.connection;
            const path = head.path orelse "";
            @memcpy(entry.path[0..path.len], path);
            entry.path_len = path.len;
        },
        .body => |body| {
            entry.id = body.id.number;
            entry.user_data = body.user_data;
            entry.len = body.octets.len;
            entry.end = body.end;
        },
        .trailers => |trailers| {
            entry.id = trailers.id.number;
            entry.user_data = trailers.user_data;
        },
        .cancelled => |cancelled| {
            entry.id = cancelled.id.number;
            entry.user_data = cancelled.user_data;
            entry.reason = cancelled.reason;
        },
        .done => |done| {
            entry.id = done.id.number;
            entry.user_data = done.user_data;
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
pub fn nth(kind: std.meta.Tag(Event), n: usize) ?*const Seen {
    var count: usize = 0;
    for (seen[0..seen_len]) |*entry| {
        if (entry.kind != kind) continue;
        if (count == n) return entry;
        count += 1;
    }
    return null;
}
