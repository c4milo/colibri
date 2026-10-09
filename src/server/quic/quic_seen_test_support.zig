//! What the server's QUIC tests keep of the events the server reported, past the call that
//! reported each, so a test can read them after `pump`. Split out of `quic_test_support.zig`,
//! which re-exports `Seen` and `nth`, because a hand-written source file stays at or under 500
//! lines (CLAUDE.md). Test-only.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");

const Event = event.Event;

/// What the server reported: its kind, its request, and a request's path, a body event's length
/// and end, or why a request was cancelled.
pub const Seen = struct {
    kind: std.meta.Tag(Event),
    id: u64,
    path: [path_len_max]u8 = undefined,
    path_len: usize = 0,
    len: usize = 0,
    end: bool = false,
    reason: ?event.CancelReason = null,

    pub fn path_of(entry: *const Seen) []const u8 {
        return entry.path[0..entry.path_len];
    }
};
const path_len_max: usize = 256;
pub const seen_max: usize = 256;
pub var seen: [seen_max]Seen align(@alignOf(Seen)) = undefined;
pub var seen_len: usize = 0;

pub fn keep(reported: Event) void {
    assert(seen_len < seen.len);
    const entry = &seen[seen_len];
    entry.* = .{ .kind = reported, .id = 0 };
    switch (reported) {
        .request => |head| {
            entry.id = head.id;
            const path = head.path orelse "";
            @memcpy(entry.path[0..path.len], path);
            entry.path_len = path.len;
        },
        .body => |body| {
            entry.id = body.id;
            entry.len = body.octets.len;
            entry.end = body.end;
        },
        .trailers => |trailers| entry.id = trailers.id,
        .cancelled => |cancelled| {
            entry.id = cancelled.id;
            entry.reason = cancelled.reason;
        },
        .done => |done| entry.id = done.id,
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
