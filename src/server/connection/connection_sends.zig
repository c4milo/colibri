//! The send deadlines of a server connection over TCP (decision 110, design §8 step 20b).
//!
//! While the connection holds octets its peer has not taken, the peer must take the minimum send
//! rate over each window: the connection's meter counts what `send` hands out. In h2 a stream
//! whose response waits on a flow-control window has a meter of its own, which counts what the
//! window lets through. It runs only while the connection holds nothing else to send, since a
//! peer that reads slowly holds every stream up and the connection's meter judges that; so a
//! client that opens a window only once it has read what fills it is not judged by the window.
//!
//! A stream the peer's window holds too long is reset with CANCEL, and the caller reads
//! `cancelled`; when the connection's own window is the one that holds it, the connection ends
//! with ENHANCE_YOUR_CALM instead, as a connection whose peer takes too little does.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const deadline = @import("../deadline.zig");
const rate = @import("../rate.zig");
const connection_module = @import("connection.zig");
const connection_bodies = @import("connection_bodies.zig");
const connection_coding = @import("connection_coding.zig");

const Connection = connection_module.Connection;
const Number = event.Number;
const Timeout = deadline.Timeout;

/// One h2 stream whose response waits on a window.
const Blocked = struct {
    /// The request, or 0 for a free entry.
    id: Number = 0,
    /// Whether the connection's window held the last write, rather than the stream's.
    connection_window: bool = false,
    meter: rate.Meter = .{},
};

pub const Sends = struct {
    /// What the peer took of the connection's octets.
    meter: rate.Meter,
    /// Only the first `written` entries hold what a stream wrote. `init` writes none of them, and
    /// a held stream writes the next entry whole when no freed entry is left, as a body does.
    entries: [constants.bodies_max]Blocked,
    /// The count of entries written since `init`.
    written: u32,
    /// The entries in use: those whose `id` is not 0. While it is 0 a lookup or a sweep reads no
    /// entry, which is how most calls find the table: `receive` observes the deadlines after every
    /// event it reads, and fires them at the first call at each instant.
    used: u32,

    pub fn init(sends: *Sends) void {
        sends.meter = .{};
        sends.written = 0;
        sends.used = 0;
    }

    fn find(sends: *Sends, id: Number) ?*Blocked {
        assert(id != 0);
        assert(sends.used <= sends.entries.len);
        // A response no window holds has no entry, so most calls find the table empty.
        if (sends.used == 0) return null;
        return sends.find_id(id);
    }

    /// A free entry, which the call takes for a stream. It is an entry that a stream left, or
    /// else the first entry not written yet, which the call writes whole. h2 holds
    /// `concurrent_streams_max` streams, and the table one entry for each.
    fn take_free(sends: *Sends) *Blocked {
        assert(sends.used < sends.entries.len);
        const free = sends.find_id(0) orelse sends.write_next();
        sends.used += 1;
        return free;
    }

    /// The first entry never written, written now with no stream.
    fn write_next(sends: *Sends) *Blocked {
        assert(sends.written < sends.entries.len);
        sends.entries[sends.written] = .{};
        sends.written += 1;
        return &sends.entries[sends.written - 1];
    }

    fn find_id(sends: *Sends, id: Number) ?*Blocked {
        for (sends.written_entries()) |*blocked| {
            if (blocked.id == id) return blocked;
        }
        return null;
    }

    /// The entries written since `init`. Every scan reads these entries and no other.
    fn written_entries(sends: *Sends) []Blocked {
        assert(sends.used <= sends.written and sends.written <= sends.entries.len);
        return sends.entries[0..sends.written];
    }
};

/// Notes an h2 write to request `id` that was offered `offered` octets: what the window let
/// through, and whether a window held it short.
pub fn on_write(connection: *Connection, id: Number, offered: usize, sent: h2.connection.DataWritten) void {
    assert(id != 0);
    const sends = &connection.sends;
    const found = sends.find(id);
    if (found) |blocked| blocked.meter.count(sent.consumed);
    const held = sent.short_by == .stream_window or sent.short_by == .connection_window;
    if (held and sent.consumed < offered) {
        const blocked = found orelse sends.take_free();
        blocked.id = id;
        blocked.connection_window = sent.short_by == .connection_window;
        return;
    }
    // The window let the write through, so the stream waits on it no more.
    if (sent.consumed > 0 or sent.short_by == .none) remove(connection, id);
}

/// Request `id`'s response ended, or the request did.
pub fn remove(connection: *Connection, id: Number) void {
    const sends = &connection.sends;
    const blocked = sends.find(id) orelse return;
    blocked.* = .{};
    assert(sends.used > 0);
    sends.used -= 1;
}

/// Starts or stops each meter as the connection's output holds octets or not, at `now_ns`.
pub fn observe(connection: *Connection, now_ns: u64) void {
    const sends = &connection.sends;
    const limits = &connection.deadlines;
    const holding = connection.output_len > 0;
    start_or_stop(&sends.meter, holding, now_ns, limits);
    if (sends.used == 0) return;
    for (sends.written_entries()) |*blocked| {
        if (blocked.id == 0) continue;
        start_or_stop(&blocked.meter, !holding, now_ns, limits);
    }
}

/// Starts `meter` at `now_ns` when it `runs` and is stopped, and stops it when it does not: a
/// pause, after which it starts again with a grace period.
pub fn start_or_stop(meter: *rate.Meter, runs: bool, now_ns: u64, limits: *const deadline.Timeouts) void {
    if (!runs) return meter.stop();
    if (!meter.running()) meter.start(now_ns, limits.rate_grace_ns, limits.rate_window_ns);
}

/// Counts the octets `send` handed out, which the connection's meter judges.
pub fn count(connection: *Connection, written: usize) void {
    connection.sends.meter.count(written);
}

/// The soonest instant a send deadline passes, or `current` when it is sooner or none does.
pub fn soonest(connection: *const Connection, current: ?u64) ?u64 {
    const sends = &connection.sends;
    const quota = connection.deadlines.send_quota() orelse return current;
    const window_ns = connection.deadlines.rate_window_ns;
    var at = current;
    if (sends.meter.check_ns(quota, window_ns)) |check_ns| at = @min(at orelse check_ns, check_ns);
    if (sends.used == 0) return at;
    for (sends.entries[0..sends.written]) |*blocked| {
        const check_ns = blocked.meter.check_ns(quota, window_ns) orelse continue;
        at = @min(at orelse check_ns, check_ns);
    }
    return at;
}

/// Resets each h2 stream whose window held it under the rate at `now_ns`, and returns
/// `send_rate` when the connection ends for it: its peer took too little, or the connection's
/// own window held a stream.
pub fn fire(connection: *Connection, now_ns: u64) ?Timeout {
    const sends = &connection.sends;
    const quota = connection.deadlines.send_quota() orelse return null;
    const window_ns = connection.deadlines.rate_window_ns;
    if (sends.meter.short(now_ns, quota, window_ns)) return .send_rate;
    if (sends.used == 0) return null;
    for (sends.written_entries()) |*blocked| {
        if (!blocked.meter.short(now_ns, quota, window_ns)) continue;
        if (blocked.connection_window) return .send_rate;
        cancel_stream(connection, blocked.id);
    }
    return null;
}

/// RFC 9113 §6.4: CANCEL says the stream is no longer needed; the caller reads `cancelled`.
fn cancel_stream(connection: *Connection, id: Number) void {
    connection.session.h2.reset_stream(@intCast(id), h2.constants.error_cancel) catch |failure| {
        assert(failure == error.StreamNotSendable);
    };
    connection_coding.forget(connection, id);
    connection_bodies.remove(connection, id);
    remove(connection, id);
    connection_bodies.owe_cancelled(connection, .{ .id = id, .reason = .{ .timeout = .send_rate } });
}

/// Starts the linger of a connection that has ended with octets still to send, at `now_ns`, and
/// ends it once `linger_ns` has passed: the connection then closes, octets or not.
pub fn linger(connection: *Connection, now_ns: u64) void {
    const clock = &connection.clock;
    if (clock.lingered) return;
    const limit_ns = connection.deadlines.linger_ns orelse return;
    const since_ns = clock.linger_since_ns orelse return;
    // Decision 110: a close is bounded, so a peer that reads nothing cannot hold it open.
    if (now_ns >= since_ns + limit_ns) clock.lingered = true;
}
