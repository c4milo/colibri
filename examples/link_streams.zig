//! The link the pool example runs over, in place of the TCP sockets a program would use. It is not
//! part of colibri, and a real program replaces it with its own sockets.
//!
//! It runs on the loops of `link.zig`: each side on its own rotor loop, in one process and on one
//! thread. Where `Link` moves one stream of octets, this one moves `streams_max` of them, one for
//! each socket the client connects. What one side sends on a stream is copied into the other
//! side's queue of that stream, and the sending loop posts the other loop a message saying how
//! many octets arrived. No socket is opened (decision 96).
//!
//! A program reads every stream after each tick of its loop. `close` drops both queues of a
//! stream, as a socket's close drops what it held.
const std = @import("std");
const assert = std.debug.assert;
const link = @import("link.zig");

pub const Side = link.Side;
pub const Error = link.Error;
pub const Loops = link.Loops;

/// Streams the link carries, and octets waiting in one side's queue of a stream, at most.
pub const streams_max = 4;
pub const queue_len_max = link.queue_len_max;

const side_count = std.meta.fields(Side).len;

/// One stream's queues, one for each side, and how many octets wait in each.
const Stream = struct {
    queues: [side_count][queue_len_max]u8,
    queue_lens: [side_count]usize,
};

pub const StreamsLink = struct {
    loops: Loops,
    streams: [streams_max]Stream,

    /// Starts both loops. The link lives outside the stack: it holds every queue.
    pub fn init(self: *StreamsLink) Error!void {
        try self.loops.init();
        for (&self.streams) |*stream| stream.queue_lens = @splat(0);
    }

    pub fn deinit(self: *StreamsLink) void {
        self.loops.deinit();
    }

    /// Copies `octets` into the other side's queue of `stream`, and posts it a message saying they
    /// arrived.
    pub fn send(self: *StreamsLink, stream: usize, from: Side, octets: []const u8) Error!void {
        if (octets.len == 0) return;
        const to = @intFromEnum(from.other());
        const held = &self.streams[stream];
        if (held.queue_lens[to] + octets.len > queue_len_max) return error.QueueFull;
        @memcpy(held.queues[to][held.queue_lens[to]..][0..octets.len], octets);
        held.queue_lens[to] += octets.len;
        try self.loops.notify(from, octets.len);
    }

    /// Ticks `side`'s loop once, which delivers the messages posted to it. The side then reads
    /// each stream's queue with `queue`.
    pub fn receive(self: *StreamsLink, side: Side) Error!void {
        try self.loops.tick(side, 0);
    }

    /// Every octet waiting for `side` on `stream`. The side hands them to colibri, then calls
    /// `consume` with how many colibri took. The octets are the side's to change.
    pub fn queue(self: *StreamsLink, stream: usize, side: Side) []u8 {
        const held = &self.streams[stream];
        return held.queues[@intFromEnum(side)][0..held.queue_lens[@intFromEnum(side)]];
    }

    /// Drops the first `len` octets of `side`'s queue of `stream`, which colibri consumed.
    pub fn consume(self: *StreamsLink, stream: usize, side: Side, len: usize) void {
        const held = &self.streams[stream];
        const queue_len = &held.queue_lens[@intFromEnum(side)];
        assert(len <= queue_len.*);
        const octets = &held.queues[@intFromEnum(side)];
        std.mem.copyForwards(u8, octets[0 .. queue_len.* - len], octets[len..queue_len.*]);
        queue_len.* -= len;
    }

    /// Drops what both queues of `stream` hold, as the close of a socket drops what it held.
    pub fn close(self: *StreamsLink, stream: usize) void {
        self.streams[stream].queue_lens = @splat(0);
    }

    /// Whether octets wait for either side on any stream.
    pub fn pending(self: *const StreamsLink) bool {
        for (&self.streams) |*stream| {
            for (stream.queue_lens) |queue_len| {
                if (queue_len > 0) return true;
            }
        }
        return false;
    }

    /// Waits on `side`'s loop until `wait_ns` nanoseconds pass, as a program waits on its sockets
    /// until its next deadline. Both loops run on this thread, so the time passes for both sides.
    pub fn wait(self: *StreamsLink, side: Side, wait_ns: u64) Error!void {
        try self.loops.tick(side, wait_ns);
    }

    /// The instant `side`'s loop read at its last tick, which is what colibri is given.
    pub fn now_ns(self: *const StreamsLink, side: Side) u64 {
        return self.loops.now_ns(side);
    }
};
