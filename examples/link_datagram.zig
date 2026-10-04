//! The link the QUIC examples run over, in place of the UDP sockets a program would use. It is not
//! part of colibri, and a real program replaces it with its own sockets.
//!
//! It runs on the loops of `link.zig`: each side on its own rotor loop, in one process and on one
//! thread. Where `Link` moves a stream of octets, this one moves datagrams. What one side sends is
//! copied whole into the other side's queue, and each datagram comes out as it went in. No socket
//! is opened (decision 96).
//!
//! QUIC runs on timers as well as datagrams. `wait` ticks a side's loop until a duration passes,
//! which is how a side with nothing to read sleeps until its next deadline.
const std = @import("std");
const assert = std.debug.assert;
const link = @import("link.zig");

pub const Side = link.Side;
pub const Error = link.Error;

/// Octets of one datagram, at most: what one Ethernet frame carries.
pub const datagram_len_max = 1500;

/// Datagrams waiting in one side's queue, at most.
pub const datagrams_max = 32;

const side_count = std.meta.fields(Side).len;

/// One side's queue: a ring of datagrams, oldest first.
const Queue = struct {
    datagrams: [datagrams_max][datagram_len_max]u8,
    lens: [datagrams_max]usize,
    /// The index of the oldest datagram, and how many wait.
    first: usize,
    count: usize,
};

pub const DatagramLink = struct {
    loops: link.Loops,
    queues: [side_count]Queue,

    /// Starts both loops. The link lives outside the stack: it holds both queues.
    pub fn init(self: *DatagramLink) Error!void {
        try self.loops.init();
        for (&self.queues) |*queue| {
            queue.first = 0;
            queue.count = 0;
        }
    }

    pub fn deinit(self: *DatagramLink) void {
        self.loops.deinit();
    }

    /// Copies `datagram` into the other side's queue and posts it a message saying it arrived.
    pub fn send(self: *DatagramLink, from: Side, datagram: []const u8) Error!void {
        assert(datagram.len > 0 and datagram.len <= datagram_len_max);
        const queue = &self.queues[@intFromEnum(from.other())];
        if (queue.count == datagrams_max) return error.QueueFull;
        const index = (queue.first + queue.count) % datagrams_max;
        @memcpy(queue.datagrams[index][0..datagram.len], datagram);
        queue.lens[index] = datagram.len;
        queue.count += 1;
        try self.loops.notify(from, datagram.len);
    }

    /// Ticks `side`'s loop once, and returns the oldest datagram waiting for it, or null. The
    /// side hands it to colibri, then calls `consume`. The octets are the side's to change: QUIC
    /// opens each packet in place.
    pub fn receive(self: *DatagramLink, side: Side) Error!?[]u8 {
        try self.loops.tick(side, 0);
        const queue = &self.queues[@intFromEnum(side)];
        if (queue.count == 0) return null;
        return queue.datagrams[queue.first][0..queue.lens[queue.first]];
    }

    /// Drops the datagram `receive` returned, which colibri took.
    pub fn consume(self: *DatagramLink, side: Side) void {
        const queue = &self.queues[@intFromEnum(side)];
        assert(queue.count > 0);
        queue.first = (queue.first + 1) % datagrams_max;
        queue.count -= 1;
    }

    /// Whether a datagram waits for either side.
    pub fn pending(self: *const DatagramLink) bool {
        for (&self.queues) |*queue| {
            if (queue.count > 0) return true;
        }
        return false;
    }

    /// Waits on `side`'s loop until `wait_ns` nanoseconds pass. Both loops run on this thread, so
    /// the time passes for both sides.
    pub fn wait(self: *DatagramLink, side: Side, wait_ns: u64) Error!void {
        try self.loops.tick(side, wait_ns);
    }

    /// The instant `side`'s loop read at its last tick, which is what colibri is given.
    pub fn now_ns(self: *const DatagramLink, side: Side) u64 {
        return self.loops.now_ns(side);
    }
};
