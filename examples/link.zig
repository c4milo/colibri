//! The link the examples run over, in place of the sockets a program would use. It is not part of
//! colibri, and a real program replaces it with its own sockets.
//!
//! Each side of an exchange runs on its own rotor loop (https://github.com/c4milo/rotor), in one
//! process and on one thread. What one side sends is copied into the other side's inbound queue in
//! memory, and the sending loop posts the receiving loop a message saying how many octets arrived.
//! The receiving side's next tick delivers that message, and the side then reads its queue. No
//! socket is opened: colibri's rules keep sockets to `src/testing/` (decision 96).
//!
//! colibri never sees the loops. It takes the octets a side read and returns the octets it owes,
//! and the instant it needs is the one the side's loop read at its last tick.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");

/// The two ends of the link. The value is the side's loop id in the registry they share.
pub const Side = enum(rotor.LoopId) {
    client = 0,
    server = 1,

    pub fn other(side: Side) Side {
        return if (side == .client) .server else .client;
    }
};

/// Octets waiting in one side's inbound queue, at most.
pub const queue_len_max = 64 * 1024;

pub const Error = rotor.Loop.InitError || rotor.Loop.TickError || error{
    /// The other side has not read enough of its queue to take these octets.
    QueueFull,
    /// A post came back refused: the other loop's mailbox was full or the loop was gone.
    PostRefused,
};

const side_count = std.meta.fields(Side).len;

/// Operations in flight on one loop: a post, at most.
const operations_max = 4;

/// Events one tick returns, at most.
const tick_events_max = 16;

/// The tag of the message that says octets arrived. Its payload is how many.
const tag_octets: u32 = 1;

/// The user data of a post, which comes back in the post's own final event.
const post_user_data: u64 = 1;

/// Ticks a sender makes for its post's final event, at most.
const post_ticks_max = 8;

const loop_options: rotor.Loop.Options = .{ .operations = operations_max };

/// One loop's memory, at Rotor's alignment on its own. An array of byte arrays aligns only the
/// first: a loop takes 1,456 octets on Linux, which is not a multiple of 64.
const LoopMemory = struct {
    bytes: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment),
};

pub const Link = struct {
    registry_memory: [rotor.Registry.memory_bytes(side_count)]u8 align(rotor.memory_alignment),
    registry: rotor.Registry,
    loop_memory: [side_count]LoopMemory,
    loops: [side_count]rotor.Loop,
    queues: [side_count][queue_len_max]u8,
    queue_lens: [side_count]usize,

    /// Starts both loops. `link` lives outside the stack: it holds both queues.
    pub fn init(link: *Link) Error!void {
        link.registry.init(&link.registry_memory, side_count);
        for (0..side_count) |index| {
            var options = loop_options;
            options.id = @intCast(index);
            options.registry = &link.registry;
            try link.loops[index].init(&link.loop_memory[index].bytes, options);
        }
        link.queue_lens = @splat(0);
    }

    pub fn deinit(link: *Link) void {
        for (&link.loops) |*loop| loop.deinit();
    }

    /// Copies `octets` into the other side's queue and posts it a message saying they arrived.
    pub fn send(link: *Link, from: Side, octets: []const u8) Error!void {
        if (octets.len == 0) return;
        const to = from.other();
        const queue_len = &link.queue_lens[@intFromEnum(to)];
        if (queue_len.* + octets.len > queue_len_max) return error.QueueFull;
        @memcpy(link.queues[@intFromEnum(to)][queue_len.*..][0..octets.len], octets);
        queue_len.* += octets.len;
        const loop = &link.loops[@intFromEnum(from)];
        const post = rotor.Operation.post(post_user_data, @intFromEnum(to), .{ .payload = octets.len, .tag = tag_octets });
        const taken = loop.submit(&.{post}, &.{});
        assert(taken == 1);
        try await_post(loop);
    }

    /// Ticks the sender's loop until its post's final event arrives.
    fn await_post(loop: *rotor.Loop) Error!void {
        var events: [tick_events_max]rotor.Event = undefined;
        for (0..post_ticks_max) |_| {
            const count = try loop.tick(&events, 0);
            for (events[0..count]) |event| {
                if (event.flags.message or event.user_data != post_user_data) continue;
                _ = event.outcome() catch return error.PostRefused;
                return;
            }
        }
        return error.PostRefused;
    }

    /// Ticks `side`'s loop once, and returns every octet waiting for it. The side hands them to
    /// colibri, then calls `consume` with how many colibri took.
    pub fn receive(link: *Link, side: Side) Error![]const u8 {
        var events: [tick_events_max]rotor.Event = undefined;
        // Both loops run on this thread, so a message posted to this one is already in its
        // mailbox, and a tick that does not wait delivers it.
        const count = try link.loops[@intFromEnum(side)].tick(&events, 0);
        for (events[0..count]) |event| assert(event.flags.message and event.result == tag_octets);
        return link.queues[@intFromEnum(side)][0..link.queue_lens[@intFromEnum(side)]];
    }

    /// Drops the first `len` octets of `side`'s queue, which colibri consumed.
    pub fn consume(link: *Link, side: Side, len: usize) void {
        const queue = &link.queues[@intFromEnum(side)];
        const queue_len = &link.queue_lens[@intFromEnum(side)];
        assert(len <= queue_len.*);
        std.mem.copyForwards(u8, queue[0 .. queue_len.* - len], queue[len..queue_len.*]);
        queue_len.* -= len;
    }

    /// The instant `side`'s loop read at its last tick, which is what colibri is given.
    pub fn now_ns(link: *const Link, side: Side) u64 {
        return link.loops[@intFromEnum(side)].now_ns();
    }
};
