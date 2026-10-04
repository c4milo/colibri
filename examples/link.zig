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

/// Both sides' loops and the registry they share. `Link` holds one, and so does the
/// `DatagramLink` of `link_datagram.zig`.
pub const Loops = struct {
    registry_memory: [rotor.Registry.memory_bytes(side_count)]u8 align(rotor.memory_alignment),
    registry: rotor.Registry,
    loop_memory: [side_count]LoopMemory,
    loops: [side_count]rotor.Loop,

    /// Starts both loops, and ticks each once, so that `now_ns` holds an instant its loop read
    /// before a connection starts: a connection's deadlines count from the instant it is given.
    pub fn init(loops: *Loops) Error!void {
        loops.registry.init(&loops.registry_memory, side_count);
        for (0..side_count) |index| {
            var options = loop_options;
            options.id = @intCast(index);
            options.registry = &loops.registry;
            try loops.loops[index].init(&loops.loop_memory[index].bytes, options);
        }
        for (std.enums.values(Side)) |side| try loops.tick(side, 0);
    }

    pub fn deinit(loops: *Loops) void {
        for (&loops.loops) |*loop| loop.deinit();
    }

    /// Posts the other side's loop a message saying `len` octets arrived for it, and ticks the
    /// sender's loop until the post's final event arrives.
    pub fn notify(loops: *Loops, from: Side, len: usize) Error!void {
        const loop = &loops.loops[@intFromEnum(from)];
        const to: rotor.LoopId = @intFromEnum(from.other());
        const post = rotor.Operation.post(post_user_data, to, .{
            .payload = len,
            .tag = tag_octets,
        });
        const taken = loop.submit(&.{post}, &.{});
        assert(taken == 1);
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

    /// Ticks `side`'s loop once, which delivers the messages posted to it. With `wait_ns` of 0 the
    /// tick does not wait: both loops run on this thread, so a message posted to this one is
    /// already in its mailbox. A longer wait is how a side sleeps until its next deadline.
    pub fn tick(loops: *Loops, side: Side, wait_ns: u64) Error!void {
        var events: [tick_events_max]rotor.Event = undefined;
        const count = try loops.loops[@intFromEnum(side)].tick(&events, wait_ns);
        for (events[0..count]) |event| assert(event.flags.message and event.result == tag_octets);
    }

    /// The instant `side`'s loop read at its last tick, which is what colibri is given.
    pub fn now_ns(loops: *const Loops, side: Side) u64 {
        return loops.loops[@intFromEnum(side)].now_ns();
    }
};

pub const Link = struct {
    loops: Loops,
    queues: [side_count][queue_len_max]u8,
    queue_lens: [side_count]usize,

    /// Starts both loops. `link` lives outside the stack: it holds both queues.
    pub fn init(link: *Link) Error!void {
        try link.loops.init();
        link.queue_lens = @splat(0);
    }

    pub fn deinit(link: *Link) void {
        link.loops.deinit();
    }

    /// Copies `octets` into the other side's queue and posts it a message saying they arrived.
    pub fn send(link: *Link, from: Side, octets: []const u8) Error!void {
        if (octets.len == 0) return;
        const to = from.other();
        const queue_len = &link.queue_lens[@intFromEnum(to)];
        if (queue_len.* + octets.len > queue_len_max) return error.QueueFull;
        @memcpy(link.queues[@intFromEnum(to)][queue_len.*..][0..octets.len], octets);
        queue_len.* += octets.len;
        try link.loops.notify(from, octets.len);
    }

    /// Ticks `side`'s loop once, and returns every octet waiting for it. The side hands them to
    /// colibri, then calls `consume` with how many colibri took. The octets are the side's to
    /// change: over TLS, colibri opens each record in place.
    pub fn receive(link: *Link, side: Side) Error![]u8 {
        try link.loops.tick(side, 0);
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

    /// Whether octets wait for either side.
    pub fn pending(link: *const Link) bool {
        for (link.queue_lens) |queue_len| {
            if (queue_len > 0) return true;
        }
        return false;
    }

    /// Waits on `side`'s loop until `wait_ns` nanoseconds pass, as a program waits on its socket
    /// until its next deadline. Both loops run on this thread, so the time passes for both sides.
    pub fn wait(link: *Link, side: Side, wait_ns: u64) Error!void {
        try link.loops.tick(side, wait_ns);
    }

    /// The instant `side`'s loop read at its last tick, which is what colibri is given.
    pub fn now_ns(link: *const Link, side: Side) u64 {
        return link.loops.now_ns(side);
    }
};
