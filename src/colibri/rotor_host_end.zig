//! The end of a run of colibri's own Rotor host (decision 159), whether the run finished or
//! failed. A run that failed leaves operations in flight and sockets open, so the end cancels what
//! is in flight, reads each final event, and frees the loop. The host's `close_open` then closes
//! each socket that is still open.
//!
//! On io_uring, a close the loop submitted is in flight, and `cancel_all` can cancel it before it
//! runs. Then the descriptor stays open. kqueue and epoll close at submit. The ticks stop after
//! `rotor.constants.drain_rounds_max`, as Rotor's own `drain` does, and `deinit` then halts.
const std = @import("std");
const rotor = @import("rotor");
const rotor_host = @import("rotor_host.zig");

/// Ends the run of `state`'s loop. See the header.
pub fn end(state: anytype) void {
    state.loop.cancel_all();
    for (0..rotor.constants.drain_rounds_max) |_| {
        if (state.loop.in_flight() == 0) break;
        const count = state.loop.tick(&state.events, rotor.constants.drain_wait_ns) catch break;
        for (state.events[0..count]) |event| on_last_event(state, event);
    }
    state.loop.deinit();
}

/// Reads one event of a run's last ticks. A close that ended canceled or timed out did not run
/// (Rotor's decision 5, rules 2 and 4), so `close_open` closes its socket. A close that failed
/// otherwise ran, and the system released the descriptor, so a second close could close another
/// descriptor with the same number. An accept that succeeded gave a socket that no driver holds,
/// so it closes here. Every other event changes nothing. A connect that succeeded, or the shutdown
/// of a write side, leaves its socket open, and `close_open` closes it.
pub fn on_last_event(state: anytype, event: rotor.Event) void {
    if (event.flags.message) return;
    const tagged = rotor_host.tag_of(event);
    switch (tagged.kind) {
        .accept => {
            const descriptor: rotor.Descriptor = @intCast(event.outcome() catch return);
            rotor.sync.close_now(descriptor);
        },
        .close => {
            _ = event.outcome() catch |failure| return state.close_ended(tagged.socket, failure);
            state.states[@intFromEnum(tagged.socket)] = .closed;
        },
        else => {},
    }
}
