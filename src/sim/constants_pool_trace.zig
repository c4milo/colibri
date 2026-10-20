//! The limits of the pool trace run (decision 105 as decision 125 extends it, design §8 step 22),
//! split off `constants.zig` because a hand-written source file stays at or under 500 lines
//! (CLAUDE.md). `constants.zig` exports them as `pool_trace`.
const std = @import("std");
const assert = std.debug.assert;

/// TCP slots a seed's pool holds, and exchanges its caller makes: the model's `TcpSlots` and `N`.
pub const slots_min: u32 = 2;
pub const slots_max: u32 = 3;
pub const exchanges_min: u32 = 2;
pub const exchanges_max: u32 = 4;

/// The instants the caller makes its exchanges in, and the most a cancel comes after its
/// exchange. One exchange in `cancel_one_in` is cancelled, and one in `post_one_in` is a POST.
pub const make_window: u32 = 4;
pub const cancel_after_max: u32 = 3;
pub const cancel_one_in: u64 = 5;
pub const post_one_in: u64 = 3;
/// The most instants the caller waits after its last exchange before it shuts the pool down.
pub const shutdown_after_max: u32 = 6;

/// One request in `break_one_in` meets a server that closes the connection before it answers, one
/// in `close_one_in` an answer that says `Connection: close` (RFC 9112 §9.6), and one slot in
/// `connect_fail_one_in` a first connect that fails.
pub const break_one_in: u64 = 5;
pub const close_one_in: u64 = 5;
pub const connect_fail_one_in: u64 = 3;

/// TCP slots the run's endpoint holds: twice the pool's, since a slot may open again before the
/// endpoint has ended the connection it held before.
pub const endpoint_slots: u32 = slots_max + slots_max;

/// Instants one run moves through at most, and events one side reports at most in one turn.
pub const instants_max: u32 = 256;
pub const turn_events_max: u32 = 64;
/// Octets each direction of a socket holds at most: a request head or a short response.
pub const pipe_len: u32 = 4096;
/// Octets of a response's content: "ok", which every body holds.
pub const body_len: u32 = 64;

/// The model's states one run keeps, each differing from the one before.
pub const states_max: u32 = 512;
/// The model's steps TLC may take between two logged states.
pub const steps_max: u32 = 16;
/// The seeds `--pool-trace-write` writes, and `--pool-trace-check` runs by default.
pub const written_seeds: u32 = 64;
/// Octets of one logged state at its longest, and of one seed's module and configuration
/// together: every state at its longest.
pub const state_len_max: u32 = 1024;
pub const module_len_max: u32 = states_max * state_len_max;

comptime {
    assert(slots_min > 1 and slots_max >= slots_min);
    assert(exchanges_min > 1 and exchanges_max >= exchanges_min);
    assert(make_window > 0 and instants_max > make_window + cancel_after_max + shutdown_after_max);
}
