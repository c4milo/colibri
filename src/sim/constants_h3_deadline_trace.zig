//! The limits of the h3 deadline trace run (design §8 step 20d), split off `constants.zig` because
//! a hand-written source file stays at or under 500 lines (CLAUDE.md). `constants.zig` exports
//! them as `h3_deadline_trace`.
const std = @import("std");
const assert = std.debug.assert;

/// Request streams a seed's client opens at most, the model's `N`, and the units of each request's
/// head, of its content and of each response, at most: the model's `HeadUnits`, `Content` and
/// `ResponseUnits`.
pub const requests_max: u32 = 3;
pub const head_units_max: u32 = 2;
pub const content_units_max: u32 = 2;
pub const response_units_max: u32 = 2;

/// The octets of one unit of a request's content, and of a response's content.
pub const content_unit_len: u32 = 16;
pub const response_unit_len: u32 = 8;

/// Actions one run draws, at least and at most, before the drain.
pub const actions_min: u32 = 32;
pub const actions_max: u32 = 96;

/// Actions of the drain after the last drawn one, at most: it delivers what is in flight, sends
/// what the client has left, writes what the application has left, and moves time on, until the
/// client reads the server's close.
pub const drain_actions_max: u32 = 256;

/// Datagrams one direction holds at once, at most, and the datagrams one side writes in one call
/// of the run at most.
pub const queue_len_max: u32 = 64;
pub const sends_per_call_max: u32 = 32;
/// The octets each side may write into one datagram: an Ethernet MTU, past RFC 9000 §14.1's 1,200.
pub const datagram_len: u32 = 1_500;

/// Events the server's connection, or the client's h3, reports in one call of the run at most.
pub const events_per_call_max: u32 = 64;

/// The model's states one run keeps, each differing from the one before: the first, and one after
/// each action.
pub const states_max: u32 = 1 + actions_max + drain_actions_max;

/// The instant the run starts at, in nanoseconds.
pub const start_ns: u64 = 1_000_000_000;

/// The server's limits, in seconds: decision 110's first-request deadline, and shorter idle, head,
/// body and drain deadlines, so a run reaches each in a few moves of time. The body rate is off:
/// the meter of all bodies together, which the model leaves out, would close the connection.
pub const first_request_seconds: u64 = 10;
pub const idle_seconds: u64 = 5;
pub const head_seconds: u64 = 3;
pub const body_seconds: u64 = 8;
pub const drain_seconds: u64 = 6;

/// The furthest one wait moves time, in seconds: past each of the run's deadlines, and far short
/// of QUIC's own idle timeout, which the model leaves out. With nothing due sooner, the run does
/// not wait.
pub const wait_seconds_max: u64 = 30;

/// The seeds `run_check` covers when its caller names none, which `sim --h3-deadline-trace-write`
/// writes for TLC, and the model's steps TLC may take between two logged states.
pub const written_seeds: u64 = 32;
pub const steps_between_max: u64 = 16;

/// Octets of the TLA+ module one seed's trace is written as: 1 MiB.
pub const module_len_max: u32 = 1_048_576;

comptime {
    assert(requests_max > 0 and head_units_max > 0 and response_units_max > 0);
    assert(actions_min <= actions_max);
    const deadlines = [_]u64{ first_request_seconds, idle_seconds, head_seconds, body_seconds, drain_seconds };
    for (deadlines) |seconds| assert(seconds < wait_seconds_max);
}
