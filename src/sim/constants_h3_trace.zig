//! The limits of the h3 trace run (https://github.com/c4milo/colibri/issues/58), split off
//! `constants.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `constants.zig` exports them as `h3_trace`.

/// The h3 trace run (https://github.com/c4milo/colibri/issues/58), inside the scope of
/// `spec/tla/h3_connection`: the requests one seed opens, the DATA frames each carries, the GOAWAY
/// frames the server sends, and the server decoder's blocked-stream limit and table capacity. The
/// client opens, cancels and the server shuts down within `act_steps` steps, and one request in
/// `cancel_one_in` is cancelled. Each DATA frame carries `data_len` octets.
pub const requests_max: u32 = 3;
pub const content_max: u32 = 2;
pub const goaways_max: u32 = 2;
pub const blocked_max: u64 = 2;
pub const capacity: u64 = 256;
pub const act_steps: u64 = 16;
pub const cancel_one_in: u64 = 3;
pub const data_len: u32 = 4;
/// The frames the trace run keeps for one message, the steps one run may take, and the highest
/// drop and duplicate rates a seed draws, out of `schedule_denominator`.
pub const prefix_len_max: u32 = 2048;
pub const steps_max: u32 = 10_000;
pub const drop_max: u64 = 50;
pub const duplicate_max: u64 = 50;
/// The model's states one trace run keeps, each one differing from the last, and the octets of
/// the TLA+ module one seed's trace is written as: 1 MiB.
pub const states_max: u32 = 1024;
pub const module_len_max: u32 = 1_048_576;
/// The seeds `sim --h3-trace-write` writes for TLC, and the model's steps TLC may take between two
/// logged states.
pub const written_seeds: u64 = 64;
pub const steps_between_max: u64 = 24;
/// The units the trace run logs from one of h3's own streams, at most. A request causes at most
/// one insert, and at most three decoder instructions: a Section Acknowledgment, a Stream
/// Cancellation and an Insert Count Increment. Four per request leaves one to spare.
/// `control_units` adds the control stream's SETTINGS and one more to spare.
pub const units_per_request_max: u32 = 4;
pub const control_units: u32 = 2;
pub const units_max: u32 = units_per_request_max * requests_max + goaways_max + control_units;
/// The frames the control stream may carry for each unit logged: the unit and a reserved frame
/// before it (RFC 9114 §7.2.8).
pub const control_frames_per_unit_max: u32 = 2;
