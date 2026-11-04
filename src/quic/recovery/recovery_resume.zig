//! Careful Resume (RFC 9959, decision 149): what a connection saves of its path for a later
//! connection, the bounds a program sets, and the phase a resumed connection is in. Part of design
//! §8 step 35. 35a holds the saved set, its checks and the Reconnaissance Phase's entry; the
//! phases that change the window are 35b's and 35c's.
//!
//! colibri holds no state between connections (non-negotiable 1): a program stores a
//! `ResumeState` as it stores a session ticket, and passes it to a later connection.
//!
//! It reads no clock: every instant is a parameter (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// The version of `ResumeState`'s layout. A program may write the set to disk, so the set carries
/// its version and its size (non-negotiable 6), and a set of another version or size is refused.
pub const state_version: u32 = 1;

/// RFC 9959 §1.1's saved CC parameters: what one connection observed of its path, which a later
/// connection to the same remote endpoint may start from. Its layout is fixed, so a program may
/// store its octets as they are.
pub const ResumeState = extern struct {
    /// `state_version` when colibri wrote it.
    version: u32 = state_version,
    /// The octets of the set, `@sizeOf(ResumeState)` when colibri wrote it.
    size: u32 = @sizeOf(ResumeState),
    /// §3.1's saved_cwnd: the octets the connection had in flight over one round trip.
    window_len: u64,
    /// §3.1's saved_rtt: the minimum round trip the connection measured, in nanoseconds.
    rtt_ns: u64,
    /// The instant the set was observed, from which §4.3.1's Lifetime runs.
    saved_at_ns: u64,

    /// Whether colibri may start from this set at `now_ns`: its version and size are this build's,
    /// it holds a window and a round trip, and its Lifetime has not passed (RFC 9959 §3.2).
    pub fn usable(state: *const ResumeState, bounds: ResumeBounds, now_ns: u64) bool {
        // Non-negotiable 6: a set of another layout says nothing this build can read.
        if (state.version != state_version or state.size != @sizeOf(ResumeState)) return false;
        // RFC 9959 §3.1: a set saves a capacity and a round trip, and one of zero saves neither.
        if (state.window_len == 0 or state.rtt_ns == 0) return false;
        // RFC 9959 §3.2: "If the Lifetime of the observed CC parameters is exceeded, this set of
        // CC parameters is not used." A set from after `now_ns` is no observation of this path.
        if (now_ns < state.saved_at_ns) return false;
        return now_ns - state.saved_at_ns <= bounds.lifetime_ns;
    }
};

comptime {
    // The layout a program stores: two 32-bit fields and three 64-bit ones, with no padding.
    assert(@sizeOf(ResumeState) == 32);
}

/// RFC 9959 §5's two bounds a sender configures: the most a window may jump to (§3.3's max_jump)
/// and how long a saved set may be used (§4.3.1's Lifetime).
pub const ResumeBounds = struct {
    jump_len_max: u64 = constants.policy.resume_jump_len_max_default,
    lifetime_ns: u64 = constants.policy.resume_lifetime_ns_default,
};

/// RFC 9959 §3's phases, as Figure 1 names them. `off` is normal congestion control, with no saved
/// set or after the connection stopped using it.
pub const Phase = enum(u8) {
    off,
    reconnaissance,
    unvalidated,
    validating,
    safe_retreat,
};

/// A connection's part of Careful Resume: its phase, and the set it resumes from.
pub const Resume = struct {
    phase: Phase,
    /// The saved set, which only the phases after `off` read.
    saved: ResumeState,
    bounds: ResumeBounds,

    /// Starts in the Reconnaissance Phase when the program passed a set colibri may use at
    /// `now_ns`, and in normal congestion control otherwise (RFC 9959 §3.2).
    pub fn init(state: *Resume, saved: ?ResumeState, bounds: ResumeBounds, now_ns: u64) void {
        state.* = .{ .phase = .off, .saved = .{ .window_len = 0, .rtt_ns = 0, .saved_at_ns = 0 }, .bounds = bounds };
        const held = saved orelse return;
        if (!held.usable(bounds, now_ns)) return;
        state.saved = held;
        state.phase = .reconnaissance;
    }

    /// RFC 9959 §3.2: "If the Remote Endpoint is not the same as any saved_remote_endpoint, or the
    /// sender receives a signal from the local stack indicating that the path is now different to
    /// the observed path, the sender MUST stop using Careful Resume". RFC 9000 §9.4's new path is
    /// such a signal.
    pub fn on_path_changed(state: *Resume) void {
        state.phase = .off;
    }
};

test {
    _ = @import("recovery_resume_test.zig");
}
