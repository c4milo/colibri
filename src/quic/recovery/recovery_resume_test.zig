//! The tests of Careful Resume's saved set and its Reconnaissance Phase's entry
//! (`recovery_resume.zig`, RFC 9959 §3.1, §3.2 and §4.3.1).
const std = @import("std");
const constants = @import("../constants.zig");
const recovery_resume = @import("recovery_resume.zig");

const ResumeState = recovery_resume.ResumeState;
const Resume = recovery_resume.Resume;
const testing = std.testing;

const saved_at_ns: u64 = 1_000_000_000;
const lifetime_ns: u64 = 60_000_000_000;
const bounds: recovery_resume.ResumeBounds = .{ .lifetime_ns = lifetime_ns };
const window_len: u64 = 400_000;
const rtt_ns: u64 = 50_000_000;
const saved: ResumeState = .{ .window_len = window_len, .rtt_ns = rtt_ns, .saved_at_ns = saved_at_ns };

test "decision 149: the bounds default to 4 MiB and 1 hour" {
    const defaults: recovery_resume.ResumeBounds = .{};
    try testing.expectEqual(4 * 1024 * 1024, defaults.jump_len_max);
    try testing.expectEqual(3_600_000_000_000, defaults.lifetime_ns);
    try testing.expectEqual(constants.policy.resume_jump_len_max_default, defaults.jump_len_max);
}

test "non-negotiable 6: a saved set carries its version and size, and another layout is refused" {
    try testing.expectEqual(recovery_resume.state_version, saved.version);
    try testing.expectEqual(32, saved.size);
    var other_version = saved;
    other_version.version += 1;
    try testing.expect(!other_version.usable(bounds, saved_at_ns));
    var other_size = saved;
    other_size.size -= 1;
    try testing.expect(!other_size.usable(bounds, saved_at_ns));
    try testing.expect(saved.usable(bounds, saved_at_ns));
}

test "RFC 9959 §3.2: a set past its Lifetime, or from after now, is not used" {
    try testing.expect(saved.usable(bounds, saved_at_ns + lifetime_ns));
    try testing.expect(!saved.usable(bounds, saved_at_ns + lifetime_ns + 1));
    try testing.expect(!saved.usable(bounds, saved_at_ns - 1));
}

test "RFC 9959 §3.1: a set with no window or no round trip is not used" {
    var empty_window = saved;
    empty_window.window_len = 0;
    try testing.expect(!empty_window.usable(bounds, saved_at_ns));
    var empty_rtt = saved;
    empty_rtt.rtt_ns = 0;
    try testing.expect(!empty_rtt.usable(bounds, saved_at_ns));
}

test "RFC 9959 §3.2: a usable set starts the Reconnaissance Phase, and a new path ends it" {
    var state: Resume = undefined;
    state.init(saved, bounds, saved_at_ns);
    try testing.expectEqual(.reconnaissance, state.phase);
    try testing.expectEqual(saved.window_len, state.saved.window_len);
    state.on_path_changed();
    try testing.expectEqual(.off, state.phase);
    state.init(null, bounds, saved_at_ns);
    try testing.expectEqual(.off, state.phase);
    state.init(saved, bounds, saved_at_ns + lifetime_ns + 1);
    try testing.expectEqual(.off, state.phase);
}
