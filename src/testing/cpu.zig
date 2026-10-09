//! The CPU colibri's TLS values take in the test-only programs (decision 97 as amended for
//! chapulin 0.2.0, https://github.com/c4milo/colibri/issues/84): stdx's probe, taken once, and the
//! mode the program's one thread runs in.
//!
//! On arm64 the program sets PSTATE.DIT on its thread where the core has FEAT_DIT, and then states
//! the mode, which is true. On x86-64 no program can read DOITM, which the operating system sets,
//! and the test programs state the mode anyway: nothing checks the statement, and it lets their
//! sessions run the AES-GCM suites, which h3spec offers alone. A program serving real peers states
//! it only where it knows the part is on Intel's DOIT list and its system set DOITM.
const std = @import("std");
const builtin = @import("builtin");
const platform = @import("platform");
const tls = @import("tls");

/// The description the first call made, which every later call returns.
var described: ?tls.Cpu align(@alignOf(?tls.Cpu)) = null;

pub fn probe() tls.Cpu {
    if (described) |cpu| return cpu;
    const found = platform.probe();
    const cpu: tls.Cpu = .{ .probe = found, .timing = timing_of(found) };
    described = cpu;
    return cpu;
}

/// The mode of the program's thread: on arm64 PSTATE.DIT, which this sets where the core has
/// FEAT_DIT, and on x86-64 the test programs' statement.
fn timing_of(found: platform.Cpu) tls.Timing {
    return switch (builtin.cpu.arch) {
        .aarch64 => if (found.dit == .yes) set_dit() else .not_stated,
        .x86_64 => .data_independent,
        else => .not_stated,
    };
}

/// Arm's `MSR DIT, #1` (FEAT_DIT), encoded so an assembler without the feature takes it: from here
/// on, the instructions Arm lists take a time independent of their data on this thread.
fn set_dit() tls.Timing {
    asm volatile (".inst 0xd503415f" ::: .{ .memory = true });
    return .data_independent;
}

const testing = std.testing;

/// PSTATE.DIT's place in what `MRS x0, DIT` reads: bit 24.
const dit_shift: u6 = 24;
const dit_bit: u64 = @as(u64, 1) << dit_shift;

/// Arm's `MRS x0, DIT`, encoded as `set_dit` encodes its instruction.
fn dit_set() bool {
    const value = asm volatile (".inst 0xd53b42a0"
        : [value] "={x0}" (-> u64),
    );
    return value & dit_bit != 0;
}

test "decision 97: an arm64 thread with FEAT_DIT runs with PSTATE.DIT set and states the mode, and x86-64 states it" {
    const cpu = probe();
    switch (builtin.cpu.arch) {
        .aarch64 => {
            const has_dit = cpu.probe.dit == .yes;
            try testing.expectEqual(@as(tls.Timing, if (has_dit) .data_independent else .not_stated), cpu.timing);
            if (has_dit) try testing.expect(dit_set());
        },
        .x86_64 => try testing.expectEqual(tls.Timing.data_independent, cpu.timing),
        else => try testing.expectEqual(tls.Timing.not_stated, cpu.timing),
    }
}
