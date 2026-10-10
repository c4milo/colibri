//! The CPU colibri's TLS values take in the test-only programs (decision 97 as amended for
//! chapulin 0.2.0, https://github.com/c4milo/colibri/issues/84): stdx's probe, taken once, and the
//! mode the program's one thread runs in.
//!
//! On arm64 the program sets PSTATE.DIT on its thread where the core has FEAT_DIT, and then states
//! the mode, which is true. A virtual machine may hide FEAT_DIT from its guest, as the bench
//! runner's does, and on x86-64 no program can read DOITM, which the operating system sets. There
//! the test programs state the mode anyway: nothing checks the statement, and it lets their sessions
//! run the AES-GCM suites, which h3spec and the bench's h2load offer alone. A program serving real
//! peers states it only where it knows its thread runs in that mode.
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

/// Prints the description `probe` gives, which decides the suites a program's TLS sessions hold
/// (decision 97 as amended), under the program's name.
pub fn print(program: []const u8) void {
    const cpu = probe();
    std.debug.print("{s}: cpu aes_clmul {t}, dit {t}, timing {t}\n", .{ program, cpu.probe.aes_clmul, cpu.probe.dit, cpu.timing });
}

/// The mode of the program's thread: on arm64 PSTATE.DIT, which this sets where the core has
/// FEAT_DIT, and the test programs' statement on every arm64 and x86-64 core.
fn timing_of(found: platform.Cpu) tls.Timing {
    return switch (builtin.cpu.arch) {
        .aarch64 => {
            if (found.dit == .yes) set_dit();
            return .data_independent;
        },
        .x86_64 => .data_independent,
        else => .not_stated,
    };
}

/// Arm's `MSR DIT, #1` (FEAT_DIT), encoded so an assembler without the feature takes it: from here
/// on, the instructions Arm lists take a time independent of their data on this thread.
fn set_dit() void {
    asm volatile (".inst 0xd503415f" ::: .{ .memory = true });
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

test "decision 97: an arm64 thread with FEAT_DIT runs with PSTATE.DIT set, and every arm64 and x86-64 core states the mode" {
    const cpu = probe();
    switch (builtin.cpu.arch) {
        .aarch64 => {
            try testing.expectEqual(tls.Timing.data_independent, cpu.timing);
            if (cpu.probe.dit == .yes) try testing.expect(dit_set());
        },
        .x86_64 => try testing.expectEqual(tls.Timing.data_independent, cpu.timing),
        else => try testing.expectEqual(tls.Timing.not_stated, cpu.timing),
    }
}

test "decision 97: a core whose probe finds no FEAT_DIT, as a virtual machine's may not, still states the mode" {
    const expected: tls.Timing = switch (builtin.cpu.arch) {
        .aarch64, .x86_64 => .data_independent,
        else => .not_stated,
    };
    // Neither probe reaches `set_dit`, which a core without FEAT_DIT would refuse.
    try testing.expectEqual(expected, timing_of(.{ .aes_clmul = .yes, .dit = .no }));
    try testing.expectEqual(expected, timing_of(.{ .aes_clmul = .yes, .dit = .not_known }));
}
