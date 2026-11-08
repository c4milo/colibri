//! `zig build colibri-loop-check` (design §8 step 44d, decision 159): what the compiler and a run
//! must refuse in `colibri.Server` and `colibri.Client`, from `src/colibri/loop_check_test.zig`. The
//! build option `case` names one case, and each case is a program of its own:
//! - `hosted_init` must compile and run to its end: a `.hosted` server and client start, turn
//!   and stop with no socket.
//! - Each case with a compile `message` must fail to compile with it: `run` and `port` on
//!   `.hosted`, and `turn` and `complete` on `.private` (decision 156 ruling 4 as amended).
//! - Each case with a halt `message` must compile, and its run must halt with SIGABRT and write
//!   the message: decision 159's rules 2, 4 and 6, which a test binary does not live through.
const std = @import("std");
const modules = @import("modules.zig");

/// How a case must end.
const Ending = enum { runs, compile_error, halt };

const Case = struct {
    name: []const u8,
    ending: Ending,
    message: []const u8 = "",
};

const no_run = "colibri: a .hosted object has no run(); its host calls turn() and complete() (decision 159)";
const no_port = "colibri: a .hosted Server has no port(); its host bound the sockets (decision 159)";
const no_turn = "colibri: a .private object has no turn(); run() calls it on colibri's own loop (decision 159)";
const no_complete = "colibri: a .private object has no complete(); run() calls it on colibri's own loop (decision 159)";

const turn_inside = "colibri: turn() called inside turn() or complete() (decision 159, rule 4)";
const complete_inside = "colibri: complete() called inside turn() or complete() (decision 159, rule 4)";
const run_inside = "colibri: run() called inside turn() or complete() (decision 159, rule 4)";

const cases = [_]Case{
    .{ .name = "hosted_init", .ending = .runs },
    .{ .name = "hosted_server_run", .ending = .compile_error, .message = no_run },
    .{ .name = "hosted_server_port", .ending = .compile_error, .message = no_port },
    .{ .name = "hosted_client_run", .ending = .compile_error, .message = no_run },
    .{ .name = "private_server_turn", .ending = .compile_error, .message = no_turn },
    .{ .name = "private_server_complete", .ending = .compile_error, .message = no_complete },
    .{ .name = "private_client_turn", .ending = .compile_error, .message = no_turn },
    .{ .name = "private_client_complete", .ending = .compile_error, .message = no_complete },
    .{
        .name = "halt_stray_completion",
        .ending = .halt,
        .message = "colibri: a completion names operation 0xffffffff, which is not in flight (decision 159, rule 6)",
    },
    .{
        .name = "halt_deinit_early",
        .ending = .halt,
        .message = "colibri: deinit of a .hosted object before stopped() (decision 159, rule 2)",
    },
    .{ .name = "halt_client_turn_in_handler", .ending = .halt, .message = turn_inside },
    .{ .name = "halt_client_complete_in_handler", .ending = .halt, .message = complete_inside },
    .{ .name = "halt_client_run_in_handler", .ending = .halt, .message = run_inside },
    .{ .name = "halt_server_turn_in_route", .ending = .halt, .message = turn_inside },
    .{ .name = "halt_server_complete_in_route", .ending = .halt, .message = complete_inside },
    .{ .name = "halt_server_run_in_route", .ending = .halt, .message = run_inside },
};

/// Adds `zig build colibri-loop-check` and returns its step, which `zig build test` depends on.
pub fn add(
    b: *std.Build,
    graph: modules.Modules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step {
    const step = b.step("colibri-loop-check", "Require the calls each kind of colibri object lacks to fail, and its halts to halt");
    for (cases) |case| {
        const options = b.addOptions();
        options.addOption([]const u8, "case", case.name);
        const module = b.createModule(.{
            .root_source_file = b.path("src/colibri/loop_check_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        module.addImport("colibri", graph.colibri);
        module.addImport("server", graph.server);
        module.addImport("client", graph.client);
        module.addImport("tls", graph.tls);
        module.addOptions("loop_case", options);
        const program = b.addExecutable(.{ .name = b.fmt("colibri_loop_{s}", .{case.name}), .root_module = module });
        switch (case.ending) {
            // Zig fails the step when the compile succeeds, or when no error line ends with the
            // message.
            .compile_error => {
                program.expect_errors = .{ .contains = case.message };
                step.dependOn(&program.step);
            },
            .runs => step.dependOn(&b.addRunArtifact(program).step),
            .halt => {
                const run = b.addRunArtifact(program);
                run.addCheck(.{ .expect_term = .{ .signal = .ABRT } });
                run.addCheck(.{ .expect_stderr_match = case.message });
                step.dependOn(&run.step);
            },
        }
    }
    return step;
}
