//! `zig build colibri-hosted-check` (design §8 step 44k, decision 159): the `colibri` module as a
//! dependent that passes no `.rotor = true` gets it, with no import of Rotor. Three cases of
//! `src/colibri/loop_check_test.zig` compile against it:
//! - `hosted_init` must compile and run to its end: a `.hosted` server and client need no Rotor.
//! - `private_server_turn` and `private_client_turn` name `colibri.Server(_, .private)` and
//!   `colibri.Client(_, .private)`. Each must fail to compile with colibri's message, which names
//!   the option to pass.
//!
//! `zig build test` runs the step, because its name ends in `-check` (build/check_steps.zig).
const std = @import("std");
const modules = @import("modules.zig");
const modules_colibri = @import("modules_colibri.zig");

/// The message of `host.require_rotor` (src/colibri/host.zig).
const no_rotor = "colibri: .private runs on Rotor; pass .rotor = true to b.dependency(\"colibri\", ...)";

const Case = struct {
    name: []const u8,
    /// Null when the case must compile and run to its end.
    message: ?[]const u8,
};

const cases = [_]Case{
    .{ .name = "hosted_init", .message = null },
    .{ .name = "private_server_turn", .message = no_rotor },
    .{ .name = "private_client_turn", .message = no_rotor },
};

/// Adds `zig build colibri-hosted-check` and returns its step, which `zig build test` depends on.
pub fn add(
    b: *std.Build,
    graph: modules.Modules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step {
    const step = b.step("colibri-hosted-check", "Require .hosted to build with no Rotor, and .private to fail with colibri's message");
    const colibri = modules_colibri.add_without_rotor(b, .{
        .core = graph.core,
        .http = graph.http,
        .server = graph.server,
        .client = graph.client,
        .tls = graph.tls,
    }, target, optimize);
    for (cases) |case| {
        const options = b.addOptions();
        options.addOption([]const u8, "case", case.name);
        const module = b.createModule(.{
            .root_source_file = b.path("src/colibri/loop_check_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        module.addImport("colibri", colibri);
        module.addImport("server", graph.server);
        module.addImport("client", graph.client);
        module.addImport("tls", graph.tls);
        module.addOptions("loop_case", options);
        const program = b.addExecutable(.{ .name = b.fmt("colibri_hosted_{s}", .{case.name}), .root_module = module });
        if (case.message) |message| {
            // Zig fails the step when the compile succeeds, or when no error line holds the
            // message.
            program.expect_errors = .{ .contains = message };
            step.dependOn(&program.step);
        } else {
            step.dependOn(&b.addRunArtifact(program).step);
        }
    }
    return step;
}
