//! The programs of `examples/` (decision 96): what a project that depends on colibri writes, each
//! one importing the library modules by the names a dependent uses, and run over an in-memory link
//! on rotor's loop. `zig build examples` builds and runs every one, and `zig build example-<name>`
//! one of them.
const std = @import("std");
const modules = @import("modules.zig");

/// Each example's file under `examples/`, without its extension.
const names = [_][]const u8{ "h11_exchange", "h2_exchange" };

pub fn add(
    b: *std.Build,
    graph: modules.Modules,
    rotor: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const all = b.step("examples", "Build and run every program in examples/ (decision 96)");
    inline for (names) |name| {
        const module = b.createModule(.{
            .root_source_file = b.path("examples/" ++ name ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });
        module.addImport("h11", graph.h11);
        module.addImport("h2", graph.h2);
        module.addImport("http", graph.http);
        module.addImport("rotor", rotor);
        const program = b.addExecutable(.{ .name = name, .root_module = module });
        const run = b.addRunArtifact(program);
        b.step("example-" ++ name, "Build and run examples/" ++ name ++ ".zig").dependOn(&run.step);
        all.dependOn(&run.step);
    }
}
