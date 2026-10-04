//! The programs of `examples/` (decision 96): what a project that depends on colibri writes, each
//! one importing the library modules by the names a dependent uses, and run over an in-memory link
//! on rotor's loop. `zig build examples` builds and runs every one, and `zig build example-<name>`
//! one of them.
const std = @import("std");
const modules = @import("modules.zig");

/// One program under `examples/`: its file without the extension, and whether it runs TLS.
const Example = struct {
    name: []const u8,
    /// A program over TLS links chapulin through `tls`, asks the operating system for entropy,
    /// probes its CPU through stdx's `platform`, and presents colibri's test identity.
    tls: bool = false,
};

const examples = [_]Example{
    .{ .name = "h11_exchange" },
    .{ .name = "h2_exchange" },
    .{ .name = "tls_exchange", .tls = true },
    .{ .name = "h3_exchange", .tls = true },
};

pub fn add(
    b: *std.Build,
    graph: modules.Modules,
    rotor: *std.Build.Module,
    testdata: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const all = b.step("examples", "Build and run every program in examples/ (decision 96)");
    inline for (examples) |example| {
        const module = b.createModule(.{
            .root_source_file = b.path("examples/" ++ example.name ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });
        module.addImport("h11", graph.h11);
        module.addImport("h2", graph.h2);
        module.addImport("http", graph.http);
        module.addImport("rotor", rotor);
        if (example.tls) add_tls(module, graph, testdata);
        const program = b.addExecutable(.{ .name = example.name, .root_module = module });
        const run = b.addRunArtifact(program);
        b.step("example-" ++ example.name, "Build and run examples/" ++ example.name ++ ".zig").dependOn(&run.step);
        all.dependOn(&run.step);
    }
}

/// What a program over TLS imports beside the protocol modules. The test identity is the one copy
/// of `src/testing/testdata/` (the owner's ruling of 2026-09-28): it stands in for the certificate
/// and the key a program loads, and no packaged module imports it.
fn add_tls(module: *std.Build.Module, graph: modules.Modules, testdata: *std.Build.Module) void {
    module.addImport("server", graph.server);
    module.addImport("client", graph.client);
    module.addImport("tls", graph.tls);
    module.addImport("platform", graph.stdx.module("platform"));
    module.addImport("testdata", testdata);
    // `getentropy`, the source each session draws from.
    module.link_libc = true;
}
