//! The programs of `examples/` (decision 96): what a project that depends on colibri writes, each
//! one importing `colibri`, the one module a dependent reaches (decision 170), and run over an
//! in-memory link on rotor's loop. Two bind a loopback port: `colibri_server` through `colibri`, and
//! `colibri_shared_rotor` in its own adapter of `.hosted` objects (decision 159). `zig build
//! examples` builds and runs every one, and `zig build example-<name>` one of them.
const std = @import("std");
const modules = @import("modules.zig");

/// One program under `examples/`: its file without the extension, and whether it runs TLS.
const Example = struct {
    name: []const u8,
    /// A program over TLS asks the operating system for entropy, probes its CPU through stdx's
    /// `platform`, and presents colibri's test identity.
    tls: bool = false,
};

const examples = [_]Example{
    .{ .name = "h11_exchange" },
    .{ .name = "h2_exchange" },
    .{ .name = "server_exchange", .tls = true },
    .{ .name = "client_exchange", .tls = true },
    .{ .name = "client_pool", .tls = true },
    .{ .name = "client_stream", .tls = true },
    .{ .name = "server_stream", .tls = true },
    .{ .name = "dnssec_check" },
    .{ .name = "colibri_server", .tls = true },
    .{ .name = "colibri_hosted", .tls = true },
    .{ .name = "colibri_shared_rotor", .tls = true },
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
    inline for (examples) |entry| {
        const example = b.createModule(.{
            .root_source_file = b.path("examples/" ++ entry.name ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });
        // The one module of colibri that a dependent imports. Its root names every other one.
        example.addImport("colibri", graph.colibri);
        example.addImport("rotor", rotor);
        if (entry.tls) add_tls(example, graph, testdata);
        const program = b.addExecutable(.{ .name = entry.name, .root_module = example });
        const run = b.addRunArtifact(program);
        b.step("example-" ++ entry.name, "Build and run examples/" ++ entry.name ++ ".zig").dependOn(&run.step);
        all.dependOn(&run.step);
    }
}

/// What a program over TLS imports beside `colibri`: stdx's `platform`, which the program takes
/// from stdx itself (decision 97 as amended), and the test identity. The identity is the one copy
/// of `src/testing/testdata/` (the owner's ruling of 2026-09-28): it stands in for the certificate
/// and the key a program loads, and no packaged module imports it.
fn add_tls(module: *std.Build.Module, graph: modules.Modules, testdata: *std.Build.Module) void {
    module.addImport("stdx", graph.stdx.module("stdx"));
    module.addImport("testdata", testdata);
    // `getentropy`, the source each session draws from.
    module.link_libc = true;
}
