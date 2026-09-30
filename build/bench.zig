//! The benchmarks of `bench/` (design §8 step 13). `zig build bench-memory` prints the static
//! memory per connection (13b), and its test joins `zig build test`, so `docs/performance.md`'s
//! table changes in the commit that changes a struct's size.
const std = @import("std");
const modules = @import("modules.zig");

pub fn add(
    b: *std.Build,
    graph: modules.Modules,
    test_step: *std.Build.Step,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const module = b.createModule(.{
        .root_source_file = b.path("bench/memory.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("server", graph.server);
    module.addImport("client", graph.client);
    module.addImport("h11", graph.h11);
    module.addImport("h2", graph.h2);
    module.addImport("h3", graph.h3);
    module.addImport("quic", graph.quic);
    module.addImport("tls", graph.tls);
    module.addAnonymousImport("performance_md", .{ .root_source_file = b.path("docs/performance.md") });
    // Decision 97 as amended: chapulin's `AES` value for the target, which sizes every struct that
    // holds a session.
    const options = b.addOptions();
    options.addOption([]const u8, "aes", @tagName(modules.aes_of(target)));
    module.addOptions("options", options);
    const program = b.addExecutable(.{ .name = "bench-memory", .root_module = module });
    const print = b.step("bench-memory", "Print the static memory per connection (design §8 step 13b)");
    print.dependOn(&b.addRunArtifact(program).step);
    const tests = b.addTest(.{ .name = "bench-memory", .root_module = module });
    const run = &b.addRunArtifact(tests).step;
    test_step.dependOn(run);
    b.step("test-bench", "Run the tests of bench/ alone, with nothing else in the graph").dependOn(run);
}
