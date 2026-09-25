//! Build graph for colibri (docs/design.md §8 step 0): `zig build` compiles every module,
//! `zig build lint` scores every function's cognitive complexity and runs the rules of tools/lint
//! over the tree, `zig build test` runs the lint and then every module's unit tests, and
//! `zig build test-<module>` runs one module's tests with nothing else in the graph, which is
//! what a mutation is measured against.
//!
//! `zig build graph-check` is step 0's own check: it compiles a source that imports `http` from
//! inside `src/quic/` and requires the compile to fail. This shows invariant 26 is enforced
//! by the build rather than by review.
//!
//! `zig build huffman-table` and `zig build golden` rewrite the generated sources of step 1, and
//! `zig build test` checks both against their sources; build/generated.zig wires them.
//!
//! `zig build lint-commits` checks the commit messages this branch adds and `zig build hooks`
//! points this clone's core.hooksPath at .githooks; neither is part of `zig build test`, because
//! commit shape is a property of the history, not of the code.
//!
//! The library has no dependencies, and colibri is meant to keep it that way (CLAUDE.md, Ask
//! before). The tools take one: pepegrillo, a lazy package in build.zig.zon that only the root
//! build requests, so a project depending on colibri never fetches it (decision 36). The module
//! graph is build/modules.zig.
const std = @import("std");
const assert = std.debug.assert;
const modules = @import("build/modules.zig");
const generated = @import("build/generated.zig");
const lint = @import("build/lint.zig");
const vectors = @import("build/vectors.zig");

/// Every directory `zig build lint` scores and `zig build fmt` checks, beside build.zig itself.
const source_directories = [_][]const u8{ "build", "src", "tools" };

/// Every directory the tools/lint rules read: the sources above plus the documents, which the
/// markdown rule covers.
const lint_rule_directories = [_][]const u8{ "build", "src", "tools", "docs" };

/// Every tool built on pepegrillo whose own tests `zig build test` runs; build/generated.zig and build/vectors.zig hook in the tests of the generator and vectors tools. A build that does not run the checkers' own
/// tests lets a rule lose its own test without the build reporting it.
const tool_test_roots = [_][]const u8{
    "tools/lint/main.zig",
    "tools/cognitive_complexity.zig",
    "tools/commit_lint.zig",
};

/// The git revision range `zig build lint-commits` checks.
const commit_lint_range = "origin/main..HEAD";

/// The directory `zig build hooks` points this clone's core.hooksPath at.
const hooks_directory = ".githooks";

/// The pre-push hook: a copy of pepegrillo's, which `zig build test` compares byte for byte.
const pre_push_hook = hooks_directory ++ "/pre-push";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Assertions stay on in production (CLAUDE.md non-negotiable 4), so the build offers Debug
    // and ReleaseSafe only: `-Drelease` selects ReleaseSafe, and the `-Doptimize` option that
    // would admit ReleaseFast or ReleaseSmall is never declared.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });
    assert(optimize == .Debug or optimize == .ReleaseSafe);

    // Decision 10: `src/testing/` is the only directory that links chapulin, and colibri vendors
    // none of its C (CLAUDE.md "Ask before"). The option names a chapulin checkout whose
    // `bin/chapulin-client.o` and `bin/chapulin-server.o` have already been built; without it the
    // TLS endpoints are not built and every other check still runs, so a fresh clone needs no
    // chapulin.
    // The two roles are two builds and either can be present without the other, so each endpoint
    // names its own. Both usually point at one checkout: colibri reads the headers from it and
    // links `bin/chapulin-client.o` or `bin/chapulin-server.o` from it.
    const chapulin: modules.Chapulin = .{
        .client = b.option([]const u8, "chapulin-client", "A chapulin checkout built ROLE=client (decision 10)"),
        .server = b.option([]const u8, "chapulin-server", "A chapulin checkout built ROLE=server (decision 10)"),
        .quic = b.option([]const u8, "chapulin-quic", "A chapulin checkout built TRANSPORT=quic-nonblocking ROLE=both (decision 10)"),
        .quic_trust = b.option(modules.QuicTrust, "chapulin-quic-trust", "The TRUST that object was built with") orelse .webpki,
    };
    const graph = modules.add(b, target, optimize, chapulin);

    // Everything below is colibri's own build: the tests, the checks and the tools. A project that
    // depends on colibri stops here, before the tools request pepegrillo.
    if (b.pkg_hash.len != 0) return;
    const pepegrillo_dependency = b.lazyDependency("pepegrillo", .{}) orelse return;
    const pepegrillo = pepegrillo_dependency.module("pepegrillo");
    // Decision 58: rotor is the loop of `src/testing/`'s UDP endpoints. Lazy like pepegrillo, and
    // requested here for the same reason, with the target and mode this build resolved. rotor's
    // build, like this one, offers ReleaseSafe as `-Drelease` and no `-Doptimize`.
    const rotor_options = .{ .target = target, .release = optimize == .ReleaseSafe };
    const rotor_dependency = b.lazyDependency("rotor", rotor_options) orelse return;
    const testing_udp = modules.add_testing_udp(b, graph, rotor_dependency.module("rotor"), chapulin, target, optimize);
    // https://github.com/c4milo/colibri/issues/61 amends decision 58: the h2 endpoints run on
    // Rotor's loop too.
    graph.testing.addImport("rotor", rotor_dependency.module("rotor"));
    graph.testing_client.addImport("rotor", rotor_dependency.module("rotor"));

    const install_step = b.getInstallStep();
    const test_step = b.step("test", "Run the lint, then every module's unit tests");
    test_step.dependOn(lint.add(b, .{
        .source_directories = &source_directories,
        .rule_directories = &lint_rule_directories,
        .complexity = b.addExecutable(.{
            .name = "cognitive_complexity",
            .root_module = tool_module(b, pepegrillo, "tools/cognitive_complexity.zig"),
        }),
        .rules = b.addExecutable(.{
            .name = "lint",
            .root_module = tool_module(b, pepegrillo, "tools/lint/main.zig"),
        }),
    }));

    const unit_test_modules = [_]struct { name: []const u8, module: *std.Build.Module }{
        .{ .name = "core", .module = graph.core },
        .{ .name = "wire", .module = graph.wire },
        .{ .name = "http", .module = graph.http },
        .{ .name = "tls", .module = graph.tls },
        .{ .name = "crypto", .module = graph.crypto },
        .{ .name = "hpack", .module = graph.hpack },
        .{ .name = "qpack", .module = graph.qpack },
        .{ .name = "quic", .module = graph.quic },
        .{ .name = "h2", .module = graph.h2 },
        .{ .name = "h3", .module = graph.h3 },
        .{ .name = "h11", .module = graph.h11 },
        .{ .name = "sim", .module = graph.sim },
        .{ .name = "sim-run", .module = graph.sim_run },
        .{ .name = "sim-run-quic", .module = graph.sim_run_quic },
        .{ .name = "golden", .module = graph.golden },
        .{ .name = "testing", .module = graph.testing },
        .{ .name = "testing-client", .module = graph.testing_client },
        .{ .name = "testing-tls", .module = graph.testing_tls },
        .{ .name = "testing-tls-server", .module = graph.testing_tls_server },
        .{ .name = "testing-quic", .module = graph.testing_quic },
        .{ .name = "testing-qif", .module = graph.testing_qif },
        .{ .name = "testing-udp", .module = testing_udp },
    };
    var golden_tests: ?*std.Build.Step = null;
    for (unit_test_modules) |entry| {
        const unit_tests = b.addTest(.{ .name = entry.name, .root_module = entry.module });
        install_step.dependOn(&unit_tests.step);
        const run = &b.addRunArtifact(unit_tests).step;
        test_step.dependOn(run);
        add_narrow_test_step(b, entry.name).dependOn(run);
        if (entry.module == graph.golden) golden_tests = run;
    }

    // The tools verify the tree, so they run on the host in Debug: a tool never ships.
    const tool_test_step = add_narrow_test_step(b, "tools");
    for (tool_test_roots) |root| {
        const tool_tests = b.addTest(.{
            .name = std.fs.path.stem(root),
            .root_module = tool_module(b, pepegrillo, root),
        });
        const run = &b.addRunArtifact(tool_tests).step;
        test_step.dependOn(run);
        tool_test_step.dependOn(run);
    }

    generated.add(b, .{
        .test_step = test_step,
        .tool_test_step = tool_test_step,
        .golden_tests = golden_tests.?,
    });

    // Decision 75: the QPACK vectors are a lazy package, fetched once and requested here, where
    // a project that depends on colibri never reaches.
    const qifs = b.lazyDependency("qifs", .{}) orelse return;
    vectors.add(b, .{ .test_step = test_step, .tool_test_step = tool_test_step }, qifs.path(""));

    test_step.dependOn(add_graph_check_step(b));
    test_step.dependOn(add_hook_check_step(b, pepegrillo_dependency));
    add_sim_step(b, graph.sim_run);
    add_h2_server_step(b, graph.testing);
    add_h2_client_step(b, graph.testing_client);
    add_tls_handshake_step(b, graph.testing_tls);
    add_tls_accept_step(b, graph.testing_tls_server);
    add_quic_loopback_step(b, graph.testing_quic);
    add_qif_step(b, graph.testing_qif);
    add_quic_udp_step(b, testing_udp);
    add_commit_lint_step(b, pepegrillo, install_step);
    add_tla_step(b, pepegrillo);
    add_lean_step(b, pepegrillo);
    add_hooks_step(b);

    const fmt_step = b.step("fmt", "Check formatting of every Zig source");
    fmt_step.dependOn(&b.addFmt(.{
        .paths = &(.{"build.zig"} ++ source_directories),
        .check = true,
    }).step);
}

/// `zig build test-<name>`: the tests of one module, or of the tools, with nothing else in the
/// graph. `zig build test` is the check that must pass; these steps are the inner loop of a
/// mutation, which is run against the narrowest target that can catch it.
fn add_narrow_test_step(b: *std.Build, name: []const u8) *std.Build.Step {
    return b.step(
        b.fmt("test-{s}", .{name}),
        b.fmt("Run the {s} tests alone, with nothing else in the graph", .{name}),
    );
}

/// A module compiled for the build host in Debug: every tool, and nothing else.
fn host_module(b: *std.Build, root_source_file: []const u8) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = b.graph.host,
        .optimize = .Debug,
    });
}

/// A host module that imports `pepegrillo`: every tool built on pepegrillo's engines.
fn tool_module(
    b: *std.Build,
    pepegrillo: *std.Build.Module,
    root_source_file: []const u8,
) *std.Build.Module {
    const module = host_module(b, root_source_file);
    module.addImport("pepegrillo", pepegrillo);
    return module;
}

/// `zig build graph-check`: design §8 step 0's check. A module can import only what
/// build/modules.zig gives it, and the way to show that is to try the import that must fail.
/// `tools/graph_check.zig` first compiles the control `tools/fixtures/quic_imports_core.zig` as a
/// module of the `quic` shape and requires it to compile, then compiles one fixture per forbidden
/// module, `quic_imports_http.zig`, `quic_imports_h2.zig`, `quic_imports_h3.zig`,
/// `quic_imports_h11.zig`, `quic_imports_hpack.zig` and `quic_imports_qpack.zig`, and requires each
/// compile to fail with an unknown-module error. A check that asserted the rule in a linter would
/// only be checking what the source says; this checks what
/// the build does.
fn add_graph_check_step(b: *std.Build) *std.Build.Step {
    const check = b.addExecutable(.{
        .name = "graph_check",
        .root_module = host_module(b, "tools/graph_check.zig"),
    });
    const check_run = b.addRunArtifact(check);
    check_run.addArg(b.graph.zig_exe);
    check_run.addDirectoryArg(b.path("src"));
    check_run.addDirectoryArg(b.path("tools/fixtures"));
    // Re-run the check when the graph it checks changes, not only when the tool does.
    check_run.addFileInput(b.path("build/modules.zig"));

    const step = b.step("graph-check", "Require that src/quic/ cannot import an HTTP module");
    step.dependOn(&check_run.step);
    return step;
}

/// `zig build hook-check`: .githooks/pre-push must be byte-identical to the hook of the pinned
/// pepegrillo. After a pepegrillo bump, copy the new hook over it.
fn add_hook_check_step(b: *std.Build, pepegrillo: *std.Build.Dependency) *std.Build.Step {
    const compare = b.addSystemCommand(&.{"cmp"});
    compare.addFileArg(pepegrillo.path("hooks/pre-push"));
    compare.addFileArg(b.path(pre_push_hook));
    const step = b.step(
        "hook-check",
        "Require " ++ pre_push_hook ++ " to match pepegrillo's hooks/pre-push; copy it when not",
    );
    step.dependOn(&compare.step);
    return step;
}

/// `zig build lint-commits`: the Conventional Commit rules of CLAUDE.md over the commits this
/// branch adds. Not part of `zig build test`: commit shape is a property of the history.
/// `zig build install-commit-lint` installs the linter alone, which .githooks/pre-push runs when
/// zig-out/bin/commit_lint is missing.
fn add_commit_lint_step(
    b: *std.Build,
    pepegrillo: *std.Build.Module,
    install_step: *std.Build.Step,
) void {
    const tool = b.addExecutable(.{
        .name = "commit_lint",
        .root_module = tool_module(b, pepegrillo, "tools/commit_lint.zig"),
    });
    const install_tool = b.addInstallArtifact(tool, .{});
    install_step.dependOn(&install_tool.step);
    const install_tool_step = b.step("install-commit-lint", "Install the commit-message linter alone");
    install_tool_step.dependOn(&install_tool.step);
    const run = b.addRunArtifact(tool);
    run.addArgs(&.{ "--range", commit_lint_range });
    const step = b.step("lint-commits", "Check the commit messages this branch adds");
    step.dependOn(&run.step);
}

/// `zig build tla [-- <configuration>...]`: pepegrillo's TLC runner over the TLA+ models in
/// spec/tla/ (decision 67). Not part of `zig build test`: TLC needs Java, which tools/ci.sh looks
/// for before it runs this.
fn add_tla_step(b: *std.Build, pepegrillo: *std.Build.Module) void {
    const tool = b.addExecutable(.{
        .name = "tla",
        .root_module = tool_module(b, pepegrillo, "tools/tla.zig"),
    });
    const run = b.addRunArtifact(tool);
    if (b.args) |arguments| run.addArgs(arguments);
    run.setCwd(b.path("."));
    run.has_side_effects = true;
    const step = b.step("tla", "Model-check the TLA+ specifications in spec/tla/ with TLC");
    step.dependOn(&run.step);
}

/// `zig build lean [-- write]`: pepegrillo's lake runner over the Lean proofs in spec/lean/, then
/// the check that the vector files the Zig tests read are what the proved definitions give
/// (decision 77). Not part of `zig build test`: lake needs elan, which tools/ci.sh looks for.
fn add_lean_step(b: *std.Build, pepegrillo: *std.Build.Module) void {
    const tool = b.addExecutable(.{
        .name = "lean",
        .root_module = tool_module(b, pepegrillo, "tools/lean.zig"),
    });
    const run = b.addRunArtifact(tool);
    if (b.args) |arguments| run.addArgs(arguments);
    run.setCwd(b.path("."));
    run.has_side_effects = true;
    const step = b.step("lean", "Build the Lean proofs in spec/lean/ and check the vectors they give");
    step.dependOn(&run.step);
}

/// `zig build sim -- <arguments>`: the simulator's command line (src/sim/run_main.zig), built in
/// the mode `-Drelease` selects, so one seed can be replayed in either.
fn add_sim_step(b: *std.Build, sim_run: *std.Build.Module) void {
    const simulator = b.addExecutable(.{ .name = "sim", .root_module = sim_run });
    const run = b.addRunArtifact(simulator);
    if (b.args) |arguments| run.addArgs(arguments);
    const step = b.step("sim", "Run the simulator: --<check>-seed <hex> or --<check>-check [seeds]");
    step.dependOn(&run.step);
}

/// The cleartext h2 server of design §9, which `tools/h2spec.sh` runs the pinned suite against.
/// It is built from the `testing` module and is never part of the library.
fn add_h2_server_step(b: *std.Build, testing: *std.Build.Module) void {
    const server = b.addExecutable(.{ .name = "h2-server", .root_module = testing });
    const run = b.addRunArtifact(server);
    if (b.args) |args| run.addArgs(args);
    const step = b.step("h2-server", "Run the test-only h2 server: -- --port <port> [--tls <identity-prefix>]");
    step.dependOn(&run.step);
    b.installArtifact(server);
}

/// The cleartext h2 client of design §9, which `tools/h2_interop.sh` runs against other
/// implementations' servers. It is built from the `testing_client` module and is never part of
/// the library.
fn add_h2_client_step(b: *std.Build, testing_client: *std.Build.Module) void {
    const client = b.addExecutable(.{ .name = "h2-client", .root_module = testing_client });
    const run = b.addRunArtifact(client);
    if (b.args) |args| run.addArgs(args);
    const step = b.step("h2-client", "Run the test-only cleartext h2 client: -- --port <port> --get <path>");
    step.dependOn(&run.step);
    b.installArtifact(client);
}

/// `zig build tls-handshake -- <port> <spki-path> <hostname>`: one TLS 1.3 handshake against a
/// server that is not colibri's, which is the first half of design §8 step 5's check. It needs a
/// chapulin checkout and a listening peer, so it is never part of `zig build test`.
fn add_tls_handshake_step(b: *std.Build, testing_tls: *std.Build.Module) void {
    const check = b.addExecutable(.{ .name = "tls-handshake", .root_module = testing_tls });
    const run = b.addRunArtifact(check);
    if (b.args) |args| run.addArgs(args);
    const step = b.step("tls-handshake", "Run one TLS handshake against a peer: -- <port> <spki> <host>");
    step.dependOn(&run.step);
    b.installArtifact(check);
}

/// `zig build tls-accept -- <port> <identity-prefix>`: one TLS 1.3 handshake as the server
/// against a client that is not colibri's, then one record each way, which is the second half of
/// design §8 step 5's check. It needs a chapulin checkout built `ROLE=server` and a peer that
/// connects, so it is never part of `zig build test`.
fn add_tls_accept_step(b: *std.Build, testing_tls_server: *std.Build.Module) void {
    const check = b.addExecutable(.{ .name = "tls-accept", .root_module = testing_tls_server });
    const run = b.addRunArtifact(check);
    if (b.args) |args| run.addArgs(args);
    const step = b.step("tls-accept", "Accept one TLS handshake from a peer: -- <port> <identity-prefix>");
    step.dependOn(&run.step);
    b.installArtifact(check);
}

/// `zig build quic-loopback -- <identity-prefix> <hostname> <unix-seconds>`: one QUIC handshake and
/// one stream between two colibri connections over chapulin, in one process. It needs a chapulin
/// checkout built `TRANSPORT=quic-nonblocking ROLE=both`, so it is never part of `zig build test`.
fn add_quic_loopback_step(b: *std.Build, testing_quic: *std.Build.Module) void {
    const check = b.addExecutable(.{ .name = "quic-loopback", .root_module = testing_quic });
    const run = b.addRunArtifact(check);
    if (b.args) |args| run.addArgs(args);
    const step = b.step("quic-loopback", "Run colibri's QUIC client and server over chapulin: -- <identity> <host> <seconds>");
    step.dependOn(&run.step);
    b.installArtifact(check);
}

/// `zig build quic-udp -- server|client ...`: design §9's UDP QUIC endpoint, as the hq-interop
/// server or client. It needs a chapulin checkout built `TRANSPORT=quic-nonblocking ROLE=both`.
/// `zig build qif -- encode|decode ...`: design §9's two QPACK command-line tools, for the QIF
/// interop of step 11.
fn add_qif_step(b: *std.Build, testing_qif: *std.Build.Module) void {
    const tool = b.addExecutable(.{ .name = "qif", .root_module = testing_qif });
    const run = b.addRunArtifact(tool);
    if (b.args) |args| run.addArgs(args);
    const step = b.step("qif", "Run a QIF tool: -- encode|decode <input> <output> <capacity> <blocked> [<ack>]");
    step.dependOn(&run.step);
    b.installArtifact(tool);
}

fn add_quic_udp_step(b: *std.Build, testing_udp: *std.Build.Module) void {
    const endpoint = b.addExecutable(.{ .name = "quic-udp", .root_module = testing_udp });
    const run = b.addRunArtifact(endpoint);
    if (b.args) |args| run.addArgs(args);
    const step = b.step("quic-udp", "Run the UDP QUIC endpoint: -- server|client ...");
    step.dependOn(&run.step);
    b.installArtifact(endpoint);
}

fn add_hooks_step(b: *std.Build) void {
    const run = b.addSystemCommand(&.{ "git", "config", "core.hooksPath", hooks_directory });
    const step = b.step("hooks", "Point this clone's core.hooksPath at " ++ hooks_directory);
    step.dependOn(&run.step);
}
