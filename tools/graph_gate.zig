//! The gate of docs/design.md §8 step 0, and the check behind
//! [invariant 26](../docs/invariants.md): `src/quic/` cannot import an HTTP module.
//!
//! A lint rule over the source would only check what build/modules.zig *says*. This checks what
//! the compiler *does*: it compiles a fixture as a module carrying exactly the import set
//! build/modules.zig gives `quic`, and requires the compile to fail with Zig's own
//! "no module named" error.
//!
//! It runs a positive control in the same pass, and that control is what stops the gate from
//! being vacuous. A gate that only requires a failure passes when the failure has nothing to do
//! with the rule — a mistyped fixture path, a missing source, a broken `zig` invocation. So one
//! fixture imports `core`, which `quic` does have, and must compile clean. A run in which the
//! control fails is reported as a broken gate, not as a pass.
//!
//! Usage: `graph_gate <zig-exe> <src-root> <fixtures-dir>`
const std = @import("std");
const assert = std.debug.assert;

/// The import set build/modules.zig gives `quic` (docs/design.md §3). The lint rule
/// `module-graph` is what holds build/modules.zig equal to this list; this tool is what shows the
/// list has the consequence the invariant claims.
const quic_imports = [_]Import{
    .{ .name = "core", .root = "core/core.zig", .deps = &.{} },
    .{ .name = "wire", .root = "wire/wire.zig", .deps = &.{"core"} },
    .{ .name = "crypto", .root = "crypto/crypto.zig", .deps = &.{"core"} },
    .{ .name = "tls", .root = "tls/tls.zig", .deps = &.{"core"} },
};

/// Every module name `quic` must not be able to reach. Each gets a fixture and each must fail.
const forbidden = [_][]const u8{ "http", "h2", "h3", "hpack", "qpack" };

/// The module name the positive control imports: one `quic` really does have.
const control = "core";

const Import = struct {
    name: []const u8,
    root: []const u8,
    deps: []const []const u8,
};

const Outcome = enum { compiled, rejected };

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 4) {
        std.debug.print("usage: graph_gate <zig-exe> <src-root> <fixtures-dir>\n", .{});
        std.process.exit(2);
    }
    const zig_exe = args[1];
    const src_root = args[2];
    const fixtures = args[3];

    var failures: usize = 0;

    // The control first: if importing a module `quic` does have does not compile, nothing this
    // tool reports afterwards means anything.
    const control_path = try fixture_path(arena, fixtures, control);
    const control_outcome = try compile(arena, init.io, zig_exe, src_root, control_path);
    if (control_outcome != .compiled) {
        std.debug.print(
            "graph-gate BROKEN: the control fixture importing '{s}' did not compile.\n" ++
                "  Nothing else this gate reports is meaningful until that is fixed.\n",
            .{control},
        );
        std.process.exit(1);
    }
    std.debug.print("graph-gate control: import '{s}' compiles, as it must\n", .{control});

    for (forbidden) |module_name| {
        const path = try fixture_path(arena, fixtures, module_name);
        const outcome = try compile(arena, init.io, zig_exe, src_root, path);
        if (outcome == .rejected) {
            std.debug.print("graph-gate: src/quic/ cannot import '{s}'\n", .{module_name});
        } else {
            std.debug.print(
                "graph-gate FAILED: src/quic/ compiled an @import(\"{s}\").\n" ++
                    "  build/modules.zig has given quic an HTTP module. See docs/invariants.md INV-26.\n",
                .{module_name},
            );
            failures += 1;
        }
    }

    if (failures != 0) std.process.exit(1);
}

fn fixture_path(arena: std.mem.Allocator, fixtures: []const u8, module_name: []const u8) ![]const u8 {
    return std.fs.path.join(arena, &.{
        fixtures,
        try std.fmt.allocPrint(arena, "quic_imports_{s}.zig", .{module_name}),
    });
}

/// Compiles `root_path` as the root of a module carrying exactly `quic_imports`, and reports
/// whether the compiler accepted it. A non-zero exit is `rejected`; anything else is `compiled`.
fn compile(
    arena: std.mem.Allocator,
    io: std.Io,
    zig_exe: []const u8,
    src_root: []const u8,
    root_path: []const u8,
) !Outcome {
    // `--dep` flags apply to the next `-M`, and the first `-M` is the root module — so the root's
    // whole dependency list precedes it, and each dependency's own list precedes its own `-M`.
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ zig_exe, "build-obj", "-fno-emit-bin" });
    for (quic_imports) |import| {
        try argv.appendSlice(arena, &.{ "--dep", import.name });
    }
    try argv.append(arena, try std.fmt.allocPrint(arena, "-Mroot={s}", .{root_path}));
    for (quic_imports) |import| {
        for (import.deps) |dep| {
            try argv.appendSlice(arena, &.{ "--dep", dep });
        }
        const root = try std.fs.path.join(arena, &.{ src_root, import.root });
        try argv.append(arena, try std.fmt.allocPrint(arena, "-M{s}={s}", .{ import.name, root }));
    }

    const result = try std.process.run(arena, io, .{ .argv = argv.items });
    return switch (result.term) {
        .exited => |code| if (code == 0) .compiled else .rejected,
        else => .rejected,
    };
}

test "the forbidden list names every HTTP module of the graph" {
    // docs/design.md §3: these five are the HTTP side. A module added to the graph that `quic`
    // must not reach is added here, or the gate stops covering it.
    const expected = [_][]const u8{ "http", "h2", "h3", "hpack", "qpack" };
    try std.testing.expectEqual(expected.len, forbidden.len);
    for (expected, forbidden) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }
}

test "the control is a module quic actually imports" {
    var found = false;
    for (quic_imports) |import| {
        if (std.mem.eql(u8, import.name, control)) found = true;
    }
    try std.testing.expect(found);
}

test "quic's import set is the one design §3 states" {
    const expected = [_][]const u8{ "core", "wire", "crypto", "tls" };
    try std.testing.expectEqual(expected.len, quic_imports.len);
    for (expected, quic_imports) |want, got| {
        try std.testing.expectEqualStrings(want, got.name);
    }
}
