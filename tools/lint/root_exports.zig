//! root-exports: the root of a library module exports names and never a file.
//!
//! Zig has file-private and `pub` and nothing between, so `src/<module>/<module>.zig` is the one
//! place a name becomes public (decision 115; CLAUDE.md, "The public API is written first"). A
//! line such as `pub const frame = @import("frame.zig");` exports every `pub` of that file, the
//! ones its neighbours call too. The rule refuses it in the root of each library module, in three
//! shapes:
//!   1. `pub const frame = @import("frame.zig");`
//!   2. `pub const frame = files.frame;`, the file through the root's private `files` struct;
//!   3. `pub const frame = frame_file;`, the file through a private `const` that imports it.
//!
//! `constants` is exported whole in every module (decision 35), and `error_code` in `quic`, the
//! registry of RFC 9000 §20.1.
//!
//! The rule also requires the root to list what it exports in a test: a call of
//! `public_names.expect(@This(), ...)`, or a read of `@typeInfo(@This())` in a module that cannot
//! import `core`.
//!
//! It reads lines and not the parsed tree. `zig fmt` writes each top-level declaration at column 0,
//! and the format check refuses any other spelling. A declaration spread over several lines is not
//! read, so a root spells each export on one line.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const report = lint.report;

pub const name = "root-exports";

/// The fifteen library modules (docs/design.md §3). The root of each is `src/<name>/<name>.zig`.
const library_modules = [_][]const u8{
    "core",   "wire",         "http", "hpack",  "qpack",
    "crypto", "tls_provider", "tls",  "qlog",   "h11",
    "h2",     "h3",           "quic", "server", "client",
};

/// A file a root exports whole: in `module` alone, or in every module when it names none.
const Whole = struct {
    module: ?[]const u8,
    file: []const u8,
};

const whole_files = [_]Whole{
    .{ .module = null, .file = "constants" },
    .{ .module = "quic", .file = "error_code" },
};

const public_prefix = "pub const ";
const private_prefix = "const ";
const assignment = " = ";
const terminator = ";";
const import_prefix = "@import(\"";
const import_suffix = ".zig\")";
const files_prefix = "files.";

/// What a root's list of its exports reads. One of these appears in the test that pins the list.
const list_reads = [_][]const u8{ "public_names.expect(@This(),", "@typeInfo(@This())" };

/// The line a finding about a whole file is reported on.
const file_line: usize = 1;

/// Longest root path the rule builds to compare with a file's.
const max_path_bytes: usize = 256;

/// One top-level declaration of the form `const name = initializer;`.
const Declaration = struct {
    name: []const u8,
    initializer: []const u8,
};

pub fn check(context: *report.Context, file: report.File) !void {
    const module = module_of(file.path) orelse return;
    var listed = false;
    var line_number: usize = 0;
    var lines = std.mem.splitScalar(u8, file.source, '\n');
    while (lines.next()) |line| {
        line_number += 1;
        if (reads_list(line)) listed = true;
        const declaration = declaration_of(line, public_prefix) orelse continue;
        if (!exports_file(file.source, declaration.initializer)) continue;
        if (allowed(module, declaration)) continue;
        try context.findings.add(
            name,
            file.path,
            line_number,
            1,
            "the root exports the file behind {s} whole; export the names a caller uses, each" ++
                " under its file's namespace (decision 115)",
            .{declaration.name},
        );
    }
    if (listed) return;
    try context.findings.add(
        name,
        file.path,
        file_line,
        1,
        "the root has no test that lists what it exports; call public_names.expect(@This(), ...)" ++
            " (decision 115)",
        .{},
    );
}

/// The library module whose root `path` is, or null.
fn module_of(path: []const u8) ?[]const u8 {
    var buffer: [max_path_bytes]u8 = undefined;
    for (library_modules) |module| {
        const root = std.fmt.bufPrint(&buffer, "src/{s}/{s}.zig", .{ module, module }) catch continue;
        if (lint.paths.ends_with_path(path, root)) return module;
    }
    return null;
}

fn reads_list(line: []const u8) bool {
    for (list_reads) |read| {
        if (std.mem.indexOf(u8, line, read) != null) return true;
    }
    return false;
}

/// Reads `line` as a declaration that starts with `prefix` at column 0 and ends on the line.
fn declaration_of(line: []const u8, prefix: []const u8) ?Declaration {
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const rest = line[prefix.len..];
    const equals = std.mem.indexOf(u8, rest, assignment) orelse return null;
    if (!std.mem.endsWith(u8, rest, terminator)) return null;
    return .{
        .name = rest[0..equals],
        .initializer = rest[equals + assignment.len .. rest.len - terminator.len],
    };
}

/// Whether `initializer` is a whole file: an import of one, a member of `files`, or a private
/// name of `source` that imports one.
fn exports_file(source: []const u8, initializer: []const u8) bool {
    if (imports_file(initializer)) return true;
    if (std.mem.startsWith(u8, initializer, files_prefix)) {
        return is_identifier(initializer[files_prefix.len..]);
    }
    if (!is_identifier(initializer)) return false;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        const declaration = declaration_of(line, private_prefix) orelse continue;
        if (!std.mem.eql(u8, declaration.name, initializer)) continue;
        return imports_file(declaration.initializer);
    }
    return false;
}

fn imports_file(initializer: []const u8) bool {
    return std.mem.startsWith(u8, initializer, import_prefix) and
        std.mem.endsWith(u8, initializer, import_suffix);
}

fn is_identifier(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |octet| {
        if (!std.ascii.isAlphanumeric(octet) and octet != '_') return false;
    }
    return true;
}

/// Whether `module` may export this file whole: the declaration imports `<file>.zig` under the
/// file's own name, and the file is one `whole_files` names for the module.
fn allowed(module: []const u8, declaration: Declaration) bool {
    for (whole_files) |whole| {
        if (whole.module) |only| {
            if (!std.mem.eql(u8, only, module)) continue;
        }
        if (!std.mem.eql(u8, declaration.name, whole.file)) continue;
        const imported = declaration.initializer;
        if (!imports_file(imported)) continue;
        const stem = imported[import_prefix.len .. imported.len - import_suffix.len];
        if (std.mem.eql(u8, stem, whole.file)) return true;
    }
    return false;
}

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

fn expect_findings(path: []const u8, source: [:0]const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), @This(), path, source);
    try harness.expect_messages(findings, expected);
}

fn whole_message(comptime exported: []const u8) []const u8 {
    return "the root exports the file behind " ++ exported ++ " whole; export the names a caller" ++
        " uses, each under its file's namespace (decision 115)";
}

const unlisted_message = "the root has no test that lists what it exports; call" ++
    " public_names.expect(@This(), ...) (decision 115)";

const curated_fixture: [:0]const u8 =
    \\const std = @import("std");
    \\pub const core = @import("core");
    \\pub const constants = @import("constants.zig");
    \\const files = struct {
    \\    pub const frame = @import("frame/frame.zig");
    \\};
    \\pub const Frame = files.frame.Frame;
    \\pub const frame = struct {
    \\    pub const read = files.frame.read;
    \\};
    \\test "the root lists what it exports" {
    \\    try core.public_names.expect(@This(), &.{ "core", "constants", "Frame", "frame" });
    \\}
;

test "root-exports passes a root of names, its constants and the modules it re-exports" {
    try expect_findings("src/h2/h2.zig", curated_fixture, &.{});
}

test "root-exports refuses a file exported whole, in each of the three shapes" {
    try expect_findings("src/h2/h2.zig",
        \\const frame_file = @import("frame/frame.zig");
        \\const files = struct {
        \\    pub const stream = @import("stream.zig");
        \\};
        \\pub const settings = @import("settings.zig");
        \\pub const stream = files.stream;
        \\pub const frame = frame_file;
        \\test "the root lists what it exports" {
        \\    try core.public_names.expect(@This(), &.{ "settings", "stream", "frame" });
        \\}
    , &.{ whole_message("settings"), whole_message("stream"), whole_message("frame") });
}

test "root-exports refuses a root with no test that lists its exports" {
    try expect_findings("src/h2/h2.zig",
        \\pub const constants = @import("constants.zig");
        \\pub const Frame = @import("frame/frame.zig").Frame;
    , &.{unlisted_message});
}

test "root-exports passes the list a module with no core reads from @typeInfo" {
    try expect_findings("src/qlog/qlog.zig",
        \\pub const constants = @import("constants.zig");
        \\test "the root lists what it exports" {
        \\    const declared = @typeInfo(@This()).@"struct".decls;
        \\    _ = declared;
        \\}
    , &.{});
}

test "root-exports lets quic alone export error_code, and no root export another file as constants" {
    const registry: [:0]const u8 =
        \\pub const error_code = @import("error_code.zig");
        \\test "the root lists what it exports" {
        \\    try core.public_names.expect(@This(), &.{"error_code"});
        \\}
    ;
    try expect_findings("src/quic/quic.zig", registry, &.{});
    try expect_findings("src/h3/h3.zig", registry, &.{whole_message("error_code")});
    try expect_findings("src/h3/h3.zig",
        \\pub const constants = @import("frame.zig");
        \\test "the root lists what it exports" {
        \\    try core.public_names.expect(@This(), &.{"constants"});
        \\}
    , &.{whole_message("constants")});
}

test "root-exports reads the roots of the library modules alone" {
    const source: [:0]const u8 = "pub const frame_ack = @import(\"frame_ack.zig\");";
    for ([_][]const u8{
        "src/quic/frame/frame.zig",
        "src/h2/frame/frame.zig",
        "src/sim/sim.zig",
        "src/golden/golden.zig",
        "tools/lint/main.zig",
    }) |path| {
        try expect_findings(path, source, &.{});
    }
}
