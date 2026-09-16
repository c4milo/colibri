//! Path predicates the rules filter files by. Every rule states its own directories and exempt
//! paths as named constants and asks these functions whether a path falls under them.
//!
//! Paths arrive as the walk built them: the PATH argument joined with the entry's relative path
//! by one `/`, so `src`, `./src` and `/absolute/src` all occur. The predicates compare whole path
//! components, never raw prefixes, so `./src/testing/endpoint.zig` is under `src/testing/` and
//! `mysrc/testing/endpoint.zig` is not.

const std = @import("std");

pub const separator: u8 = '/';

/// The extension of a Zig source file, the files the AST rules read.
pub const zig_extension = ".zig";

pub fn has_extension(path: []const u8, extension: []const u8) bool {
    return std.mem.endsWith(u8, path, extension);
}

/// The last component of the path.
pub fn basename(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, separator) orelse return path;
    return path[slash + 1 ..];
}

/// The path without its last component and the separator before it, or empty when the path is a
/// bare name.
pub fn dirname(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, separator) orelse return "";
    return path[0..slash];
}

/// The basename of the directory holding the path, or empty for a bare name.
pub fn parent_basename(path: []const u8) []const u8 {
    return basename(dirname(path));
}

/// True when `directory`, given as components such as `src/testing`, occurs as consecutive whole
/// components of the path's directory part. A trailing separator on `directory` is ignored, so
/// `src/testing/` and `src/testing` agree.
pub fn is_under(path: []const u8, directory: []const u8) bool {
    const wanted = std.mem.trimEnd(u8, directory, "/");
    const directories = dirname(path);
    var start: usize = 0;
    while (start <= directories.len) {
        const remaining = directories[start..];
        if (std.mem.startsWith(u8, remaining, wanted) and
            (remaining.len == wanted.len or remaining[wanted.len] == separator))
        {
            return true;
        }
        const slash = std.mem.indexOfScalar(u8, remaining, separator) orelse return false;
        start += slash + 1;
    }
    return false;
}

/// True when the path is under any of the listed directories.
pub fn is_under_any(path: []const u8, directories: []const []const u8) bool {
    for (directories) |directory| {
        if (is_under(path, directory)) return true;
    }
    return false;
}

/// True when the path is exactly `suffix` or ends with a separator followed by `suffix`, so
/// `build/modules.zig` matches `./build/modules.zig` and not `notbuild/modules.zig`.
pub fn ends_with_path(path: []const u8, suffix: []const u8) bool {
    if (std.mem.eql(u8, path, suffix)) return true;
    if (path.len <= suffix.len) return false;
    return std.mem.endsWith(u8, path, suffix) and path[path.len - suffix.len - 1] == separator;
}

/// True when the path ends with any of the listed paths.
pub fn ends_with_any_path(path: []const u8, suffixes: []const []const u8) bool {
    for (suffixes) |suffix| {
        if (ends_with_path(path, suffix)) return true;
    }
    return false;
}

/// The path with `suffix` removed from its end, or the whole path when it does not end there.
/// `build/modules.zig` with `build/modules.zig` removed is the empty string, and
/// `/home/me/colibri/build/modules.zig` becomes `/home/me/colibri/`.
pub fn without_suffix(path: []const u8, suffix: []const u8) []const u8 {
    if (!std.mem.endsWith(u8, path, suffix)) return path;
    return path[0 .. path.len - suffix.len];
}

/// Writes `root/relative` into `buffer` with exactly one separator between them: trailing
/// separators on `root` are dropped first, so a directory argument given as `src/` reports
/// `src/core/core.zig` and not `src//core/core.zig`.
pub fn join(buffer: []u8, root: []const u8, relative: []const u8) ![]const u8 {
    const trimmed_root = std.mem.trimEnd(u8, root, "/");
    return std.fmt.bufPrint(buffer, "{s}/{s}", .{ trimmed_root, relative });
}

// Tests.

const testing = std.testing;

test "basename, dirname and parent_basename split at the last separator" {
    try testing.expectEqualStrings("core.zig", basename("src/core/core.zig"));
    try testing.expectEqualStrings("core.zig", basename("core.zig"));
    try testing.expectEqualStrings("src/core", dirname("src/core/core.zig"));
    try testing.expectEqualStrings("", dirname("core.zig"));
    try testing.expectEqualStrings("core", parent_basename("src/core/core.zig"));
    try testing.expectEqualStrings("docs", parent_basename("./docs/design.md"));
    try testing.expectEqualStrings("", parent_basename("README.md"));
}

test "is_under matches whole components anywhere in the directory part" {
    try testing.expect(is_under("src/testing/endpoint.zig", "src/testing/"));
    try testing.expect(is_under("./src/testing/endpoint.zig", "src/testing"));
    try testing.expect(is_under("/home/me/colibri/src/quic/packet/header.zig", "src/quic"));
    try testing.expect(is_under("tools/lint/main.zig", "tools"));
    try testing.expect(!is_under("mysrc/testing/endpoint.zig", "src/testing"));
    try testing.expect(!is_under("src/testingx/endpoint.zig", "src/testing"));
    try testing.expect(!is_under("src/testing", "src/testing"));
    try testing.expect(!is_under("core.zig", "tools"));
}

test "ends_with_path needs a separator before the suffix" {
    try testing.expect(ends_with_path("build/modules.zig", "build/modules.zig"));
    try testing.expect(ends_with_path("./build/modules.zig", "build/modules.zig"));
    try testing.expect(!ends_with_path("notbuild/modules.zig", "build/modules.zig"));
    try testing.expect(!ends_with_path("modules.zig", "build/modules.zig"));
    try testing.expect(ends_with_any_path("./build/modules.zig", &.{ "a.zig", "build/modules.zig" }));
    try testing.expect(!ends_with_any_path("./build/modules.zig", &.{"a.zig"}));
}

test "without_suffix removes the suffix it finds and nothing else" {
    try testing.expectEqualStrings("", without_suffix("build/modules.zig", "build/modules.zig"));
    try testing.expectEqualStrings("./", without_suffix("./build/modules.zig", "build/modules.zig"));
    try testing.expectEqualStrings("a/b.zig", without_suffix("a/b.zig", "c.zig"));
}

test "join drops trailing separators from the root" {
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings("src/core.zig", try join(&buffer, "src", "core.zig"));
    try testing.expectEqualStrings("src/core.zig", try join(&buffer, "src//", "core.zig"));
    try testing.expectEqualStrings("/core.zig", try join(&buffer, "/", "core.zig"));
    var short: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, join(&short, "src", "core.zig"));
}
