//! Reading and writing a file, and an exit code, shared by design §9's test-only entry points.
//!
//! The reads go through libc rather than a reader that allocates, because no source file under
//! `src/` takes an allocator (CLAUDE.md non-negotiable 4), test-only or not. `src/testing/` is
//! the one directory permitted to touch a descriptor at all.
const std = @import("std");

/// A path, held null-terminated for libc. Long enough for any path a run uses.
pub const path_len_max: usize = 4096;
var path_storage: [path_len_max:0]u8 = undefined;

pub const exit_usage: u8 = 2;
pub const exit_failed: u8 = 1;

/// Reads one part of a set the peer wrote, whose path is the prefix and the suffix.
pub fn read_part(prefix: []const u8, suffix: []const u8, into: []u8) ![]const u8 {
    var joined: [path_len_max]u8 = undefined;
    if (prefix.len + suffix.len >= joined.len) std.process.exit(exit_usage);
    @memcpy(joined[0..prefix.len], prefix);
    @memcpy(joined[prefix.len..][0..suffix.len], suffix);
    return read_file(joined[0 .. prefix.len + suffix.len], into);
}

/// Reads one part of a set when the peer wrote it, and answers null when it did not.
pub fn read_part_if_present(prefix: []const u8, suffix: []const u8, into: []u8) ?[]const u8 {
    var joined: [path_len_max:0]u8 = undefined;
    if (prefix.len + suffix.len >= joined.len) std.process.exit(exit_usage);
    @memcpy(joined[0..prefix.len], prefix);
    @memcpy(joined[prefix.len..][0..suffix.len], suffix);
    joined[prefix.len + suffix.len] = 0;
    const descriptor = std.c.open(&joined, .{});
    if (descriptor < 0) return null;
    _ = std.c.close(descriptor);
    return read_file(joined[0 .. prefix.len + suffix.len], into) catch null;
}

/// Reads up to `into.len` octets of `path`, and returns what it read.
pub fn read_file(path: []const u8, into: []u8) ![]const u8 {
    if (path.len >= path_storage.len) std.process.exit(exit_usage);
    @memcpy(path_storage[0..path.len], path);
    path_storage[path.len] = 0;
    const descriptor = std.c.open(&path_storage, .{});
    if (descriptor < 0) {
        std.debug.print("cannot read {s}\n", .{path});
        std.process.exit(exit_usage);
    }
    defer _ = std.c.close(descriptor);
    var written: usize = 0;
    // Bounded by the caller's slice: a read of zero is the end of the file.
    while (written < into.len) {
        const read = std.c.read(descriptor, into[written..].ptr, into.len - written);
        if (read <= 0) break;
        written += @intCast(read);
    }
    return into[0..written];
}

/// Writes `octets` to `path`, creating it or replacing what it held, and answers false when it
/// cannot.
pub fn write_file(path: []const u8, octets: []const u8) bool {
    if (path.len >= path_storage.len) std.process.exit(exit_usage);
    @memcpy(path_storage[0..path.len], path);
    path_storage[path.len] = 0;
    const descriptor = std.c.open(&path_storage, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, file_mode);
    if (descriptor < 0) return false;
    defer _ = std.c.close(descriptor);
    var written: usize = 0;
    // Bounded by `octets`: a write of zero or less is a failure.
    while (written < octets.len) {
        const wrote = std.c.write(descriptor, octets[written..].ptr, octets.len - written);
        if (wrote <= 0) return false;
        written += @intCast(wrote);
    }
    return true;
}

/// Owner read and write, group and others read.
const file_mode: std.c.mode_t = 0o644;
