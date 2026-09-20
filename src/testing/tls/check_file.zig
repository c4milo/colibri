//! Reading a file and an exit code, shared by the two TLS checks of design §8 step 5.
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
