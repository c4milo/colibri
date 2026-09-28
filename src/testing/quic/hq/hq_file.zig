//! The files hq-interop moves (design §8 step 9e, piece 11): a server reads them from the
//! directory it serves and a client writes them into its downloads directory. It is all the file
//! I/O of the UDP endpoints, through libc, and it allocates nothing: `udp_qlog.zig` writes each
//! connection's qlog through it too, and the server's `h3` mode maps each file it answers with
//! (design §8 step 17b).
//!
//! A path arrives already checked by `hq.read_request` or `hq.write_request`, so joining it to a
//! directory names a file inside it.
const std = @import("std");
const assert = std.debug.assert;
const check_file = @import("../../tls/check_file.zig");

/// A descriptor, and the value that names none.
pub const Descriptor = std.c.fd_t;
pub const none: Descriptor = -1;

/// A file opened for reading, and its length in octets.
pub const Opened = struct {
    descriptor: Descriptor,
    len: u64,
};

/// Owner read and write, and read for everyone else. The QUIC Interop Runner compares a
/// downloaded file as its own user, and on Linux the file keeps the owner the endpoint's container
/// wrote it as, root.
const created_mode: std.c.mode_t = 0o644;

comptime {
    assert(created_mode & 0o004 != 0);
}

/// `directory` and `path` joined into `into`, null-terminated for libc, or null when too long.
fn join(directory: []const u8, path: []const u8, into: *[check_file.path_len_max:0]u8) ?[:0]const u8 {
    assert(path.len > 0 and path[0] == '/');
    const len = directory.len + path.len;
    if (len >= into.len) return null;
    @memcpy(into[0..directory.len], directory);
    @memcpy(into[directory.len..][0..path.len], path);
    into[len] = 0;
    return into[0..len :0];
}

/// Opens `path` under `directory` for reading, or answers null when it is not there.
pub fn open_read(directory: []const u8, path: []const u8) ?Opened {
    var joined: [check_file.path_len_max:0]u8 = undefined;
    const name = join(directory, path, &joined) orelse return null;
    const descriptor = std.c.open(name, .{ .ACCMODE = .RDONLY });
    if (descriptor < 0) return null;
    const end = std.c.lseek(descriptor, 0, std.c.SEEK.END);
    if (end < 0) {
        close(descriptor);
        return null;
    }
    return .{ .descriptor = descriptor, .len = @intCast(end) };
}

/// Creates `path` under `directory` for writing, emptying any file already there, or answers
/// null when it cannot.
pub fn create(directory: []const u8, path: []const u8) ?Descriptor {
    var joined: [check_file.path_len_max:0]u8 = undefined;
    const name = join(directory, path, &joined) orelse return null;
    const descriptor = std.c.open(name, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, created_mode);
    if (descriptor < 0) return null;
    return descriptor;
}

/// Reads up to `output.len` octets at `offset`, and answers how many it read.
pub fn read_at(descriptor: Descriptor, offset: u64, output: []u8) usize {
    assert(descriptor != none);
    const read = std.c.pread(descriptor, output.ptr, output.len, @intCast(offset));
    if (read <= 0) return 0;
    return @intCast(read);
}

/// Writes all of `octets`, and answers false when the file would not take them.
pub fn write_all(descriptor: Descriptor, octets: []const u8) bool {
    assert(descriptor != none);
    var written: usize = 0;
    // Bounded: each pass writes at least one octet or ends the loop.
    while (written < octets.len) {
        const count = std.c.write(descriptor, octets[written..].ptr, octets.len - written);
        if (count <= 0) return false;
        written += @intCast(count);
    }
    return true;
}

pub fn close(descriptor: Descriptor) void {
    assert(descriptor != none);
    _ = std.c.close(descriptor);
}

/// Maps the `len` octets of the file `descriptor` names, read-only, or answers null when the
/// system refuses. The mapping outlives the descriptor, until `unmap`, and the kernel reads each
/// page in when it is first touched.
pub fn map_read(descriptor: Descriptor, len: u64) ?[]const u8 {
    assert(descriptor != none);
    // An empty file maps nothing.
    if (len == 0) return &.{};
    const mapped = std.c.mmap(null, @intCast(len), .{ .READ = true }, .{ .TYPE = .PRIVATE }, descriptor, 0);
    if (mapped == std.c.MAP_FAILED) return null;
    const octets: [*]const u8 = @ptrCast(mapped);
    return octets[0..@intCast(len)];
}

/// Unmaps what `map_read` mapped.
pub fn unmap(mapping: []const u8) void {
    if (mapping.len == 0) return;
    _ = std.c.munmap(@ptrCast(@alignCast(mapping.ptr)), mapping.len);
}
