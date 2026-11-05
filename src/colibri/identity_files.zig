//! The PEM files of a server's identity, read at `init` into memory the `Server` holds (design §8
//! step 37e). The reads go through Rotor's own file calls (decision 150 ruling 10): `open_file` and
//! `file_size` from `rotor.sync`, and one `read` operation at a time on a loop of one slot.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");
const Identity = @import("identity.zig").Identity;

/// The memory the two files are read into. `identity.load` wipes `key` before `init` returns.
pub const Text = struct {
    chain: [constants.limits.pem_file_len_max]u8,
    key: [constants.limits.pem_file_len_max]u8,
};

pub const ReadError = rotor.Loop.InitError || rotor.Loop.TickError || error{
    /// No file has the name.
    IdentityFileNotFound,
    /// The program may not open the file. Rotor's `open_file` opens a file to read and to write,
    /// so the program needs both permissions.
    IdentityFileAccessDenied,
    /// The file holds more than `pem_file_len_max` octets.
    IdentityFileTooLong,
    /// The name is empty, holds a zero octet or passes the system's longest path, or the file
    /// could not be measured or read whole.
    IdentityFileUnreadable,
};

/// The loop that reads the files: one operation in flight. A backend whose file calls block makes
/// the read on the loop's thread, which is the thread that calls `init` (Rotor's decision 18).
pub const loop_options: rotor.Loop.Options = .{ .operations = 1, .file_policy = .blocking };
pub const loop_memory_bytes = rotor.Loop.memory_bytes(loop_options);

/// The longest name, with its terminator, that the system opens.
const path_len_max = std.Io.Dir.max_path_bytes;

/// Reads the chain's file and the key's file into `text` on a loop in `loop_memory`, and returns
/// the PEM text of each. The loop ends before this returns, so `run` can use the same memory.
pub fn read(names: Identity.Files, text: *Text, loop_memory: []align(rotor.memory_alignment) u8) ReadError!Identity.Pem {
    assert(loop_memory.len >= loop_memory_bytes);
    var loop: rotor.Loop = undefined;
    try loop.init(loop_memory[0..loop_memory_bytes], loop_options);
    defer loop.deinit();
    const chain = try read_file(&loop, names.chain, &text.chain);
    const key = try read_file(&loop, names.key, &text.key);
    assert(chain.len <= text.chain.len and key.len <= text.key.len);
    return .{ .chain = chain, .key = key };
}

/// Opens `name`, refuses a file longer than `into`, and reads the whole file into `into`.
fn read_file(loop: *rotor.Loop, name: []const u8, into: []u8) ReadError![]const u8 {
    var path: [path_len_max]u8 = undefined;
    if (name.len == 0 or name.len >= path.len) return error.IdentityFileUnreadable;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return error.IdentityFileUnreadable;
    @memcpy(path[0..name.len], name);
    path[name.len] = 0;
    const file = rotor.sync.open_file(path[0..name.len :0], .{ .create = false, .direct = false }) catch |err| return switch (err) {
        error.FileNotFound => error.IdentityFileNotFound,
        error.AccessDenied => error.IdentityFileAccessDenied,
        else => error.IdentityFileUnreadable,
    };
    defer rotor.sync.close_now(file);
    const size = rotor.sync.file_size(file) catch return error.IdentityFileUnreadable;
    if (size > into.len) return error.IdentityFileTooLong;
    const len: usize = @intCast(size);
    var done: usize = 0;
    // Each read that does not fail takes at least one octet, so the file's length bounds the loop.
    for (0..len + 1) |_| {
        if (done == len) return into[0..len];
        const taken = try read_once(loop, file, into[done..len], done);
        // The file became shorter after `file_size` measured it.
        if (taken == 0) return error.IdentityFileUnreadable;
        done += taken;
    }
    unreachable;
}

/// One `read` operation at `offset`, and the octets it took.
fn read_once(loop: *rotor.Loop, file: rotor.Descriptor, into: []u8, offset: usize) ReadError!usize {
    assert(into.len > 0);
    const taken = loop.submit(&.{rotor.Operation.read(0, file, into, offset)}, &.{});
    assert(taken == 1);
    var events: [1]rotor.Event = undefined;
    const count = loop.tick(&events, rotor.constants.wait_ns_max) catch |err| {
        settle(loop, &events);
        return err;
    };
    if (count == 0) {
        settle(loop, &events);
        return error.IdentityFileUnreadable;
    }
    assert(count == 1 and loop.in_flight() == 0);
    const read_len = events[0].outcome() catch return error.IdentityFileUnreadable;
    assert(read_len <= into.len);
    return read_len;
}

/// Ends a read that is still in flight, so the loop can end.
fn settle(loop: *rotor.Loop, events: []rotor.Event) void {
    loop.cancel_all();
    loop.drain(events) catch {};
}

const testing = std.testing;

/// The loop memory and the text the tests place, outside any stack frame. Test-only.
threadlocal var test_loop_memory: [loop_memory_bytes]u8 align(rotor.memory_alignment) = undefined;
threadlocal var test_text: Text align(@alignOf(Text)) = undefined;

/// A directory the tests write their files into, and the names of those files relative to the
/// process's directory, which is where `std.testing.tmpDir` makes the directory. Test-only.
pub const TestDirectory = struct {
    directory: testing.TmpDir,
    chain_name: [path_len_max]u8 = undefined,
    key_name: [path_len_max]u8 = undefined,

    pub fn init() TestDirectory {
        return .{ .directory = testing.tmpDir(.{}) };
    }

    pub fn deinit(self: *TestDirectory) void {
        self.directory.cleanup();
    }

    /// Writes `data` into the chain's file or the key's file, and returns the file's name.
    pub fn write(self: *TestDirectory, comptime which: enum { chain, key }, data: []const u8) ![]const u8 {
        const base = @tagName(which) ++ ".pem";
        const name = switch (which) {
            .chain => &self.chain_name,
            .key => &self.key_name,
        };
        try self.directory.dir.writeFile(testing.io, .{ .sub_path = base, .data = data });
        return std.fmt.bufPrint(name, ".zig-cache/tmp/{s}/{s}", .{ &self.directory.sub_path, base });
    }
};

test "design §8 step 37e: the two files are read whole, up to pem_file_len_max octets" {
    var directory: TestDirectory = .init();
    defer directory.deinit();
    const longest: [constants.limits.pem_file_len_max]u8 = @splat('k');
    const chain = try directory.write(.chain, "chain");
    const key = try directory.write(.key, &longest);
    const pem = try read(.{ .chain = chain, .key = key }, &test_text, &test_loop_memory);
    try testing.expectEqualStrings("chain", pem.chain);
    try testing.expectEqualSlices(u8, &longest, pem.key);
}

test "design §8 step 37e: a file longer than pem_file_len_max is refused" {
    var directory: TestDirectory = .init();
    defer directory.deinit();
    const long: [constants.limits.pem_file_len_max + 1]u8 = @splat('k');
    const chain = try directory.write(.chain, "chain");
    const key = try directory.write(.key, &long);
    try testing.expectError(error.IdentityFileTooLong, read(.{ .chain = chain, .key = key }, &test_text, &test_loop_memory));
    try testing.expectError(error.IdentityFileTooLong, read(.{ .chain = key, .key = chain }, &test_text, &test_loop_memory));
}

test "design §8 step 37e: a missing file, an empty name and a name with a zero octet are refused" {
    var directory: TestDirectory = .init();
    defer directory.deinit();
    const chain = try directory.write(.chain, "chain");
    const missing = ".zig-cache/tmp/colibri-no-such-directory/key.pem";
    try testing.expectError(error.IdentityFileNotFound, read(.{ .chain = chain, .key = missing }, &test_text, &test_loop_memory));
    try testing.expectError(error.IdentityFileNotFound, read(.{ .chain = missing, .key = chain }, &test_text, &test_loop_memory));
    try testing.expectError(error.IdentityFileUnreadable, read(.{ .chain = chain, .key = "" }, &test_text, &test_loop_memory));
    try testing.expectError(error.IdentityFileUnreadable, read(.{ .chain = "chain\x00.pem", .key = chain }, &test_text, &test_loop_memory));
}
