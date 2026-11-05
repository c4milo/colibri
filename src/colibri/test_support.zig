//! What the tests of `colibri` share: a source each test passes as the program's, which fills its
//! octets from a counter so every run draws the same octets, a CPU with no fast path, and a
//! directory for the PEM files of `.files`. Test-only.
const std = @import("std");
const tls = @import("tls");
const path_len_max = @import("identity_files.zig").path_len_max;

const testing = std.testing;

pub const Counter = struct {
    next: u8 = 0,

    pub fn random(self: *Counter) tls.Random {
        return tls.Random.init(self, fill);
    }

    fn fill(self: *Counter, buffer: []u8) void {
        for (buffer) |*octet| {
            octet.* = self.next;
            self.next +%= 1;
        }
    }
};

pub fn cpu() tls.Cpu {
    return .{
        .probe = .{ .aes_clmul = .no, .dit = .not_known, .sha256 = .no, .sha512 = .no, .sha3 = .no, .ssse3 = .no, .sse4_1 = .no, .avx2 = .no, .vaes = .no },
        .timing = .not_stated,
    };
}

/// A directory the tests write their files into, and the names of those files relative to the
/// process's directory, which is where `std.testing.tmpDir` makes the directory.
pub const TestDirectory = struct {
    directory: testing.TmpDir,
    chain_name: [path_len_max]u8 = undefined,
    key_name: [path_len_max]u8 = undefined,

    pub const File = enum { chain, key };

    pub fn init() TestDirectory {
        return .{ .directory = testing.tmpDir(.{}) };
    }

    pub fn deinit(self: *TestDirectory) void {
        self.directory.cleanup();
    }

    /// Writes `data` into the chain's file or the key's file, and returns the file's name.
    pub fn write(self: *TestDirectory, comptime which: File, data: []const u8) ![]const u8 {
        const name = switch (which) {
            .chain => &self.chain_name,
            .key => &self.key_name,
        };
        try self.directory.dir.writeFile(testing.io, .{ .sub_path = base_name(which), .data = data });
        return std.fmt.bufPrint(name, ".zig-cache/tmp/{s}/{s}", .{ &self.directory.sub_path, base_name(which) });
    }

    /// The name of the file in the directory.
    pub fn base_name(comptime which: File) []const u8 {
        return @tagName(which) ++ ".pem";
    }
};
