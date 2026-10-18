//! The test that `Connection.init` writes every field that code reads. A server's connection
//! leaves its h11 session's payload unfilled (`server`'s `make_h11_session`). So the octets
//! `init` leaves are what the storage held before.
const std = @import("std");
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;
const Role = connection_module.Role;
const testing = std.testing;

/// The parts of a connection that `init` leaves as they were. Code writes each part before it
/// reads it. The ring of outstanding requests holds an entry once `outstanding_len` counts it.
/// Each field section holds an octet once `octets_len` counts it, and a line once `count` does.
/// Test-only.
const storage_left_by_init = [_][]const u8{
    "outstanding", "section.octets", "section.lines", "trailers.octets", "trailers.lines",
};

/// Two connections `init` starts over storage filled with zeros and with ones. Test-only.
var over_zeros: Connection align(@alignOf(Connection)) = undefined;
var over_ones: Connection align(@alignOf(Connection)) = undefined;

/// Fails, naming the field, when a field of `T` at any depth holds different octets in `zeros`
/// and `ones`, other than the storage `init` leaves.
fn expect_written(comptime T: type, zeros: *const T, ones: *const T, comptime path: []const u8) !void {
    inline for (storage_left_by_init) |left| {
        if (comptime std.mem.eql(u8, path, left)) return;
    }
    const info = @typeInfo(T);
    if (info == .@"struct" and info.@"struct".layout != .@"packed") {
        inline for (info.@"struct".fields) |field| {
            const inner = if (path.len == 0) field.name else path ++ "." ++ field.name;
            try expect_written(field.type, &@field(zeros.*, field.name), &@field(ones.*, field.name), inner);
        }
        return;
    }
    if (std.mem.eql(u8, std.mem.asBytes(zeros), std.mem.asBytes(ones))) return;
    std.debug.print("first difference: init leaves {s} as the storage held it\n", .{path});
    return error.TestUnexpectedResult;
}

test "init writes every field but the storage it leaves, for each role" {
    for ([_]Role{ .server, .client }) |role| {
        @memset(std.mem.asBytes(&over_zeros), 0);
        @memset(std.mem.asBytes(&over_ones), std.math.maxInt(u8));
        over_zeros.init(role, .{});
        over_ones.init(role, .{});
        try expect_written(Connection, &over_zeros, &over_ones, "");
    }
}
