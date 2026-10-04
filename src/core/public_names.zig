//! What the tests of decision 115 share: they compare a type's public declarations with the names
//! its test lists, and say which name one list has and the other lacks. Test-only: nothing outside
//! a `test` block references it, so it is never compiled into the library.
const std = @import("std");

/// The names of `T`'s public declarations, in the order its file declares them.
pub fn names(comptime T: type) [@typeInfo(T).@"struct".decls.len][]const u8 {
    const declared = @typeInfo(T).@"struct".decls;
    var held: [declared.len][]const u8 = undefined;
    inline for (declared, &held) |declaration, *name| name.* = declaration.name;
    return held;
}

/// Whether `T`'s public declarations are `expected`, in order.
pub fn matches(comptime T: type, expected: []const []const u8) bool {
    const declared = names(T);
    if (expected.len != declared.len) return false;
    for (expected, declared) |want, have| {
        if (!std.mem.eql(u8, want, have)) return false;
    }
    return true;
}

/// Fails unless `T`'s public declarations are `expected`, in order. It then prints each name that
/// is public and not listed, and each that is listed and not public.
pub fn expect(comptime T: type, expected: []const []const u8) !void {
    if (matches(T, expected)) return;
    const declared = names(T);
    for (declared) |name| {
        if (!contains(expected, name)) std.debug.print("public and not listed: {s}\n", .{name});
    }
    for (expected) |name| {
        if (!contains(&declared, name)) std.debug.print("listed and not public: {s}\n", .{name});
    }
    std.debug.print("the list must name what is public, in the order the file declares it\n", .{});
    return error.TestExpectedEqual;
}

fn contains(list: []const []const u8, name: []const u8) bool {
    for (list) |held| {
        if (std.mem.eql(u8, held, name)) return true;
    }
    return false;
}

const Sample = struct {
    held: u8,

    pub fn first(sample: *const Sample) u8 {
        return sample.held;
    }

    pub fn second(sample: *const Sample) u8 {
        return sample.held;
    }

    fn hidden(sample: *const Sample) u8 {
        return sample.held;
    }
};

test "decision 115: a type's public declarations are its names, in order, and no private one" {
    const sample: Sample = .{ .held = 1 };
    try std.testing.expectEqual(sample.first(), sample.second());
    try std.testing.expectEqual(sample.held, sample.hidden());
    try expect(Sample, &.{ "first", "second" });
    // A name the list lacks, a name the type lacks, and the names out of order each differ.
    try std.testing.expect(!matches(Sample, &.{"first"}));
    try std.testing.expect(!matches(Sample, &.{ "first", "second", "hidden" }));
    try std.testing.expect(!matches(Sample, &.{ "second", "first" }));
}
