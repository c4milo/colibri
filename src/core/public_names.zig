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

/// References every name `Root` exports, and each public declaration of each namespace it
/// declares, so a name the root exports and no file declares fails the build. `modules` names the
/// modules the root re-exports, which check their own. Returns how many names it referenced.
pub fn reference(comptime Root: type, comptime modules: []const []const u8) usize {
    var count: usize = 0;
    inline for (@typeInfo(Root).@"struct".decls) |declaration| {
        const skipped = comptime for (modules) |name| {
            if (std.mem.eql(u8, name, declaration.name)) break true;
        } else false;
        if (!skipped) count += reference_one(Root, declaration.name);
    }
    return count;
}

fn reference_one(comptime Namespace: type, comptime name: []const u8) usize {
    const value = @field(Namespace, name);
    _ = &value;
    var count: usize = 1;
    if (@TypeOf(value) != type or @typeInfo(value) != .@"struct") return count;
    // A namespace holds declarations and no field.
    if (@typeInfo(value).@"struct".fields.len != 0) return count;
    inline for (@typeInfo(value).@"struct".decls) |declaration| count += reference_one(value, declaration.name);
    return count;
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

const SampleRoot = struct {
    pub const module = struct {
        pub const unseen: u8 = 0;
    };
    pub const limit: u8 = 1;
    pub const namespace = struct {
        pub const first: u8 = 2;
        pub const inner = struct {
            pub const second: u8 = 3;
        };
    };
};

test "decision 115: reference visits each name of a root and of its namespaces, and no module's" {
    // `limit`, `namespace`, `first`, `inner` and `second`.
    const visited: usize = 5;
    try std.testing.expectEqual(visited, reference(SampleRoot, &.{"module"}));
}
