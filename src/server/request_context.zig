//! The request's own object, which each router callback takes after the program's context
//! (decision 163). The root exports it as `server.RequestContext`.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("event.zig");

/// A view of the router's entry for one request, valid during the callback that receives it. A
/// program keeps no pointer to it past that callback.
pub const RequestContext = struct {
    request_id: event.RequestId,
    /// The table's `Values` of this request, for the whole request.
    values_held: Held = .{},
    /// The route's path and query, during the route's `on_request` alone.
    path_held: Held = .{},
    query_held: Held = .{},

    /// The request this context belongs to.
    pub fn id(ctx: *const RequestContext) event.RequestId {
        return ctx.request_id;
    }

    /// The request's values, of the type the route table names as `.Values`. Every request starts
    /// with `.{}`, and each callback of the request reads the same ones (decision 163 ruling 2).
    pub fn values(ctx: *const RequestContext, comptime T: type) *T {
        return held_as(T, ctx.values_held, "values");
    }

    /// The path's parameters, of the type the route names as `.path`. The route's `on_request`
    /// reads them; another callback halts (decision 163 ruling 3).
    pub fn path(ctx: *const RequestContext, comptime P: type) *const P {
        return held_as(P, ctx.path_held, "path");
    }

    /// The query's pairs, of the type the route names as `.query`, during the route's
    /// `on_request` alone (decision 163 ruling 3).
    pub fn query(ctx: *const RequestContext, comptime Q: type) *const Q {
        return held_as(Q, ctx.query_held, "query");
    }
};

/// A pointer the router lends the context, and the name of the type it points to. One that lends
/// nothing is all zero bits, so the router writes none for a route that names no path and no
/// query (design §8 step 50, sub-step 50c).
pub const Held = struct {
    pointer: ?*anyopaque = null,
    /// `@typeName` of the type `pointer` points to. Null with no pointer.
    name: ?[*:0]const u8 = null,

    /// What `of` lends: `item`, which the router owns.
    pub fn of(comptime T: type, item: *T) Held {
        return .{ .pointer = @ptrCast(item), .name = @typeName(T) };
    }
};

comptime {
    // A `Held` is a pointer and a name's address. Where an address is 8 octets, the context is
    // its id and its three `Held`, with no padding.
    assert(@sizeOf(Held) == @sizeOf(?*anyopaque) + @sizeOf(?[*:0]const u8));
    if (@sizeOf(usize) == @sizeOf(u64)) assert(@sizeOf(RequestContext) == @sizeOf(event.RequestId) + @sizeOf([3]Held));
}

/// `held`'s pointer as a `*T`. Decision 163 ruling 3: a call with a type other than the one the
/// router lent, or when it lent none, is a program's error, and halts.
fn held_as(comptime T: type, held: Held, comptime call: []const u8) *T {
    const pointer = held.pointer orelse
        std.debug.panic("server.RequestContext.{s}: this callback has no {s} (decision 163)", .{ call, @typeName(T) });
    // `of` sets the pointer and the name together.
    const name = held.name orelse unreachable;
    if (!names(T, name))
        std.debug.panic("server.RequestContext.{s}: {s} asked, {s} held (decision 163)", .{ call, @typeName(T), name });
    return @ptrCast(@alignCast(pointer));
}

/// Whether `name` is the name of `T`. The compiler most often keeps one copy of a type's name, so
/// the two addresses are compared first, and the octets only when they differ.
fn names(comptime T: type, name: [*:0]const u8) bool {
    const asked: [*:0]const u8 = @typeName(T);
    if (name == asked) return true;
    return std.mem.eql(u8, std.mem.span(name), @typeName(T));
}

const testing = std.testing;
const public_names = @import("core").public_names;

test "decision 115: a RequestContext's calls" {
    try public_names.expect(RequestContext, &.{ "id", "values", "path", "query" });
}

test "design §8 step 50c: a context that lends nothing is zero bits past its id" {
    // The router's pool starts each entry with such a context, and a request writes its id alone.
    const empty: RequestContext = .{ .request_id = event.id_of(0) };
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&empty), 0));
    try testing.expectEqual(null, empty.values_held.pointer);
    try testing.expectEqual(null, empty.path_held.name);
}

test "decision 163: one type's name from two copies is the same name" {
    const Path = struct { name: []const u8 };
    // A copy of the name at another address, as a second copy in a program would be.
    var copy = @typeName(Path).*;
    try testing.expect(names(Path, &copy));
    try testing.expect(names(Path, @typeName(Path)));
    try testing.expect(!names(Path, @typeName(u8)));
    copy[0] ^= 1;
    try testing.expect(!names(Path, &copy));
}

test "decision 163: values, path and query give what the router lent, by type" {
    const Values = struct { user: []const u8 = "", count: u32 = 0 };
    const Path = struct { name: []const u8 };
    var values: Values = .{};
    var path: Path = .{ .name = "ada" };
    var ctx: RequestContext = .{ .request_id = @bitCast(@as(u128, 7)), .values_held = .of(Values, &values), .path_held = .of(Path, &path) };
    ctx.values(Values).count += 1;
    try testing.expectEqual(1, values.count);
    try testing.expectEqualStrings("ada", ctx.path(Path).name);
    try testing.expectEqual(@as(u128, 7), @as(u128, @bitCast(ctx.id())));
}
