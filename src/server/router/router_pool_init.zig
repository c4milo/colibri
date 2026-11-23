//! The start of a router in place (decision 158 ruling 1,
//! https://github.com/c4milo/colibri/issues/148). `router.* = .{}` copies the router's whole
//! default value from a constant of the program's image, each entry's response, body and state
//! memory too. `init` writes each field that a request reads before it writes it, and no octet of
//! an entry's buffers outside Debug.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const router_call = @import("router_call.zig");

/// The fields of a router, in order. A field that `init` does not know fails the compile.
const router_fields = [_][]const u8{ "entries", "answers", "parameters", "query", "failing_body" };
/// The fields of a router that `init` writes one field down: each holds a buffer it leaves alone.
const router_nested = [_][]const u8{ "parameters", "query" };
/// The fields of an entry, in order. A field that `init` does not know fails the compile.
const entry_fields = [_][]const u8{
    "used", "route",       "response",  "request_context",   "values", "memory", "state",
    "body", "body_stream", "chain_ran", "middleware_states", "held",   "header",
};
/// The fields of an entry that `init` writes one field down: each holds a buffer it leaves alone.
const entry_nested = [_][]const u8{ "body", "held", "header" };

/// Writes each field of `router` and of each of its entries to its default, one field at a time.
/// A field whose default is `undefined` takes no store outside Debug, so no buffer is written.
pub fn init(comptime P: type, comptime Entry: type, router: *P) void {
    comptime check_names(P, &router_fields);
    comptime check_names(Entry, &entry_fields);
    for (&router.entries) |*entry| write_fields(Entry, entry, &entry_nested, &.{});
    write_fields(P, router, &router_nested, &.{"entries"});
    assert(!router.entries[0].used);
    assert(router.parameters.count == 0);
}

/// Writes each field of `value` but those of `skipped` to its default. A field of `nested` is a
/// struct whose own fields are written in turn, so its buffer is not.
inline fn write_fields(
    comptime T: type,
    value: *T,
    comptime nested: []const []const u8,
    comptime skipped: []const []const u8,
) void {
    // A safe build fills an `undefined` field with 0xaa, which writes every buffer whole. Debug
    // keeps that fill, which shows a read of a field the program never wrote (decision 163 as
    // amended on 2026-11-15); ReleaseSafe skips it.
    @setRuntimeSafety(builtin.mode == .Debug);
    inline for (@typeInfo(T).@"struct".fields) |field| {
        if (comptime contains(skipped, field.name)) continue;
        if (comptime contains(nested, field.name)) {
            router_call.reset_to_defaults(field.type, &@field(value, field.name));
        } else {
            // An optional cannot hold an `undefined` default at comptime, so the pointer is read.
            const default: *const field.type = @ptrCast(@alignCast(field.default_value_ptr.?));
            @field(value, field.name) = default.*;
        }
    }
}

fn contains(comptime names: []const []const u8, comptime name: []const u8) bool {
    for (names) |listed| {
        if (std.mem.eql(u8, listed, name)) return true;
    }
    return false;
}

/// Fails the compile when `T`'s fields are not `names`, in order: a new field needs its rule here.
fn check_names(comptime T: type, comptime names: []const []const u8) void {
    const fields = @typeInfo(T).@"struct".fields;
    if (fields.len != names.len) @compileError("router_pool_init: the fields of " ++ @typeName(T) ++ " changed");
    for (fields, names) |field, name| {
        if (!std.mem.eql(u8, field.name, name)) @compileError("router_pool_init: no rule for the field " ++ field.name);
    }
}
