//! The request method as RFC 9110 §9.1 models it: an opaque, case-sensitive token (decision 15).
//!
//! colibri does not refuse a method it does not know. A method is valid when it is a token, and
//! `standard` names the eight methods RFC 9110 §9.1 defines when the token is exactly one of them.
//! `get` is a valid method and is not GET: the token is case-sensitive.
//!
//! A method is checked in this order (invariant 7):
//!   1. not empty, or `error.MethodEmpty` (a token is one or more tchar, RFC 9110 §5.6.2);
//!   2. every octet a tchar, or `error.MethodNotToken` (RFC 9110 §9.1).
const std = @import("std");
const core = @import("core");
const field = @import("field.zig");

pub const Error = error{
    MethodEmpty,
    MethodNotToken,
};

/// The methods RFC 9110 §9.1 defines.
pub const Standard = enum { get, head, post, put, delete, connect, options, trace };

/// Each standard method's token, as RFC 9110 §9.1's table writes it.
const tokens = [_]struct { []const u8, Standard }{
    .{ "GET", .get },
    .{ "HEAD", .head },
    .{ "POST", .post },
    .{ "PUT", .put },
    .{ "DELETE", .delete },
    .{ "CONNECT", .connect },
    .{ "OPTIONS", .options },
    .{ "TRACE", .trace },
};

/// Checks that `method` is a token. RFC 9110 §9.1 sets no length limit on a method, and a method
/// travels as a field value in both h2 and h3, where the field-value limit already bounds it.
pub fn validate(method: []const u8) Error!void {
    // RFC 9110 §5.6.2: a token is one or more tchar, so an empty method is not a token.
    if (method.len == 0) return error.MethodEmpty;
    for (method) |octet| {
        // RFC 9110 §9.1: method = token.
        if (!field.is_tchar(octet)) return error.MethodNotToken;
    }
}

/// The standard method `method` names, or null. The comparison is exact: RFC 9110 §9.1 makes the
/// method token case-sensitive.
pub fn standard(method: []const u8) ?Standard {
    for (tokens) |entry| {
        // RFC 9110 §9.1: the method token is case-sensitive.
        if (std.mem.eql(u8, method, entry[0])) return entry[1];
    }
    return null;
}

const testing = std.testing;

test "the eight standard methods are recognised exactly" {
    try testing.expectEqual(Standard.get, standard("GET").?);
    try testing.expectEqual(Standard.head, standard("HEAD").?);
    try testing.expectEqual(Standard.post, standard("POST").?);
    try testing.expectEqual(Standard.put, standard("PUT").?);
    try testing.expectEqual(Standard.delete, standard("DELETE").?);
    try testing.expectEqual(Standard.connect, standard("CONNECT").?);
    try testing.expectEqual(Standard.options, standard("OPTIONS").?);
    try testing.expectEqual(Standard.trace, standard("TRACE").?);
    for (tokens) |entry| try validate(entry[0]);
}

test "a method is case-sensitive, and an unknown token is still a method" {
    try testing.expectEqual(null, standard("get"));
    try testing.expectEqual(null, standard("Get"));
    try testing.expectEqual(null, standard("PATCH"));
    try validate("get");
    try validate("PATCH");
    try validate("M-SEARCH");
}

test "a method that is not a token is refused" {
    try testing.expectError(error.MethodEmpty, validate(""));
    try testing.expectError(error.MethodNotToken, validate("GET "));
    try testing.expectError(error.MethodNotToken, validate("GE(T"));
    try testing.expectError(error.MethodNotToken, validate("G\x00T"));
}

/// Most octets a fuzz input carries. Test-only.
const fuzz_input_len_max = 32;

fn fuzz_validate(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const method = input[0..smith.slice(&input)];
    validate(method) catch return testing.expectEqual(null, standard(method));
    for (method) |octet| try testing.expect(field.is_tchar(octet));
}

test "fuzz: a method that fails validation is never a standard method" {
    try testing.fuzz({}, fuzz_validate, .{ .corpus = &.{
        core.fuzz.input("GET"),
        core.fuzz.input("get"),
        core.fuzz.input(""),
        core.fuzz.input("GE T"),
    } });
}

test "sweep: every method of up to two octets that fails validation is not standard" {
    try core.fuzz.sweep(fuzz_validate, null);
}
