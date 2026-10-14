//! The checks on the method of a route (decision 122, design §8 step 21e). They run at compile
//! time. A route names a method in one of three ways:
//!   - an enum literal that names a member of `http.method.Standard`: `.get`;
//!   - a value of `http.method.Standard`: `http.method.Standard.get`;
//!   - the token of a method outside RFC 9110 §9.1's eight: `"PATCH"`.
//!
//! A method is checked in this order (invariant 7):
//!   1. an enum literal names a member of `Standard`, or `method_unknown`;
//!   2. a standard method is not CONNECT, or `method_connect`;
//!   3. a method that is not standard is text, or `method_type`;
//!   4. the text is a token, or `method_not_token`;
//!   5. the token is not one of the eight, or `method_standard_as_token`.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const routes_pattern = @import("routes_pattern.zig");

const Standard = http.method.Standard;

/// Why a method does not compile.
pub const Refusal = enum {
    method_unknown,
    method_not_token,
    method_standard_as_token,
    method_connect,
    method_type,

    /// The sentence that the compile error writes after the refusal's name.
    pub fn reason(refusal: Refusal) []const u8 {
        return switch (refusal) {
            .method_unknown => "no member of http.method.Standard has this name; write a method " ++
                "outside RFC 9110's eight as its token, such as \"PATCH\"",
            .method_not_token => "a method is a token (RFC 9110 §9.1)",
            .method_standard_as_token => "write a method of RFC 9110's eight as its enum literal, such as .get",
            .method_connect => "a CONNECT request has no path (RFC 9110 §9.3.6, decision 19)",
            .method_type => "a method is an enum literal, a value of http.method.Standard, or a token",
        };
    }
};

/// The verdict on a route's method, or null when the method can match a request. Comptime-only.
pub fn refusal_of(comptime method: anytype) ?Refusal {
    const Method = @TypeOf(method);
    if (Method == @EnumLiteral()) {
        if (!@hasField(Standard, @tagName(method))) return .method_unknown;
        return standard_refusal(@field(Standard, @tagName(method)));
    }
    if (Method == Standard) return standard_refusal(method);
    if (!routes_pattern.is_text(Method)) return .method_type;
    // RFC 9110 §9.1: method = token.
    http.method.validate(method) catch return .method_not_token;
    // https://github.com/c4milo/colibri/issues/96: a table names a method of RFC 9110 §9.1's
    // eight by its member of `Standard`.
    if (http.method.standard(method) != null) return .method_standard_as_token;
    return null;
}

fn standard_refusal(comptime method: Standard) ?Refusal {
    // RFC 9110 §9.3.6, RFC 9112 §3.2.3, RFC 9113 §8.5 and RFC 9114 §4.4: a CONNECT request names
    // an authority and no path. Decision 19 refuses the extended CONNECT, which has a path.
    if (method == .connect) return .method_connect;
    return null;
}

/// The token that a request carries for a route's method, which `refusal_of` passed.
/// Comptime-only.
pub fn token_of(comptime method: anytype) []const u8 {
    assert(refusal_of(method) == null);
    const standard = standard_of(method) orelse return method;
    const name = @tagName(standard);
    var token: [name.len]u8 = undefined;
    _ = std.ascii.upperString(&token, name);
    const final = token;
    // RFC 9110 §9.1: the table of methods writes each standard method's token in uppercase.
    assert(http.method.standard(&final).? == standard);
    return &final;
}

/// Where a route's method goes in an Allow value: the standard methods in the order of RFC 9110
/// §9.1's table, which is `Standard`'s order, and after them every token. Comptime-only.
pub fn rank_of(comptime method: anytype) usize {
    const standard = standard_of(method) orelse return @typeInfo(Standard).@"enum".fields.len;
    return @intFromEnum(standard);
}

fn standard_of(comptime method: anytype) ?Standard {
    if (@TypeOf(method) == @EnumLiteral()) return @field(Standard, @tagName(method));
    if (@TypeOf(method) == Standard) return method;
    return null;
}
