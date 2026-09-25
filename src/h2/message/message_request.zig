//! Step 3 of the check order message.zig states, for a request (invariant 7), which are the
//! request rules RFC 9113 §8.3.1 and §8.5 share with RFC 9114 §4.3.1 and §4.4. The rules
//! themselves live in `http.message_request` ([decision 51](../../../docs/decisions.md)); this
//! file names h2's errors for the reasons that module returns.
//!
//! Every one of the eleven maps to an error of the same name, because RFC 9113 and RFC 9114 state
//! all eleven and differ only in the error a violation carries. What RFC 9114 adds and RFC 9113 does
//! not state — the four MUSTs binding `:authority` to `Host` (§4.3.1) — is in neither module:
//! RFC 9113 §8.3.1 has one SHOULD there, and meeting it needs URI normalization colibri's h2 does
//! not implement.
//!
//! Every error is one of message.zig's `Error`: a malformed message, which RFC 9113 §8.1.1 makes
//! a stream error of type PROTOCOL_ERROR.
const std = @import("std");
const http = @import("http");
const message = @import("message.zig");
const message_lines = @import("message_lines.zig");

const Error = message.Error;
const FieldSection = http.FieldSection;
const Seen = message_lines.Seen;

/// Step 3 for a request whose lines `walk` accepted. Returns true when the request is CONNECT.
/// Each reason `http` returns becomes the h2 error RFC 9113 §8 assigns it.
pub fn check(seen: Seen) Error!bool {
    return http.message_request.check(seen) catch |reason| switch (reason) {
        // RFC 9113 §8.3.1: every request includes exactly one valid value for :method.
        error.MethodMissing => error.MethodMissing,
        error.MethodInvalid => error.MethodInvalid,
        // RFC 9113 §8.5: a CONNECT request omits :scheme and :path and carries :authority.
        error.ConnectWithSchemeOrPath => error.ConnectWithSchemeOrPath,
        error.ConnectWithoutAuthority => error.ConnectWithoutAuthority,
        error.ConnectAuthorityInvalid => error.ConnectAuthorityInvalid,
        // RFC 9113 §8.3.1: every other request carries :scheme and :path.
        error.SchemeMissing => error.SchemeMissing,
        error.SchemeInvalid => error.SchemeInvalid,
        error.PathMissing => error.PathMissing,
        error.PathEmpty => error.PathEmpty,
        error.PathInvalid => error.PathInvalid,
        // RFC 9113 §8.3.1: :authority carries no userinfo for an http or https URI.
        error.AuthorityUserinfo => error.AuthorityUserinfo,
    };
}

const testing = std.testing;

/// The section the tests fill, placed outside any stack frame.
var test_section: FieldSection = undefined;

/// A request of the pseudo-headers given, each left out when null, in RFC 9113 §8.3.1's order.
fn request_of(method: ?[]const u8, scheme: ?[]const u8, authority: ?[]const u8, path: ?[]const u8) !*const FieldSection {
    test_section.init();
    if (method) |value| try test_section.append(":method", value);
    if (scheme) |value| try test_section.append(":scheme", value);
    if (authority) |value| try test_section.append(":authority", value);
    if (path) |value| try test_section.append(":path", value);
    return &test_section;
}

fn expect_request(err: Error, section: *const FieldSection) !void {
    try testing.expectError(err, message.validate_request(section));
}

fn expect_accepted(section: *const FieldSection) !void {
    _ = try message.validate_request(section);
}

test "http2/8.1.2.3/1: an empty :path is PathEmpty for http or https in any case, and / and * pass" {
    try expect_request(error.PathEmpty, try request_of("GET", "http", "example.org", ""));
    try expect_request(error.PathEmpty, try request_of("GET", "HTTPS", "example.org", ""));
    try expect_accepted(try request_of("GET", "https", "example.org", "/"));
    try expect_accepted(try request_of("OPTIONS", "http", "example.org", "*"));
    // RFC 9113 §8.3.1 states the rule for http and https URIs only, compared as whole tokens.
    const other_scheme = try message.validate_request(try request_of("GET", "ftp", "example.org", ""));
    try testing.expectEqualStrings("", other_scheme.path.?);
    try expect_accepted(try request_of("GET", "httpx", "example.org", ""));
    try expect_accepted(try request_of("GET", "http2", "example.org", ""));
}

test "an http or https :path that does not start with / is PathInvalid, and a scheme outside them is not held to it" {
    try expect_request(error.PathInvalid, try request_of("GET", "https", "example.org", "foo"));
    try expect_request(error.PathInvalid, try request_of("GET", "HTTP", null, "?q=1"));
    try expect_accepted(try request_of("GET", "https", "example.org", "/foo?q=1"));
    try expect_accepted(try request_of("GET", "http", null, "//"));
    try expect_accepted(try request_of("GET", "httpsx", null, "foo"));
}

test "a :path of * is PathInvalid in a request other than OPTIONS, in any scheme (RFC 9110 §7.1)" {
    try expect_request(error.PathInvalid, try request_of("GET", "https", "example.org", "*"));
    try expect_request(error.PathInvalid, try request_of("options", "http", null, "*"));
    try expect_request(error.PathInvalid, try request_of("GET", "ftp", null, "*"));
    try expect_accepted(try request_of("OPTIONS", "ftp", null, "*"));
    try expect_accepted(try request_of("OPTIONS", "https", null, "/"));
}

test "only a :path of exactly * is the asterisk form: *x takes the rules of any other path" {
    try expect_request(error.PathInvalid, try request_of("OPTIONS", "https", null, "*x"));
    try expect_accepted(try request_of("GET", "ftp", null, "*x"));
    try expect_accepted(try request_of("GET", "ftp", null, "**"));
}

test "http2/8.1.2.3/2, /3, /4: a request without :method, :scheme or :path is refused, in that order" {
    try expect_request(error.MethodMissing, try request_of(null, "http", "example.org", "/"));
    try expect_request(error.SchemeMissing, try request_of("GET", null, "example.org", "/"));
    try expect_request(error.PathMissing, try request_of("GET", "http", "example.org", null));
    try expect_request(error.MethodMissing, try request_of(null, null, null, null));
    try expect_request(error.SchemeMissing, try request_of("GET", null, null, null));
    // RFC 9113 §8.3.1: a request with no authority information to convey omits :authority.
    const no_authority = try message.validate_request(try request_of("GET", "http", null, "/"));
    try testing.expectEqual(null, no_authority.authority);
}

test "an empty :scheme is SchemeInvalid, checked after :scheme is present and before :path is" {
    try expect_request(error.SchemeInvalid, try request_of("GET", "", "example.org", "/"));
    try expect_request(error.SchemeInvalid, try request_of("GET", "", null, null));
    try expect_request(error.SchemeInvalid, try request_of("GET", "", null, ""));
    try expect_accepted(try request_of("GET", "a", null, "/"));
}

test "a :method that is not a token is MethodInvalid, checked before the target rules" {
    try expect_request(error.MethodInvalid, try request_of("", "http", null, "/"));
    try expect_request(error.MethodInvalid, try request_of("GE(T", "http", null, "/"));
    try expect_request(error.MethodInvalid, try request_of("GE(T", null, null, null));
    try expect_request(error.MethodInvalid, try request_of("CONNECT(", "http", null, "/"));
    const patch = try message.validate_request(try request_of("PATCH", "http", null, "/"));
    try testing.expectEqualStrings("PATCH", patch.method);
}

test "only the exact token CONNECT is CONNECT: connect, CONNECTX and CONNEC take the target rules" {
    // The method token is case-sensitive (RFC 9110 §9.1).
    try expect_request(error.SchemeMissing, try request_of("connect", null, "example.org:443", null));
    try expect_request(error.SchemeMissing, try request_of("CONNECTX", null, "a:1", null));
    try expect_request(error.SchemeMissing, try request_of("CONNEC", null, "a:1", null));
    const extended = try message.validate_request(try request_of("CONNECTX", "https", "a:1", "/"));
    try testing.expect(!extended.is_connect);
}

test "a CONNECT request with :authority alone passes, and one with :scheme or :path is ConnectWithSchemeOrPath" {
    const connect = try message.validate_request(try request_of("CONNECT", null, "example.org:443", null));
    try testing.expect(connect.is_connect);
    try testing.expectEqualStrings("CONNECT", connect.method);
    try testing.expectEqualStrings("example.org:443", connect.authority.?);
    try testing.expectEqual(null, connect.scheme);
    try testing.expectEqual(null, connect.path);
    try expect_request(error.ConnectWithSchemeOrPath, try request_of("CONNECT", "https", "example.org:443", null));
    try expect_request(error.ConnectWithSchemeOrPath, try request_of("CONNECT", null, "example.org:443", "/"));
}

test "a CONNECT request without :authority is ConnectWithoutAuthority, checked after :scheme and :path" {
    try expect_request(error.ConnectWithoutAuthority, try request_of("CONNECT", null, null, null));
    try expect_request(error.ConnectWithSchemeOrPath, try request_of("CONNECT", null, null, "/"));
    try expect_request(error.ConnectWithSchemeOrPath, try request_of("CONNECT", "", "", ""));
}

test "a CONNECT :authority without a host, a colon or a decimal port is ConnectAuthorityInvalid" {
    const refused = [_][]const u8{ "", "example.org", "example.org:", ":443", ":", "a:4x3", "a:44/", "a::", "[::1]", "a:\t1" };
    for (refused) |authority| {
        try expect_request(error.ConnectAuthorityInvalid, try request_of("CONNECT", null, authority, null));
    }
    const accepted = [_][]const u8{ "a:0", "a:9", "[::1]:443", "a:b:0123456789", "a:65536" };
    for (accepted) |authority| try expect_accepted(try request_of("CONNECT", null, authority, null));
}

test "an http or https :authority holding userinfo is AuthorityUserinfo, and other schemes are not held to it" {
    const refused = [_][]const u8{ "user@example.org", "user:password@example.org:443", "@example.org", "example.org@", "a@[::1]:443" };
    for (refused) |authority| {
        try expect_request(error.AuthorityUserinfo, try request_of("GET", "https", authority, "/"));
        try expect_request(error.AuthorityUserinfo, try request_of("GET", "HTTP", authority, "/"));
    }
    // The :path rules come first, and a scheme outside http and https is not held to the rule.
    try expect_request(error.PathInvalid, try request_of("GET", "https", "user@example.org", "x"));
    try expect_accepted(try request_of("GET", "ftp", "user@example.org", "/"));
    try expect_accepted(try request_of("GET", "https", "example.org:443", "/"));
    try expect_accepted(try request_of("GET", "https", "[::1]:443", "/"));
    // A CONNECT :authority takes RFC 9113 §8.5's rules, which the rule above does not reach.
    try expect_accepted(try request_of("CONNECT", null, "user@example.org:443", null));
}

test "check reports whether a request is CONNECT, over a record walk filled" {
    const connect = try message_lines.walk(try request_of("CONNECT", null, "a:1", null), .request);
    try testing.expect(try check(connect));
    const get = try message_lines.walk(try request_of("GET", "https", null, "/"), .request);
    try testing.expect(!try check(get));
}
