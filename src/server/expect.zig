//! The 100-continue expectation (RFC 9110 §10.1.1): whether a request asks for a 100 (Continue)
//! before it sends its content. The connection owes one for such a request once `receive` reports
//! it, and writes it unless the caller answers with a final status first.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("event.zig");

/// The one expectation RFC 9110 §10.1.1 defines.
const hundred_continue = "100-continue";

/// Whitespace around a list member (RFC 9110 §5.6.1, §5.6.3).
const list_whitespace = " \t";

/// The version from which a server honours the expectation (RFC 9110 §10.1.1).
const version_min: event.Version = .{ .major = 1, .minor = 1 };

/// Whether `request` expects a 100 (Continue) before its content.
pub fn expects_continue(request: event.Request) bool {
    // RFC 9110 §10.1.1: a server MAY omit the 100 when the framing indicates no content.
    if (request.end) return false;
    const version = request.version;
    // RFC 9110 §10.1.1: a server MUST ignore the expectation in an HTTP/1.0 request.
    if (version.major < version_min.major or (version.major == version_min.major and version.minor < version_min.minor)) return false;
    var lines = request.fields.iterator();
    // Bounded: a section holds `field_count_max` lines at most.
    for (0..request.fields.len()) |_| {
        const line = lines.next() orelse return false;
        if (!http.field.names_equal(line.name, "expect")) continue;
        if (names_hundred_continue(line.value)) return true;
    }
    return false;
}

/// Whether the Expect field value `value` holds the 100-continue member. RFC 9110 §10.1.1: the
/// value is case-insensitive.
fn names_hundred_continue(value: []const u8) bool {
    var members = std.mem.splitScalar(u8, value, ',');
    // Bounded: a value of n octets holds at most n + 1 members.
    for (0..value.len + 1) |_| {
        const member = members.next() orelse return false;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, member, list_whitespace), hundred_continue)) return true;
    }
    return false;
}

test {
    _ = @import("expect_test.zig");
}
