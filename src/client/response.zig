//! Writes a response into the exchange the caller placed (decision 100): the final status, the
//! values of the fields the caller named, and the content, each in the caller's memory. A value or
//! content that does not fit is refused whole, and the exchange ends `too_large`.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("event.zig");

const HttpExchange = event.HttpExchange;
const FieldSection = http.FieldSection;

pub const Error = error{
    /// The content passed `body`, or a wanted value passed `values`: the caller's memory is full.
    NoSpaceLeft,
};

/// RFC 9110 §5.3: "use comma SP" between the values of field lines with the same name.
const separator = ", ";

/// Records a final response's status and the values of the fields the caller named, from the
/// regular field lines of `section`, which start at index `first`.
pub fn record_head(exchange: *HttpExchange, status: u16, section: *const FieldSection, first: u32) Error!void {
    assert(exchange.status == 0 and exchange.values_len == 0);
    assert(first <= section.len());
    exchange.status = status;
    for (exchange.wanted) |*wanted| {
        wanted.value = try join(exchange, wanted.name, section, first);
    }
}

/// The value of every field line of `section` named `name`, joined into the exchange's `values`,
/// or null when none is.
fn join(exchange: *HttpExchange, name: []const u8, section: *const FieldSection, first: u32) Error!?[]const u8 {
    const start = exchange.values_len;
    var found = false;
    var iterator: http.field_section.Iterator = .{ .section = section, .index = first };
    // Bounded: the section holds `len()` lines.
    for (0..section.len()) |_| {
        const line = iterator.next() orelse break;
        // RFC 9110 §5.1: field names are case-insensitive.
        if (!std.ascii.eqlIgnoreCase(line.name, name)) continue;
        // RFC 9110 §5.3: a recipient may join field lines with the same name, in order.
        if (found) try append(exchange, separator);
        try append(exchange, line.value);
        found = true;
    }
    if (!found) return null;
    return exchange.values[start..exchange.values_len];
}

fn append(exchange: *HttpExchange, octets: []const u8) Error!void {
    const room = exchange.values.len - exchange.values_len;
    if (octets.len > room) return error.NoSpaceLeft;
    @memcpy(exchange.values[exchange.values_len..][0..octets.len], octets);
    exchange.values_len += octets.len;
}

/// Copies octets of the response's content after those already in `body`.
pub fn append_body(exchange: *HttpExchange, octets: []const u8) Error!void {
    const room = exchange.body.len - exchange.body_len;
    if (octets.len > room) return error.NoSpaceLeft;
    @memcpy(exchange.body[exchange.body_len..][0..octets.len], octets);
    exchange.body_len += octets.len;
    assert(exchange.body_len <= exchange.body.len);
}

const testing = std.testing;

/// A section the tests fill, outside any stack frame. Test-only.
threadlocal var test_section: FieldSection align(@alignOf(FieldSection)) = undefined;

test "RFC 9110 §5.3: the field lines of a wanted name are joined in order, and a missing one is null" {
    test_section.init();
    try test_section.append(":status", "200");
    try test_section.append("cache-control", "max-age=60");
    try test_section.append("content-type", "application/dns-message");
    try test_section.append("Cache-Control", "no-transform");
    var wanted = [_]event.Wanted{ .{ .name = "cache-control" }, .{ .name = "age" }, .{ .name = "Content-Type" } };
    var values: [64]u8 = undefined;
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .wanted = &wanted, .values = &values };
    try record_head(&exchange, 200, &test_section, 1);
    try testing.expectEqual(200, exchange.status);
    try testing.expectEqualStrings("max-age=60, no-transform", wanted[0].value.?);
    try testing.expectEqual(null, wanted[1].value);
    try testing.expectEqualStrings("application/dns-message", wanted[2].value.?);
}

test "a value or content past the caller's memory is refused whole" {
    test_section.init();
    try test_section.append("content-type", "application/dns-message");
    var wanted = [_]event.Wanted{.{ .name = "content-type" }};
    var values: [8]u8 = undefined;
    var body: [4]u8 = undefined;
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .wanted = &wanted, .values = &values, .body = &body };
    try testing.expectError(error.NoSpaceLeft, record_head(&exchange, 200, &test_section, 0));
    try append_body(&exchange, "abc");
    try testing.expectError(error.NoSpaceLeft, append_body(&exchange, "de"));
    try testing.expectEqual(3, exchange.body_len);
    try append_body(&exchange, "d");
    try testing.expectEqualStrings("abcd", body[0..exchange.body_len]);
}
