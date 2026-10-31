//! Writes a response into the `Response` the caller placed (decisions 100 and 123): the final
//! status, the values of the fields the caller named, and the content, each in the caller's memory.
//! A value or content that does not fit is refused whole, and the exchange ends `too_large`.
//! Content in a coding the client offered is decoded into the caller's memory (`coding.zig`,
//! decision 101).
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("event.zig");
const slots_module = @import("slots.zig");
const coding = @import("coding.zig");

const Response = event.Response;
const FieldSection = http.FieldSection;
const Slot = slots_module.Slot;

pub const Error = coding.Error;

/// How an exchange whose response the client refused ends: `too_large` when the caller's memory
/// is full, and `malformed` when its content coding is corrupt (decision 101).
pub fn outcome_of(failure: Error) event.Result {
    return switch (failure) {
        error.NoSpaceLeft => .too_large,
        error.CodingCorrupt => .malformed,
    };
}

/// RFC 9110 §5.3: "use comma SP" between the values of field lines with the same name.
const separator = ", ";

/// Records a final response's status and the values of the fields the caller named, from the
/// regular field lines of `section`, which start at index `first`, and what its Content-Encoding
/// says of its content, given the decoders the slot took for the codings its request offered.
pub fn record_head(slot: *Slot, status: u16, section: *const FieldSection, first: u32) Error!void {
    const response = slot.response;
    assert(response.status == 0 and response.values_len == 0);
    assert(first <= section.len());
    response.status = status;
    for (response.wanted) |*wanted| {
        wanted.value = try join(response, wanted.name, section, first);
    }
    coding.begin(slot, status, section, first);
}

/// The value of every field line of `section` named `name`, joined into the response's `values`,
/// or null when none is.
fn join(response: *Response, name: []const u8, section: *const FieldSection, first: u32) Error!?[]const u8 {
    const start = response.values_len;
    var found = false;
    var iterator: http.field_section.Iterator = .{ .section = section, .index = first };
    // Bounded: the section holds `len()` lines.
    for (0..section.len()) |_| {
        const line = iterator.next() orelse break;
        // RFC 9110 §5.1: field names are case-insensitive.
        if (!std.ascii.eqlIgnoreCase(line.name, name)) continue;
        // RFC 9110 §5.3: a recipient may join field lines with the same name, in order.
        if (found) try append(response, separator);
        try append(response, line.value);
        found = true;
    }
    if (!found) return null;
    return response.values[start..response.values_len];
}

fn append(response: *Response, octets: []const u8) Error!void {
    const room = response.values.len - response.values_len;
    if (octets.len > room) return error.NoSpaceLeft;
    @memcpy(response.values[response.values_len..][0..octets.len], octets);
    response.values_len += octets.len;
}

/// Copies octets of the response's content after those already in `body`, or decodes them there.
pub fn append_body(slot: *Slot, octets: []const u8) Error!void {
    if (coding.active(slot)) return coding.decode(slot, octets);
    const response = slot.response;
    const room = response.body.len - response.body_len;
    if (octets.len > room) return error.NoSpaceLeft;
    @memcpy(response.body[response.body_len..][0..octets.len], octets);
    response.body_len += octets.len;
    assert(response.body_len <= response.body.len);
}

/// Whether the final response that `record_head` just read declares, in its Content-Length, more
/// content than the room left in the caller's `body`, so the exchange ends `too_large` at its
/// head (https://github.com/c4milo/colibri/issues/106). Decoded content has a length no head
/// gives (decision 101), so a response the client decodes is judged as its content arrives.
pub fn too_large_at_head(slot: *const Slot, status: u16, section: *const FieldSection) bool {
    if (coding.active(slot)) return false;
    // RFC 9110 §8.6: the Content-Length of a response to HEAD, or of a 304, counts content that
    // the response does not carry.
    if (http.method.standard(slot.request.method) == .head or status == not_modified) return false;
    // The protocol checked the value before the head was an event (RFC 9112 §6.3, RFC 9113
    // §8.1.1, RFC 9114 §4.1.2), so a value it refused never reaches here.
    const declared = http.content_length.from_section(section) catch return false;
    const response = slot.response;
    return (declared orelse return false) > response.body.len - response.body_len;
}

/// RFC 9110 §15.4.5: 304 (Not Modified).
const not_modified: u16 = 304;

/// The response's content ended whole, which coded content must end with its stream.
pub fn end_body(slot: *Slot) Error!void {
    return coding.end(slot);
}

const testing = std.testing;

/// A section the tests fill, outside any stack frame, and the request each test slot holds.
/// Test-only.
threadlocal var test_section: FieldSection align(@alignOf(FieldSection)) = undefined;
const test_request: event.Request = .{ .method = "GET", .path = "/" };

test "RFC 9110 §5.3: the field lines of a wanted name are joined in order, and a missing one is null" {
    test_section.init();
    try test_section.append(":status", "200");
    try test_section.append("cache-control", "max-age=60");
    try test_section.append("content-type", "application/dns-message");
    try test_section.append("Cache-Control", "no-transform");
    var wanted = [_]event.WantedHeader{ .{ .name = "cache-control" }, .{ .name = "age" }, .{ .name = "Content-Type" } };
    var values: [64]u8 = undefined;
    var response: Response = .{ .wanted = &wanted, .values = &values };
    var slot: Slot = .{ .stage = .sent, .request = &test_request, .response = &response };
    try record_head(&slot, 200, &test_section, 1);
    try testing.expectEqual(200, response.status);
    try testing.expectEqualStrings("max-age=60, no-transform", wanted[0].value.?);
    try testing.expectEqual(null, wanted[1].value);
    try testing.expectEqualStrings("application/dns-message", wanted[2].value.?);
}

test "a value or content past the caller's memory is refused whole" {
    test_section.init();
    try test_section.append("content-type", "application/dns-message");
    var wanted = [_]event.WantedHeader{.{ .name = "content-type" }};
    var values: [8]u8 = undefined;
    var body: [4]u8 = undefined;
    var response: Response = .{ .wanted = &wanted, .values = &values, .body = &body };
    var slot: Slot = .{ .stage = .sent, .request = &test_request, .response = &response };
    try testing.expectError(error.NoSpaceLeft, record_head(&slot, 200, &test_section, 0));
    try append_body(&slot, "abc");
    try testing.expectError(error.NoSpaceLeft, append_body(&slot, "de"));
    try testing.expectEqual(3, response.body_len);
    try append_body(&slot, "d");
    try testing.expectEqualStrings("abcd", body[0..response.body_len]);
}

test "issue 106: a Content-Length past the caller's memory is too large at the head" {
    test_section.init();
    try test_section.append("content-length", "5");
    var body: [4]u8 = undefined;
    var response: Response = .{ .body = &body };
    var slot: Slot = .{ .stage = .sent, .request = &test_request, .response = &response };
    try testing.expect(too_large_at_head(&slot, 200, &test_section));
    test_section.init();
    try test_section.append("content-length", "4");
    try testing.expect(!too_large_at_head(&slot, 200, &test_section));
    test_section.init();
    try testing.expect(!too_large_at_head(&slot, 200, &test_section));
}

test "RFC 9110 §8.6: a HEAD response's or a 304's Content-Length is never too large at the head" {
    test_section.init();
    try test_section.append("content-length", "5");
    var body: [4]u8 = undefined;
    var response: Response = .{ .body = &body };
    const head_request: event.Request = .{ .method = "HEAD", .path = "/" };
    var head_slot: Slot = .{ .stage = .sent, .request = &head_request, .response = &response };
    try testing.expect(!too_large_at_head(&head_slot, 200, &test_section));
    var slot: Slot = .{ .stage = .sent, .request = &test_request, .response = &response };
    try testing.expect(!too_large_at_head(&slot, not_modified, &test_section));
}
