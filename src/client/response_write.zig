//! Writes a response into the `Response` the caller placed (decisions 100 and 123): the final
//! status, its header section, its content and its trailer section, each in the caller's memory
//! (decision 152). A section or content that does not fit is refused whole, and the exchange ends
//! `too_large`.
//! Content in a coding the client offered is decoded into the caller's memory (`coding.zig`,
//! decision 101).
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("event.zig");
const slots_module = @import("slots.zig");
const coding = @import("coding.zig");
const event_internal = @import("event_internal.zig");
const headers = @import("headers.zig");

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

/// Records a final response's status and its header section, from the regular field lines of
/// `section`, which start at index `first`, and what its Content-Encoding says of its content,
/// given the decoders the slot took for the codings its request offered.
pub fn record_head(slot: *Slot, status: u16, section: *const FieldSection, first: u32) Error!void {
    const response = slot.response;
    assert(response.status == event_internal.no_status and response.headers.len == 0);
    assert(first <= section.len());
    response.status = @enumFromInt(status);
    try headers.record(&response.headers, section, first);
    coding.begin(slot, status, section, first);
}

/// Records a response's trailer section, which RFC 9110 §6.5.1 keeps apart from its headers.
pub fn record_trailers(slot: *Slot, section: *const FieldSection) Error!void {
    const response = slot.response;
    assert(response.trailers.len == 0);
    try headers.record(&response.trailers, section, 0);
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

/// Copies the start of `octets` into the caller's empty `body`, as much as it holds, as the next
/// piece of a streamed response (decision 153 ruling 7), and returns the octets copied. The piece
/// is held, and its `body` event owed, until the caller releases it.
pub fn hold_piece(slot: *Slot, octets: []const u8) usize {
    assert(octets.len > 0);
    const room = piece_room(slot);
    const len = @min(octets.len, room.len);
    @memcpy(room[0..len], octets[0..len]);
    hold_len(slot, len);
    return len;
}

/// The caller's empty `body`, where the next piece of a streamed response goes.
pub fn piece_room(slot: *const Slot) []u8 {
    assert(slot.request.streamed.response and !slot.body_held);
    assert(slot.response.body_len == 0 and slot.response.body.len > 0);
    return slot.response.body;
}

/// Holds the first `len` octets of the caller's `body` as the next piece, which the connection
/// wrote there itself, as `hold_piece` does once it copied them.
pub fn hold_len(slot: *Slot, len: usize) void {
    assert(len > 0 and len <= piece_room(slot).len);
    slot.response.body_len = len;
    slot.body_held = true;
    slot.body_owed = true;
}

/// The caller gave back the piece `body` held. Returns its octets, the flow credit the connection
/// gives back for it (RFC 9113 §6.9, RFC 9000 §4.1).
pub fn release_piece(slot: *Slot) usize {
    assert(slot.body_held and !slot.body_owed);
    const len = slot.response.body_len;
    slot.response.body_len = 0;
    slot.body_held = false;
    return len;
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

test "decision 152: a final head copies its regular field lines, and the status apart" {
    test_section.init();
    try test_section.append(":status", "200");
    try test_section.append("cache-control", "max-age=60");
    try test_section.append("content-type", "application/dns-message");
    var buffer: [128]u8 = undefined;
    var response: Response = .{ .headers = .{ .buffer = &buffer } };
    event_internal.clear(&response);
    var slot: Slot = .{ .stage = .sent, .request = &test_request, .response = &response };
    try record_head(&slot, 200, &test_section, 1);
    try testing.expectEqual(200, @intFromEnum(response.status));
    try testing.expectEqualStrings("max-age=60", response.headers.get("cache-control").?);
    try testing.expectEqual(null, response.headers.get(":status"));
    try testing.expectEqual(0, response.trailers.len);
}

test "RFC 9110 §6.5.1: trailers go to their own buffer, never to the headers" {
    test_section.init();
    try test_section.append("grpc-status", "0");
    var header_buffer: [32]u8 = undefined;
    var trailer_buffer: [32]u8 = undefined;
    var response: Response = .{ .headers = .{ .buffer = &header_buffer }, .trailers = .{ .buffer = &trailer_buffer } };
    var slot: Slot = .{ .stage = .sent, .request = &test_request, .response = &response };
    try record_trailers(&slot, &test_section);
    try testing.expectEqualStrings("0", response.trailers.get("grpc-status").?);
    try testing.expectEqual(null, response.headers.get("grpc-status"));
}

test "a section or content past the caller's memory is refused whole" {
    test_section.init();
    try test_section.append("content-type", "application/dns-message");
    var buffer: [8]u8 = undefined;
    var body: [4]u8 = undefined;
    var response: Response = .{ .headers = .{ .buffer = &buffer }, .body = &body };
    event_internal.clear(&response);
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
