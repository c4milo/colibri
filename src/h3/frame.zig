//! The HTTP/3 framing layer of RFC 9114 §7. Part of design §8 step 12.
//!
//! Every frame is a type, a length and a payload, all three read from a QUIC stream (§7.1). The
//! header and the payload are read apart, because a DATA frame's payload is as long as the
//! content and arrives over many packets: a reader that wanted the whole frame in one buffer
//! would put the body's size in colibri's memory bound, which decision 35 forbids.
//!
//! **A short read is not a protocol error.** `Truncated` means the octets have not all arrived
//! and the caller should read more; every other error is a connection error and names the code
//! §8.1 gives it. Telling the two apart is the whole point of reading the header on its own.
//!
//! What this file does not do is decide. Which frames a stream may carry is §7.2's table and is
//! `permitted`; what a HEADERS payload means is QPACK's; when a frame is out of order is the
//! connection's.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");

const Reader = core.Reader;
const varint = wire.varint;

pub const Error = core.reader.Error || error{
    /// RFC 9114 §8.1's H3_FRAME_ERROR: a payload with octets after the fields its type defines,
    /// or one that ended before them.
    FrameError,
    /// §8.1's H3_FRAME_UNEXPECTED: a frame that is not permitted on the stream it arrived on, or
    /// one of §11.2.1's HTTP/2 types that MUST NOT be sent.
    FrameUnexpected,
    /// §8.1's H3_SETTINGS_ERROR: a SETTINGS frame this endpoint will not accept.
    SettingsError,
};

/// The error code RFC 9114 §8.1 gives each of those, for the connection to close with.
pub fn error_code(failure: Error) u64 {
    return switch (failure) {
        error.FrameUnexpected => constants.error_frame_unexpected,
        error.SettingsError => constants.error_settings_error,
        // §7.1: a frame truncated by a stream that ended cleanly is H3_FRAME_ERROR too. The
        // caller knows whether the stream ended; here both reach the same code.
        error.FrameError, error.Truncated => constants.error_frame_error,
    };
}

/// The three stream kinds frames travel on (RFC 9114 §7's Table 1).
pub const StreamKind = enum { control, request, push };

/// One frame's header (RFC 9114 §7.1).
pub const Header = struct {
    /// The type as it was on the wire. An unknown type is kept rather than rejected, because
    /// §9 requires an endpoint to ignore one it does not know.
    frame_type: u64,
    /// The payload's length in octets.
    length: u64,

    /// Whether this type carries a payload colibri reads whole (RFC 9114 §7.2). DATA and
    /// HEADERS do not: their payloads are as long as the content and the field section.
    pub fn is_streamed(header: Header) bool {
        return header.frame_type == constants.frame_data or header.frame_type == constants.frame_headers;
    }
};

/// Reads a frame header (RFC 9114 §7.1). `Truncated` means the two varints have not all arrived;
/// nothing is consumed in that case, so the caller reads more and asks again.
pub fn read_header(reader: *Reader) Error!Header {
    var cursor = reader.*;
    const frame_type = (try varint.decode(&cursor)).value;
    const length = (try varint.decode(&cursor)).value;
    reader.* = cursor;
    return .{ .frame_type = frame_type, .length = length };
}

/// Whether a frame type may appear on `kind` (RFC 9114 §7's Table 1). An unknown type is
/// permitted everywhere, because §9 requires an endpoint to ignore one it does not know; §11.2.1's
/// reserved HTTP/2 types are the exception and are permitted nowhere.
pub fn permitted(frame_type: u64, kind: StreamKind) bool {
    for (constants.frame_reserved_http2) |held| {
        if (frame_type == held) return false;
    }
    return switch (frame_type) {
        constants.frame_data, constants.frame_headers => kind != .control,
        constants.frame_cancel_push,
        constants.frame_settings,
        constants.frame_goaway,
        constants.frame_max_push_id,
        => kind == .control,
        constants.frame_push_promise => kind == .request,
        else => true,
    };
}

/// A frame whose payload colibri reads whole (RFC 9114 §7.2). DATA and HEADERS are absent: the
/// caller streams their payloads rather than holding them.
pub const Payload = union(enum) {
    cancel_push: u64,
    settings: Settings,
    goaway: u64,
    max_push_id: u64,
    push_promise: PushPromise,
    /// A type §9 requires this endpoint to ignore, carried so a caller can count or log it.
    unknown: u64,
};

/// RFC 9114 §7.2.5: a push ID followed by an encoded field section, which the caller decodes.
pub const PushPromise = struct {
    push_id: u64,
    field_section: []const u8,
};

/// Reads a whole payload of `length` octets for `frame_type` (RFC 9114 §7.2). `payload` holds
/// exactly the frame's octets: §7.1 makes anything left over, and anything missing, H3_FRAME_ERROR.
pub fn read_payload(frame_type: u64, payload: []const u8) Error!Payload {
    var reader = Reader.init(payload);
    const found = try read_payload_at(frame_type, &reader);
    switch (found) {
        // §7.2.5's field section runs to the end of the frame, and §9 has an unknown type's
        // payload ignored whole, so neither has anything left over to refuse.
        .push_promise, .unknown => {},
        // §7.1: a payload that contains additional bytes after the identified fields MUST be
        // treated as a connection error of type H3_FRAME_ERROR.
        else => if (reader.remaining_len() != 0) return Error.FrameError,
    }
    return found;
}

fn read_payload_at(frame_type: u64, reader: *Reader) Error!Payload {
    return switch (frame_type) {
        constants.frame_cancel_push => .{ .cancel_push = try read_single(reader) },
        constants.frame_goaway => .{ .goaway = try read_single(reader) },
        constants.frame_max_push_id => .{ .max_push_id = try read_single(reader) },
        constants.frame_settings => .{ .settings = try read_settings(reader) },
        constants.frame_push_promise => .{ .push_promise = try read_push_promise(reader) },
        // §7.2.1, §7.2.2: these two are streamed, so asking for their payload whole is the
        // caller's own error and not a peer's.
        constants.frame_data, constants.frame_headers => unreachable,
        else => .{ .unknown = frame_type },
    };
}

/// A payload that is one variable-length integer and nothing else (RFC 9114 §7.2.3, §7.2.6,
/// §7.2.7).
fn read_single(reader: *Reader) Error!u64 {
    // §7.1: a payload that terminates before the end of the identified fields is H3_FRAME_ERROR,
    // which is what a truncated varint is here — the caller already has the whole frame.
    const decoded = varint.decode(reader) catch return Error.FrameError;
    return decoded.value;
}

/// RFC 9114 §7.2.5: the push ID, then the field section, which runs to the end of the payload.
fn read_push_promise(reader: *Reader) Error!PushPromise {
    const push_id = try read_single(reader);
    return .{ .push_id = push_id, .field_section = reader.take_rest() };
}

/// The settings RFC 9114 §7.2.4.1 and RFC 9204 §5 define, as a peer sent them. An absent setting
/// is null and the caller applies the default, which is not the same as a peer sending the
/// default value.
pub const Settings = struct {
    /// RFC 9114 §7.2.4.1: the largest field section this endpoint's peer will accept, in the
    /// size of §4.2.2. Absent means unlimited.
    max_field_section_size: ?u64 = null,
    /// RFC 9204 §5: both default to zero, which is what makes a static-only QPACK conformant.
    qpack_max_table_capacity: ?u64 = null,
    qpack_blocked_streams: ?u64 = null,
    /// RFC 9114 §7.2.4.1: a reserved setting, `0x1f * N + 0x21`, which "Endpoints SHOULD include"
    /// and which a receiver MUST ignore. Written when set; a reader never sets it.
    reserved: ?Reserved = null,
};

/// One reserved setting: its `N` and its value, which has no meaning (RFC 9114 §7.2.4.1).
pub const Reserved = struct {
    n: u64,
    value: u64,

    pub fn identifier(reserved: Reserved) u64 {
        const found = constants.reserved_base +| (constants.reserved_step *| reserved.n);
        assert(constants.is_reserved(found));
        return found;
    }
};

/// Reads a SETTINGS payload (RFC 9114 §7.2.4).
fn read_settings(reader: *Reader) Error!Settings {
    var found: Settings = .{};
    // Bounded: every pair consumes at least two octets of a payload the caller already holds.
    while (reader.remaining_len() > 0) {
        const identifier = (varint.decode(reader) catch return Error.FrameError).value;
        const value = (varint.decode(reader) catch return Error.FrameError).value;
        try apply(&found, identifier, value);
    }
    return found;
}

/// Puts one identifier and value into `found`, or refuses it (RFC 9114 §7.2.4.1).
fn apply(found: *Settings, identifier: u64, value: u64) Error!void {
    // §7.2.4.1: the HTTP/2 setting identifiers are reserved, and receiving one MUST be treated
    // as a connection error of type H3_SETTINGS_ERROR.
    for (constants.setting_reserved_http2) |held| {
        if (identifier == held) return Error.SettingsError;
    }
    const slot = switch (identifier) {
        constants.setting_max_field_section_size => &found.max_field_section_size,
        constants.setting_qpack_max_table_capacity => &found.qpack_max_table_capacity,
        constants.setting_qpack_blocked_streams => &found.qpack_blocked_streams,
        // §7.2.4.1: an identifier this endpoint does not understand MUST be ignored. A duplicate
        // of one is ignored with it: noticing would mean remembering every identifier a peer
        // sent, which is memory a peer chooses the size of.
        else => return,
    };
    // §7.2.4.1: the same identifier MUST NOT occur more than once, and a receiver MAY treat a
    // duplicate as a connection error of H3_SETTINGS_ERROR. colibri does, for the ones it holds.
    if (slot.* != null) return Error.SettingsError;
    slot.* = value;
}

const testing = std.testing;

test "§7.1: a header is two varints, and a short one consumes nothing" {
    // Type 0x01 (HEADERS) and length 0x0a, both in one octet each.
    var reader = Reader.init(&.{ 0x01, 0x0a });
    const header = try read_header(&reader);
    try testing.expectEqual(constants.frame_headers, header.frame_type);
    try testing.expectEqual(10, header.length);
    try testing.expectEqual(0, reader.remaining_len());
    try testing.expect(header.is_streamed());
    // A two-octet varint length: 0x4100 is 0x100.
    var wide = Reader.init(&.{ 0x00, 0x41, 0x00 });
    const long = try read_header(&wide);
    try testing.expectEqual(constants.frame_data, long.frame_type);
    try testing.expectEqual(0x100, long.length);
    // §7.1: a header whose octets have not all arrived is not a protocol error. Nothing is
    // consumed, so the caller reads more and asks again.
    var short = Reader.init(&.{0x00});
    try testing.expectError(error.Truncated, read_header(&short));
    try testing.expectEqual(1, short.remaining_len());
    var half = Reader.init(&.{ 0x00, 0x41 });
    try testing.expectError(error.Truncated, read_header(&half));
    try testing.expectEqual(2, half.remaining_len());
    // Only DATA and HEADERS are streamed; every other payload is read whole.
    try testing.expect(!(Header{ .frame_type = constants.frame_settings, .length = 0 }).is_streamed());
}

test "§7: Table 1 says which frames a stream may carry" {
    // DATA and HEADERS travel on request and push streams and never on the control stream.
    try testing.expect(permitted(constants.frame_data, .request));
    try testing.expect(permitted(constants.frame_data, .push));
    try testing.expect(!permitted(constants.frame_data, .control));
    try testing.expect(permitted(constants.frame_headers, .push));
    try testing.expect(!permitted(constants.frame_headers, .control));
    // The four control frames travel only on the control stream.
    for ([_]u64{
        constants.frame_cancel_push,
        constants.frame_settings,
        constants.frame_goaway,
        constants.frame_max_push_id,
    }) |held| {
        try testing.expect(permitted(held, .control));
        try testing.expect(!permitted(held, .request));
        try testing.expect(!permitted(held, .push));
    }
    // PUSH_PROMISE is the one frame that travels on a request stream alone.
    try testing.expect(permitted(constants.frame_push_promise, .request));
    try testing.expect(!permitted(constants.frame_push_promise, .control));
    try testing.expect(!permitted(constants.frame_push_promise, .push));
}

test "§9 and §11.2.1: an unknown type is permitted everywhere and an HTTP/2 one nowhere" {
    // §9: an endpoint MUST ignore a frame type it does not know, wherever it arrives, and
    // §7.2.8's reserved types exist to exercise exactly that.
    const reserved = constants.reserved_base;
    try testing.expect(constants.is_reserved(reserved));
    for ([_]StreamKind{ .control, .request, .push }) |kind| {
        try testing.expect(permitted(reserved, kind));
        try testing.expect(permitted(0x5555, kind));
    }
    // §11.2.1: the HTTP/2 types are reserved the other way — they MUST NOT be sent and their
    // receipt is H3_FRAME_UNEXPECTED, so no stream accepts one.
    for (constants.frame_reserved_http2) |held| {
        for ([_]StreamKind{ .control, .request, .push }) |kind| {
            try testing.expect(!permitted(held, kind));
        }
    }
}

test "§7.2.3, §7.2.6, §7.2.7: a one-integer payload must be exactly that" {
    try testing.expectEqual(7, (try read_payload(constants.frame_cancel_push, &.{0x07})).cancel_push);
    try testing.expectEqual(7, (try read_payload(constants.frame_goaway, &.{0x07})).goaway);
    try testing.expectEqual(0x100, (try read_payload(constants.frame_max_push_id, &.{ 0x41, 0x00 })).max_push_id);
    // §7.1: octets after the fields the type defines are H3_FRAME_ERROR.
    try testing.expectError(Error.FrameError, read_payload(constants.frame_goaway, &.{ 0x07, 0x00 }));
    // And a payload that ends before them is the same error, not a short read: the caller
    // already holds the whole frame, so there is nothing more to wait for.
    try testing.expectError(Error.FrameError, read_payload(constants.frame_goaway, &.{0x41}));
    try testing.expectError(Error.FrameError, read_payload(constants.frame_goaway, &.{}));
}

test "§7.2.4: SETTINGS is identifier and value pairs" {
    const payload = [_]u8{
        constants.setting_max_field_section_size, 0x41, 0x00,
        constants.setting_qpack_blocked_streams,  0x10,
    };
    const found = (try read_payload(constants.frame_settings, &payload)).settings;
    try testing.expectEqual(0x100, found.max_field_section_size);
    try testing.expectEqual(0x10, found.qpack_blocked_streams);
    // §7.2.4.1: an absent setting is not the same as one a peer sent with its default value, so
    // it is null and the caller applies the default.
    try testing.expectEqual(null, found.qpack_max_table_capacity);
    // An empty payload is a SETTINGS frame with nothing in it, which §7.2.4 permits.
    const empty = (try read_payload(constants.frame_settings, &.{})).settings;
    try testing.expectEqual(null, empty.max_field_section_size);
    // §7.1: a pair cut in half is H3_FRAME_ERROR.
    try testing.expectError(Error.FrameError, read_payload(constants.frame_settings, &.{0x06}));
}

test "§7.2.4.1: a duplicate or an HTTP/2 identifier is refused, and an unknown one ignored" {
    // The same identifier twice, which §7.2.4.1 lets a receiver treat as H3_SETTINGS_ERROR.
    const twice = [_]u8{ constants.setting_max_field_section_size, 0x01, constants.setting_max_field_section_size, 0x02 };
    try testing.expectError(Error.SettingsError, read_payload(constants.frame_settings, &twice));
    // §7.2.4.1: the HTTP/2 identifiers are reserved and receiving one MUST be an error.
    for (constants.setting_reserved_http2) |held| {
        const payload = [_]u8{ @intCast(held), 0x01 };
        try testing.expectError(Error.SettingsError, read_payload(constants.frame_settings, &payload));
    }
    // An identifier this endpoint does not know is ignored, and so is a second copy of it:
    // noticing that duplicate would mean remembering every identifier a peer chose to send.
    const unknown = [_]u8{ 0x40, 0x99, 0x01, 0x40, 0x99, 0x02, constants.setting_qpack_max_table_capacity, 0x05 };
    const found = (try read_payload(constants.frame_settings, &unknown)).settings;
    try testing.expectEqual(5, found.qpack_max_table_capacity);
}

test "§7.2.5: PUSH_PROMISE splits into a push ID and the field section after it" {
    const payload = [_]u8{ 0x04, 0x00, 0x00, 0xd1 };
    const found = (try read_payload(constants.frame_push_promise, &payload)).push_promise;
    try testing.expectEqual(4, found.push_id);
    // Everything after the push ID is the encoded field section, which QPACK decodes: here the
    // zero-zero prefix and one indexed line.
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0xd1 }, found.field_section);
    // A promise with no field section at all leaves an empty one rather than failing here; what
    // an empty field section means is QPACK's answer and not the framing layer's.
    const bare = (try read_payload(constants.frame_push_promise, &.{0x04})).push_promise;
    try testing.expectEqual(0, bare.field_section.len);
}

test "§9: an unknown frame type's payload is skipped whole" {
    const found = try read_payload(constants.reserved_base, &.{ 0xde, 0xad, 0xbe, 0xef });
    try testing.expectEqual(constants.reserved_base, found.unknown);
    // Whatever the payload holds, and however long it is, nothing in it is read.
    try testing.expectEqual(0x5555, (try read_payload(0x5555, &.{})).unknown);
}

test "§8.1: every error names the code the connection closes with" {
    try testing.expectEqual(constants.error_frame_unexpected, error_code(Error.FrameUnexpected));
    try testing.expectEqual(constants.error_settings_error, error_code(Error.SettingsError));
    try testing.expectEqual(constants.error_frame_error, error_code(Error.FrameError));
    // §7.1: a frame left truncated by a stream that ended cleanly is H3_FRAME_ERROR too.
    try testing.expectEqual(constants.error_frame_error, error_code(Error.Truncated));
}
