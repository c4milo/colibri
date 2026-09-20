//! The unidirectional streams of RFC 9114 §6.2, and the rules about which of them may exist.
//! Part of design §8 step 12.
//!
//! A unidirectional stream begins with one variable-length integer saying what it is (§6.2), and
//! everything after that depends on the answer. Four types are defined for HTTP/3: the control
//! stream and the push stream here, and QPACK's encoder and decoder streams in RFC 9204 §4.2.
//! Anything else is an extension's, and §9 requires this endpoint to discard the data or abort
//! reading rather than guess.
//!
//! **Three of the four are critical**, which is the rule worth stating plainly: §6.2.1 makes
//! closing a control stream a connection error of H3_CLOSED_CRITICAL_STREAM, and RFC 9204 §4.2
//! says the same of both QPACK streams. A push stream is not critical; it carries one response.
//!
//! What this file holds is the bookkeeping: which types have been seen, which a role may send,
//! and what a second one of a kind means. What it does not do is read frames — that is
//! `frame.zig` — or open streams, which is QUIC's.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const varint = wire.varint;

pub const Error = core.reader.Error || error{
    /// RFC 9114 §8.1's H3_STREAM_CREATION_ERROR: a second stream of a kind only one of which
    /// may exist, or a push stream from a peer that may not push.
    StreamCreationError,
};

/// Which side of the connection this endpoint is. A push stream may only travel one way
/// (RFC 9114 §6.2.2), so the rules below need to know.
pub const Role = enum { client, server };

/// What a unidirectional stream turned out to be (RFC 9114 §6.2, RFC 9204 §4.2).
pub const Kind = union(enum) {
    /// §6.2.1: HTTP/3 frames, SETTINGS first.
    control,
    /// §6.2.2: one pushed response, identified by its push ID.
    push: u64,
    /// RFC 9204 §4.2: the encoder's and decoder's instruction streams.
    qpack_encoder,
    qpack_decoder,
    /// §6.2.3's reserved types and anything an extension defined. §9: this endpoint discards the
    /// data or aborts reading, and considers the stream to mean nothing.
    unknown: u64,

    /// Whether closing this stream is a connection error (RFC 9114 §6.2.1, RFC 9204 §4.2). A
    /// push stream carries one response and ends; the other three run for the connection.
    pub fn is_critical(kind: Kind) bool {
        return switch (kind) {
            .control, .qpack_encoder, .qpack_decoder => true,
            .push, .unknown => false,
        };
    }
};

/// Reads a unidirectional stream header (RFC 9114 §6.2). A push stream's header carries its push
/// ID too (§6.2.2), so a stream type alone is not always enough and `Truncated` may mean the ID
/// has not arrived yet. Nothing is consumed in that case.
pub fn read_header(reader: *Reader) Error!Kind {
    var cursor = reader.*;
    const stream_type = (try varint.decode(&cursor)).value;
    const kind: Kind = switch (stream_type) {
        constants.stream_control => .control,
        constants.stream_qpack_encoder => .qpack_encoder,
        constants.stream_qpack_decoder => .qpack_decoder,
        constants.stream_push => .{ .push = (try varint.decode(&cursor)).value },
        else => .{ .unknown = stream_type },
    };
    reader.* = cursor;
    return kind;
}

/// Writes a unidirectional stream header (RFC 9114 §6.2). All of the octets are written, or none.
pub fn write_header(writer: *Writer, kind: Kind) core.writer.Error!void {
    var cursor = writer.*;
    switch (kind) {
        .control => try varint.encode(&cursor, constants.stream_control),
        .qpack_encoder => try varint.encode(&cursor, constants.stream_qpack_encoder),
        .qpack_decoder => try varint.encode(&cursor, constants.stream_qpack_decoder),
        .push => |push_id| {
            try varint.encode(&cursor, constants.stream_push);
            try varint.encode(&cursor, push_id);
        },
        .unknown => |stream_type| try varint.encode(&cursor, stream_type),
    }
    writer.* = cursor;
}

/// Which unidirectional streams a peer has opened, and what a new one means (RFC 9114 §6.2.1,
/// RFC 9204 §4.2). One of these per connection, for the streams the peer opens.
pub const Opened = struct {
    control: bool,
    qpack_encoder: bool,
    qpack_decoder: bool,

    pub fn init(opened: *Opened) void {
        opened.* = .{ .control = false, .qpack_encoder = false, .qpack_decoder = false };
    }

    /// Records a stream the peer opened, or says why it may not. `peer` is the role that opened
    /// it, which is this endpoint's peer.
    pub fn accept(opened: *Opened, kind: Kind, peer: Role) Error!void {
        // RFC 9114 §6.2.2: only servers can push, so a client-initiated push stream is a
        // connection error of H3_STREAM_CREATION_ERROR.
        if (kind == .push and peer != .server) return Error.StreamCreationError;
        const slot = opened.slot_of(kind) orelse return;
        // §6.2.1: only one control stream per peer is permitted, and receipt of a second
        // claiming to be one MUST be a connection error of H3_STREAM_CREATION_ERROR. RFC 9204
        // §4.2 says the same of each QPACK stream.
        if (slot.*) return Error.StreamCreationError;
        slot.* = true;
    }

    /// Whether the peer has opened every stream the connection needs from it.
    pub fn complete(opened: *const Opened) bool {
        return opened.control and opened.qpack_encoder and opened.qpack_decoder;
    }

    fn slot_of(opened: *Opened, kind: Kind) ?*bool {
        return switch (kind) {
            .control => &opened.control,
            .qpack_encoder => &opened.qpack_encoder,
            .qpack_decoder => &opened.qpack_decoder,
            // §6.2.2: a peer may open as many push streams as its push IDs allow, and §9 puts no
            // bound on how many streams of an unknown type it opens.
            .push, .unknown => null,
        };
    }
};

/// The error code RFC 9114 §8.1 gives each of those.
pub fn error_code(failure: Error) u64 {
    return switch (failure) {
        error.StreamCreationError => constants.error_stream_creation,
        // §6.2: a stream header that never arrives leaves the stream unusable. §6.2.1 makes a
        // closed control stream H3_CLOSED_CRITICAL_STREAM, which is what a truncated header on
        // a stream that ended amounts to.
        error.Truncated => constants.error_closed_critical_stream,
    };
}

const testing = std.testing;

/// Room for what a test writes, and the record it drives. Test-only.
const test_room: usize = 64;
var test_octets: [test_room]u8 = undefined;
var test_opened: Opened = undefined;

/// Writes a header and reads it back. Test-only.
fn round_trip(kind: Kind) !Kind {
    var writer = Writer.init(&test_octets);
    try write_header(&writer, kind);
    var reader = Reader.init(writer.written());
    const back = try read_header(&reader);
    try testing.expectEqual(0, reader.remaining_len());
    return back;
}

test "§6.2: a unidirectional stream begins with its type" {
    // §6.2.1 and RFC 9204 §4.2: 0x00, 0x02 and 0x03 are the three streams that run for the
    // whole connection.
    try testing.expectEqual(Kind.control, try round_trip(.control));
    try testing.expectEqual(Kind.qpack_encoder, try round_trip(.qpack_encoder));
    try testing.expectEqual(Kind.qpack_decoder, try round_trip(.qpack_decoder));
    var reader = Reader.init(&.{0x00});
    try testing.expectEqual(Kind.control, try read_header(&reader));
    // §6.2.2: a push stream's header carries its push ID after the type.
    const pushed = try round_trip(.{ .push = 0x100 });
    try testing.expectEqual(0x100, pushed.push);
    var wire_octets = Reader.init(&.{ 0x01, 0x41, 0x00 });
    try testing.expectEqual(0x100, (try read_header(&wire_octets)).push);
}

test "§9: a type this endpoint does not know is carried, not refused" {
    // §6.2.3's reserved types exist to exercise exactly this, and §9 requires an endpoint to
    // discard the data or abort reading rather than treat the stream as meaning anything.
    const reserved = try round_trip(.{ .unknown = constants.reserved_base });
    try testing.expectEqual(constants.reserved_base, reserved.unknown);
    try testing.expect(constants.is_reserved(reserved.unknown));
    const extension = try round_trip(.{ .unknown = 0x5555 });
    try testing.expectEqual(0x5555, extension.unknown);
    // Nothing unknown is critical: §6.2.1's rule is about the streams HTTP/3 defines.
    try testing.expect(!extension.is_critical());
}

test "§6.2.1: the three streams that run for the connection are critical" {
    // §6.2.1 makes a closed control stream H3_CLOSED_CRITICAL_STREAM, and RFC 9204 §4.2 says
    // the same of both QPACK streams.
    try testing.expect((Kind{ .control = {} }).is_critical());
    try testing.expect((Kind{ .qpack_encoder = {} }).is_critical());
    try testing.expect((Kind{ .qpack_decoder = {} }).is_critical());
    // A push stream carries one response and ends, so closing it is ordinary.
    try testing.expect(!(Kind{ .push = 0 }).is_critical());
}

test "§6.2.1: a second control or QPACK stream is a connection error" {
    test_opened.init();
    try testing.expect(!test_opened.complete());
    try test_opened.accept(.control, .server);
    try test_opened.accept(.qpack_encoder, .server);
    try test_opened.accept(.qpack_decoder, .server);
    try testing.expect(test_opened.complete());
    // §6.2.1: receipt of a second stream claiming to be a control stream MUST be a connection
    // error of H3_STREAM_CREATION_ERROR, and RFC 9204 §4.2 says the same of each QPACK stream.
    try testing.expectError(Error.StreamCreationError, test_opened.accept(.control, .server));
    try testing.expectError(Error.StreamCreationError, test_opened.accept(.qpack_encoder, .server));
    try testing.expectError(Error.StreamCreationError, test_opened.accept(.qpack_decoder, .server));
    // The three are counted apart, so one arriving does not stand in for another.
    test_opened.init();
    try test_opened.accept(.qpack_encoder, .server);
    try testing.expect(!test_opened.complete());
    try test_opened.accept(.control, .server);
    try test_opened.accept(.qpack_decoder, .server);
    try testing.expect(test_opened.complete());
}

test "§6.2.2: only a server may open a push stream, and it may open many" {
    test_opened.init();
    // §6.2.2: only servers can push; a client-initiated push stream MUST be treated as a
    // connection error of H3_STREAM_CREATION_ERROR.
    try testing.expectError(Error.StreamCreationError, test_opened.accept(.{ .push = 0 }, .client));
    try test_opened.accept(.{ .push = 0 }, .server);
    // A second push stream is ordinary: how many a server may open is what its push IDs bound,
    // and that is §4.6's rule rather than this one.
    try test_opened.accept(.{ .push = 1 }, .server);
    try test_opened.accept(.{ .push = 2 }, .server);
    // §9 puts no bound on streams of an unknown type either, from either side.
    try test_opened.accept(.{ .unknown = 0x5555 }, .client);
    try test_opened.accept(.{ .unknown = 0x5555 }, .server);
}

test "§6.2: a header whose octets have not all arrived consumes nothing" {
    // A type that is a multi-octet varint, cut short.
    var short = Reader.init(&.{0x41});
    try testing.expectError(error.Truncated, read_header(&short));
    try testing.expectEqual(1, short.remaining_len());
    // §6.2.2: a push stream's type has arrived but its push ID has not, so the header is not
    // complete and the stream type alone must not be accepted.
    var half = Reader.init(&.{0x01});
    try testing.expectError(error.Truncated, read_header(&half));
    try testing.expectEqual(1, half.remaining_len());
    var partial = Reader.init(&.{ 0x01, 0x41 });
    try testing.expectError(error.Truncated, read_header(&partial));
    try testing.expectEqual(2, partial.remaining_len());
}

test "§8.1: every error names the code the connection closes with" {
    try testing.expectEqual(constants.error_stream_creation, error_code(Error.StreamCreationError));
    try testing.expectEqual(constants.error_closed_critical_stream, error_code(Error.Truncated));
}

test "a header that does not fit writes nothing" {
    // A push stream header of type and a two-octet push ID takes three octets.
    var room: [3]u8 = undefined;
    var tight = Writer.init(room[0..2]);
    try testing.expectError(error.NoSpaceLeft, write_header(&tight, .{ .push = 0x100 }));
    try testing.expectEqual(0, tight.written().len);
    var exact = Writer.init(&room);
    try write_header(&exact, .{ .push = 0x100 });
    try testing.expectEqual(3, exact.written().len);
}
