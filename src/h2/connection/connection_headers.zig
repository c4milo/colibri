//! The frames that carry a field block: HEADERS (RFC 9113 §6.2), CONTINUATION (§6.10) and
//! PUSH_PROMISE (§6.6). Split off `connection_stream.zig` for the work of reassembling a field
//! block.
//!
//! Every fragment is fed to the HPACK decoder, whatever state colibri holds for the stream it
//! arrived on.
//! §4.3 makes a field block the connection's state and not the stream's: a block colibri skipped
//! would leave its dynamic table one insert behind the peer's and every later block would decode
//! to the wrong field lines (invariant 10). So a block on a stream colibri has refused, reset or
//! never opened is decoded like any other, and only the section it produces is
//! dropped, which `block_discarded` marks.
//!
//! The stream moves when the HEADERS frame arrives, not when the block ends: §6.2 makes the
//! CONTINUATION frames that follow logically part of that frame, and §4.3 lets nothing come
//! between them.
//!
//! A section that arrives whole is validated where it is read (decision 15): a request at a
//! server or a response at a client (§8.3), and the section after the final one is a trailer
//! section, which §8.1 requires to end the stream. A client reads every section before the final
//! response as an interim response, because §8.1 admits any number of them. A message §8 refuses
//! is malformed, which §8.1.1 makes a stream error of PROTOCOL_ERROR, never a connection error.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const message = @import("../message/message.zig");
const stream = @import("../stream/stream.zig");
const streams_table = @import("../stream/streams.zig");
const field_block = @import("../field_block.zig");
const connection = @import("connection.zig");
const stream_frames = @import("connection_stream.zig");

const Connection = connection.Connection;
const Event = connection.Event;
const Error = connection.Error;
const Stream = streams_table.Stream;

/// What the stream of a HEADERS frame is, once the table has been asked to open it.
const Opened = union(enum) {
    /// The table holds the stream, and the section the block decodes to is the caller's.
    held,
    /// The stream was refused or ignored: the block is decoded and its section dropped, with this
    /// event for the caller.
    dropped: ?Event,
};

/// Reads one HEADERS frame: it opens a stream or continues one, and starts a field block.
pub fn on_headers(target: *Connection, header: frame.Header, payload: frame.Headers, now_ns: u64) Error!?Event {
    const id = header.stream_id;
    const found = try stream_frames.find(target, id, .headers, payload.end_stream, now_ns);
    var refusal: ?Event = null;
    var dropped = true;
    switch (found) {
        .refused => |event| refusal = event,
        .discard => {},
        .open => |verdict| switch (try open_stream(target, id, verdict, payload.end_stream, now_ns)) {
            .held => dropped = false,
            .dropped => |event| refusal = event,
        },
        .act => |acting| {
            target.streams.transition(acting.record, acting.verdict, .receive, .headers, payload.end_stream);
            dropped = false;
        },
    }
    target.block.begin(id, .headers, payload.end_stream);
    target.block_discarded = dropped;
    const done = try feed_fragment(target, payload.fragment, payload.end_headers);
    const event = try finish(target, done, now_ns);
    // The stream's refusal is the event the caller gets; the block was read for the decoder.
    return refusal orelse event;
}

/// Reads one CONTINUATION frame, which carries the rest of a block another frame began (§6.10).
pub fn on_continuation(target: *Connection, header: frame.Header, payload: frame.Continuation, now_ns: u64) Error!?Event {
    // `connection_receive.zig` checked that this CONTINUATION belongs to the block in progress.
    assert(target.block.stream_id() == header.stream_id);
    const done = try feed_fragment(target, payload.fragment, payload.end_headers);
    return finish(target, done, now_ns);
}

/// Reads one PUSH_PROMISE frame. colibri never accepts a push (decision 17): a server refuses the
/// frame outright, and a client reserves the promised stream and resets it.
pub fn on_push_promise(target: *Connection, header: frame.Header, payload: frame.PushPromise, now_ns: u64) Error!?Event {
    // RFC 9113 §8.4: a client cannot push, so a server treats a PUSH_PROMISE as a connection error
    // of PROTOCOL_ERROR. §6.5.2: so does an endpoint whose ENABLE_PUSH of 0 has been acknowledged.
    if (target.role == .server or target.push_refused()) return target.fail(constants.error_protocol_error);
    const refusal = try reserve_promised(target, payload.promised_stream_id, now_ns);
    target.block.begin(header.stream_id, .push_promise, false);
    target.block_discarded = true;
    const done = try feed_fragment(target, payload.fragment, payload.end_headers);
    _ = try finish(target, done, now_ns);
    return refusal;
}

/// Opens the stream a HEADERS frame names at a server. A table that cannot hold the stream leaves
/// the block to be decoded and its section dropped.
fn open_stream(target: *Connection, id: u32, verdict: stream.Verdict, end_stream: bool, now_ns: u64) Error!Opened {
    const record = target.streams.open_peer(id, target.peer.initial_window_size) catch |failure| {
        return switch (failure) {
            // RFC 9113 §5.1.1: a stream identifier of the wrong parity, or one not above every
            // identifier the peer has used, is a connection error of PROTOCOL_ERROR.
            error.WrongParity, error.IdentifierNotIncreasing => target.fail(constants.error_protocol_error),
            // RFC 9113 §6.8: a stream above the last identifier of a GOAWAY colibri sent is one the
            // peer must retry on another connection, and this one ignores it.
            error.AfterGoaway => .{ .dropped = null },
            // RFC 9113 §5.1.2: a stream past SETTINGS_MAX_CONCURRENT_STREAMS is a stream error of
            // REFUSED_STREAM, which §8.7 says the peer may retry.
            error.Refused => .{ .dropped = try stream_frames.reset_stream(target, id, constants.error_refused_stream, now_ns) },
        };
    };
    target.streams.transition(record, verdict, .receive, .headers, end_stream);
    return .held;
}

/// Records the stream a PUSH_PROMISE promises and resets it, at a client (RFC 9113 §6.6).
fn reserve_promised(target: *Connection, promised_id: u32, now_ns: u64) Error!?Event {
    target.streams.reserve_peer(promised_id) catch {
        // RFC 9113 §6.6: a promised identifier that is not one the server may open next is a
        // connection error of PROTOCOL_ERROR (§5.1.1).
        return target.fail(constants.error_protocol_error);
    };
    // Decision 17: colibri implements no push, so every promised stream is refused at once, which
    // §8.4 allows with RST_STREAM.
    return try stream_frames.reset_stream(target, promised_id, constants.error_refused_stream, now_ns);
}

/// Feeds one fragment to the field-block slot, and turns its refusals into connection errors.
fn feed_fragment(target: *Connection, fragment: []const u8, end_headers: bool) Error!?field_block.Done {
    return target.block.feed(&target.decoder, fragment, end_headers) catch |failure| {
        return target.fail(switch (failure) {
            // RFC 9113 §10.5: the CONTINUATION frames of one block are bounded, and §6.10's excess
            // is ENHANCE_YOUR_CALM.
            error.TooManyContinuations => constants.error_enhance_your_calm,
            // RFC 9113 §4.3: a field block that does not decompress is a connection error of
            // COMPRESSION_ERROR.
            error.DecodeFailed, error.RepresentationTooLong, error.BlockCutInsideRepresentation => constants.error_compression_error,
        });
    };
}

/// Turns a finished block into the event its section means, or nothing while the block goes on.
fn finish(target: *Connection, done: ?field_block.Done, now_ns: u64) Error!?Event {
    const block = done orelse return null;
    if (target.block_discarded) return null;
    if (block.too_large) {
        // RFC 9113 §10.5.1: a field section larger than the endpoint is willing to handle may be
        // refused with a stream error, and §10.5 names ENHANCE_YOUR_CALM for a peer that costs
        // more work than it should.
        return try stream_frames.reset_stream(target, block.stream_id, constants.error_enhance_your_calm, now_ns);
    }
    // The block was not dropped, so the table held its stream when the block opened, and nothing
    // between then and now removes a record: only an open drops one, and §4.3 admits no frame in
    // the middle of a field block.
    const record = target.streams.lookup(block.stream_id).live;
    // RFC 9113 §8.1: a trailer section is the one that follows the final field section. An interim
    // response is not the final one, so the section after it is still the response.
    if (record.sections_received == .final) return validate_trailers(target, block, record, now_ns);
    return switch (target.role) {
        .server => validate_request(target, block, record, now_ns),
        .client => validate_response(target, block, record, now_ns),
    };
}

/// Validates the request section at a server, which is the only one §8.3.1 defines (RFC 9113 §8.3.1).
fn validate_request(target: *Connection, block: field_block.Done, record: *Stream, now_ns: u64) Error!?Event {
    const request = message.validate_request(target.field_section()) catch {
        return try refuse_message(target, block.stream_id, now_ns);
    };
    record.content_length = request.content_length;
    // RFC 9113 §8.3.1: a request has no interim form, so its section is the final one.
    record.sections_received = .final;
    return .{ .request = .{
        .stream_id = block.stream_id,
        .request = request,
        .end_stream = block.end_stream,
    } };
}

/// Validates a section at a client, which is an interim response or the final one until the final
/// one has arrived (RFC 9113 §8.1, §8.3.2).
fn validate_response(target: *Connection, block: field_block.Done, record: *Stream, now_ns: u64) Error!?Event {
    const response = message.validate_response(target.field_section(), block.end_stream) catch {
        return try refuse_message(target, block.stream_id, now_ns);
    };
    // RFC 9113 §8.1: zero or more interim responses may precede the final one, and only the final
    // one makes the next section a trailer section.
    const interim = response.status.is_interim();
    record.sections_received = if (interim) .interim else .final;
    // RFC 9113 §8.1.1: the content-length belongs to the message the final response begins, so an
    // interim response never sets the count the DATA octets are compared with.
    if (!interim) record.content_length = response.content_length;
    return .{ .response = .{
        .stream_id = block.stream_id,
        .response = response,
        .end_stream = block.end_stream,
    } };
}

/// Validates a second section on a stream, which RFC 9113 §8.1 makes a trailer section.
fn validate_trailers(target: *Connection, block: field_block.Done, record: *Stream, now_ns: u64) Error!?Event {
    _ = record;
    // RFC 9113 §8.1: a trailer section carries the END_STREAM flag, because nothing follows it.
    if (!block.end_stream) return try refuse_message(target, block.stream_id, now_ns);
    message.validate_trailers(target.field_section()) catch {
        return try refuse_message(target, block.stream_id, now_ns);
    };
    return .{ .trailers = .{ .stream_id = block.stream_id } };
}

/// Ends the stream of a message RFC 9113 §8 refuses: §8.1.1 makes a malformed message a stream
/// error of PROTOCOL_ERROR, which `message.verdict` names.
fn refuse_message(target: *Connection, id: u32, now_ns: u64) Error!?Event {
    return try stream_frames.reset_stream(target, id, message.verdict.stream_error, now_ns);
}

const testing = std.testing;
const core = @import("core");
const Writer = core.Writer;
const test_connection = &connection.test_connection;
const feed = connection.feed;
const feed_request = connection.feed_request;
const frame_bytes = connection.frame_bytes;
const start_server = connection.start_server;
const write_queued = connection.write_queued;
const test_input = &connection.test_input;

/// Where a test builds a field block before it is cut into frames. Test-only.
var test_block: [constants.frame_size_max]u8 = undefined;

test "a GET request is reported with its pseudo-header fields and the section it came from" {
    try start_server();
    const event = (try feed_request(1, "/index.html", true)).?;
    try testing.expectEqual(1, event.request.stream_id);
    try testing.expect(event.request.end_stream);
    try testing.expectEqualStrings("GET", event.request.request.method);
    try testing.expectEqualStrings("/index.html", event.request.request.path.?);
    try testing.expectEqualStrings("http", event.request.request.scheme.?);
    try testing.expectEqualStrings("example.com", event.request.request.authority.?);
    try testing.expectEqual(4, test_connection.field_section().len());
    // The stream is the peer's, open in one direction only, and counted.
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual(stream.State.half_closed_remote, record.state);
    try testing.expectEqual(1, test_connection.streams.peer_active);
}

test "http2/6.10: a field block cut into CONTINUATION frames is one request" {
    try start_server();
    const fragment = try connection.request_block(&test_block, "/");
    const cut = fragment.len / 2;
    const opening = try frame_bytes(test_input, constants.frame_type_headers, constants.flag_end_stream, 1, fragment[0..cut]);
    try testing.expectEqual(null, try feed(opening));
    try testing.expect(test_connection.block.is_in_progress());
    var rest: [constants.frame_header_len + constants.frame_size_max]u8 = undefined;
    const closing = try frame_bytes(&rest, constants.frame_type_continuation, constants.flag_end_headers, 1, fragment[cut..]);
    const event = (try feed(closing)).?;
    try testing.expectEqualStrings("/", event.request.request.path.?);
    try testing.expect(event.request.end_stream);
}

test "§8.1: a second field section is a trailer section, and one without END_STREAM is refused" {
    try start_server();
    _ = try feed_request(1, "/", false);
    var writer = Writer.init(&test_block);
    connection.test_encoder.init(constants.header_table_size_initial, .never);
    try connection.test_encoder.begin_block(&writer);
    try connection.test_encoder.write_field(&writer, "x-checksum", "abc", .without_indexing);
    connection.test_encoder.commit_block();
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    const trailers = try frame_bytes(test_input, constants.frame_type_headers, flags, 1, writer.written());
    const event = (try feed(trailers)).?;
    try testing.expectEqual(1, event.trailers.stream_id);
    // RFC 9113 §8.1: a trailer section that does not end the stream is malformed.
    try start_server();
    _ = try feed_request(1, "/", false);
    const open_trailers = try frame_bytes(test_input, constants.frame_type_headers, constants.flag_end_headers, 1, writer.written());
    const refused = (try feed(open_trailers)).?;
    try testing.expectEqual(constants.error_protocol_error, refused.stream_refused.error_code);
}

test "§8.3.1: a request §8 refuses is a stream error, and the decoder stays in step with the peer" {
    try start_server();
    var writer = Writer.init(&test_block);
    connection.test_encoder.init(constants.header_table_size_initial, .always);
    try connection.test_encoder.begin_block(&writer);
    // No :path, which §8.3.1 requires, and an insert the next block will index.
    try connection.test_encoder.write_field(&writer, ":method", "GET", .without_indexing);
    try connection.test_encoder.write_field(&writer, ":scheme", "http", .without_indexing);
    try connection.test_encoder.write_field(&writer, "x-trace", "abc", .incremental);
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    const malformed = try frame_bytes(test_input, constants.frame_type_headers, flags, 1, writer.written());
    const refused = (try feed(malformed)).?;
    try testing.expectEqual(1, refused.stream_refused.stream_id);
    try testing.expectEqual(constants.error_protocol_error, refused.stream_refused.error_code);
    try testing.expectEqual(1, test_connection.decoder.table.len());
    // The next request indexes what that block inserted, which only a decoder synchronized with
    // the peer's encoder can read.
    var second = Writer.init(&test_block);
    try connection.test_encoder.begin_block(&second);
    try connection.test_encoder.write_field(&second, ":method", "GET", .without_indexing);
    try connection.test_encoder.write_field(&second, ":scheme", "http", .without_indexing);
    try connection.test_encoder.write_field(&second, ":path", "/", .without_indexing);
    try connection.test_encoder.write_field(&second, "x-trace", "abc", .without_indexing);
    connection.test_encoder.commit_block();
    var buffer: [constants.frame_header_len + constants.frame_size_max]u8 = undefined;
    const bytes = try frame_bytes(&buffer, constants.frame_type_headers, flags, 3, second.written());
    const event = (try feed(bytes)).?;
    try testing.expectEqualStrings("/", event.request.request.path.?);
    const line = test_connection.field_section().get(3);
    try testing.expectEqualStrings("x-trace", line.name);
    try testing.expectEqualStrings("abc", line.value);
}

test "http2/5.1.2/1: the stream past concurrent_streams_max is refused, and its block is still decoded" {
    try start_server();
    var id: u32 = 1;
    for (0..constants.concurrent_streams_max) |_| {
        _ = try feed_request(id, "/", false);
        id += constants.stream_id_step;
    }
    try testing.expectEqual(constants.concurrent_streams_max, test_connection.streams.peer_active);
    // The refused stream's field block carries an insert, which the decoder must still read:
    // §4.3 makes the dynamic table the connection's state, not the stream's (invariant 10).
    var writer = Writer.init(&test_block);
    connection.test_encoder.init(constants.header_table_size_initial, .never);
    try connection.test_encoder.begin_block(&writer);
    try connection.test_encoder.write_field(&writer, ":method", "GET", .without_indexing);
    try connection.test_encoder.write_field(&writer, ":scheme", "http", .without_indexing);
    try connection.test_encoder.write_field(&writer, ":path", "/", .without_indexing);
    try connection.test_encoder.write_field(&writer, "x-trace", "abc", .incremental);
    connection.test_encoder.commit_block();
    const inserts_before = test_connection.decoder.table.len();
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    const bytes = try frame_bytes(test_input, constants.frame_type_headers, flags, id, writer.written());
    const refused = (try feed(bytes)).?;
    try testing.expectEqual(id, refused.stream_refused.stream_id);
    try testing.expectEqual(constants.error_refused_stream, refused.stream_refused.error_code);
    try testing.expectEqual(constants.concurrent_streams_max, test_connection.streams.peer_active);
    try testing.expectEqual(inserts_before + 1, test_connection.decoder.table.len());
}

test "http2/5.1.1/1: a HEADERS frame on the server's own parity ends the connection" {
    try start_server();
    const fragment = try connection.request_block(&test_block, "/");
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    const bytes = try frame_bytes(test_input, constants.frame_type_headers, flags, 2, fragment);
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(bytes, 0));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
}

test "§8.4: a PUSH_PROMISE at a server ends the connection (decision 17)" {
    try start_server();
    _ = try feed_request(1, "/", false);
    const fragment = try connection.request_block(&test_block, "/");
    var payload: [constants.frame_header_len + constants.frame_size_max]u8 = undefined;
    var writer = Writer.init(&payload);
    try writer.write_int(u32, 2);
    try writer.write_bytes(fragment);
    const bytes = try frame_bytes(test_input, constants.frame_type_push_promise, constants.flag_end_headers, 1, writer.written());
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(bytes, 0));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
}

test "§10.5.1: a field section past what colibri accepts is a stream error and the block is read whole" {
    try start_server();
    var writer = Writer.init(&test_block);
    connection.test_encoder.init(constants.header_table_size_initial, .never);
    try connection.test_encoder.begin_block(&writer);
    try connection.test_encoder.write_field(&writer, ":method", "GET", .without_indexing);
    try connection.test_encoder.write_field(&writer, ":scheme", "http", .without_indexing);
    try connection.test_encoder.write_field(&writer, ":path", "/", .without_indexing);
    connection.test_encoder.commit_block();
    // One line more than `field_count_max`, which is the section the caller's storage holds.
    var name: [16]u8 = undefined;
    for (0..core.constants.field_count_max) |index| {
        const written_name = try std.fmt.bufPrint(&name, "x-{d}", .{index});
        try connection.test_encoder.write_field(&writer, written_name, "v", .without_indexing);
    }
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    const bytes = try frame_bytes(test_input, constants.frame_type_headers, flags, 1, writer.written());
    const refused = (try feed(bytes)).?;
    try testing.expectEqual(constants.error_enhance_your_calm, refused.stream_refused.error_code);
    try expect_queued_reset(1, constants.error_enhance_your_calm);
}

/// Requires the connection to have queued exactly one RST_STREAM for `stream_id`. Test-only.
fn expect_queued_reset(stream_id: u32, code: u32) !void {
    var expected: [constants.frame_header_len + constants.rst_stream_len]u8 = undefined;
    var writer = Writer.init(&expected);
    try frame.write_rst_stream(&writer, stream_id, code);
    try testing.expectEqualSlices(u8, writer.written(), write_queued());
}
