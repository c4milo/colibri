//! One connection of the test-only h2 server, with no socket in it: octets in, octets out, and
//! a 200 response to every request that ends (design §9). `h2_server.zig` is the socket around it,
//! and these tests drive the same code the socket does.
//!
//! `step` does three things in order, each bounded by the caller's buffers:
//!   1. writes what the connection owes: its preface, the acknowledgments, the window updates and
//!      the GOAWAY (RFC 9113 §3.4, §6.5.3, §6.7, §6.9, §6.8);
//!   2. reads frames until the input runs out, the connection owes as many responses as the queue
//!      holds, or the connection fails;
//!   3. writes as much of the owed responses as the windows and the caller's room allow, oldest
//!      first, and leaves the rest owed.
//! A connection that fails in step 2 writes its GOAWAY before the step returns. A step that writes
//! nothing and consumes nothing means the caller must read more octets, or the connection is
//! finished, which `done` says.
//!
//! The server answers every request the same way, whatever its method or path: design §9 asks for
//! 200 and a non-empty body, which is what h2spec's DATA cases and h2load both need. A request the
//! connection refuses is never passed to the session, because the refusal is the connection's
//! (§5.4.2).
//!
//! Time is a value, never a clock: each step reports an instant `tick_ns` after the last, so the
//! rate limits of §10.5 move and two runs of the same octets stay identical (invariant 6).
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const constants = @import("constants.zig");

const Connection = h2.Connection;
const Event = h2.Event;

/// What one step did.
pub const Step = struct {
    /// Octets of the caller's input the connection consumed.
    consumed: usize,
    /// Octets written into the caller's output, to be sent in order.
    written: usize,
    /// Whether the connection is finished: it failed and its GOAWAY has been written.
    done: bool,
};

/// One connection's server state, in storage the caller places.
pub const Session = struct {
    connection: Connection,
    /// The instant the next step reports (design §4.2).
    now_ns: u64,
    /// The streams owing a response, oldest first: one per request that ended (RFC 9113 §8.1).
    owed: [constants.responses_owed_max]u32,
    owed_count: u32,
    /// Whether the oldest owed response has had its field section written.
    head_written: bool,
    /// Octets of `response_body` the oldest owed response has sent.
    body_sent: usize,
    /// Whether the connection failed and its GOAWAY has been written.
    finished: bool,

    /// Makes a server connection that has read nothing and written nothing.
    pub fn init(session: *Session) void {
        session.connection.init(.server);
        session.now_ns = 0;
        session.owed = @splat(0);
        session.owed_count = 0;
        session.head_written = false;
        session.body_sent = 0;
        session.finished = false;
    }

    /// Consumes what it can of `input` and writes what it can into `output`. See the header.
    pub fn step(session: *Session, input: []const u8, output: []u8) Step {
        session.now_ns += constants.tick_ns;
        var written = session.connection.write_pending(output, session.now_ns);
        if (session.finished) return .{ .consumed = 0, .written = written, .done = true };
        const consumed = session.read_frames(input);
        written += session.write_responses(output[written..]);
        // RFC 9113 §5.4.1: a connection that failed in this step says so in this step, so the
        // socket around the session sends the GOAWAY before it closes.
        if (session.finished) written += session.connection.write_pending(output[written..], session.now_ns);
        return .{ .consumed = consumed, .written = written, .done = session.finished };
    }

    /// Reads frames until the input runs out, the queue of owed responses is full, or the
    /// connection ends. Reading never stops for a response colibri has not finished writing: the
    /// WINDOW_UPDATE that lets it finish is a frame the peer sends (RFC 9113 §6.9.1).
    fn read_frames(session: *Session, input: []const u8) usize {
        var consumed: usize = 0;
        for (0..input.len + 1) |_| {
            if (session.owed_count == constants.responses_owed_max) return consumed;
            const received = session.connection.receive(input[consumed..], session.now_ns) catch {
                // RFC 9113 §5.4.1: the connection is over; its GOAWAY goes out in this step.
                session.finished = true;
                return consumed;
            };
            if (received.consumed == 0) return consumed;
            consumed += received.consumed;
            const event = received.event orelse continue;
            const stream_id = ends_request(event) orelse continue;
            session.owed[session.owed_count] = stream_id;
            session.owed_count += 1;
        } else unreachable; // Each frame takes at least one octet, so the input ends first.
    }

    /// Writes as much of the owed responses as the windows and the room allow, oldest first.
    fn write_responses(session: *Session, output: []u8) usize {
        var written: usize = 0;
        for (0..constants.responses_owed_max) |_| {
            if (session.owed_count == 0) return written;
            const step_written = session.write_oldest(output[written..]);
            written += step_written;
            if (step_written == 0) return written;
        }
        return written;
    }

    /// Writes what is left of the oldest owed response: its field section, then as much of the
    /// body as fits. A response written whole is removed from the queue.
    fn write_oldest(session: *Session, output: []u8) usize {
        assert(session.owed_count > 0);
        const stream_id = session.owed[0];
        var written: usize = 0;
        if (!session.head_written) {
            written = session.write_head(stream_id, output) orelse return 0;
            session.head_written = true;
        }
        const rest = constants.response_body[session.body_sent..];
        const sent = session.connection.write_data(output[written..], stream_id, rest, true) catch {
            return written;
        };
        session.body_sent += sent.consumed;
        if (session.body_sent == constants.response_body.len) session.finish_oldest();
        return written + sent.written;
    }

    /// Drops the response just written and makes the next one the oldest.
    fn finish_oldest(session: *Session) void {
        assert(session.owed_count > 0);
        for (1..session.owed_count) |index| session.owed[index - 1] = session.owed[index];
        session.owed_count -= 1;
        session.head_written = false;
        session.body_sent = 0;
    }

    /// Writes the response's field section, or null when the caller's buffer has no room for it.
    fn write_head(session: *Session, stream_id: u32, output: []u8) ?usize {
        const fields = [_]h2.hpack.Field{
            .{ .name = "content-type", .value = constants.response_content_type },
            .{ .name = "content-length", .value = constants.response_content_length },
        };
        return session.connection.write_response(
            output,
            stream_id,
            constants.response_status,
            &fields,
            false,
        ) catch null;
    }
};

/// The stream a request ended on, or null when the event ends none. RFC 9113 §8.1: a request ends
/// with END_STREAM, on its field section, on a DATA frame or on its trailer section.
fn ends_request(event: Event) ?u32 {
    return switch (event) {
        .request => |request| if (request.end_stream) request.stream_id else null,
        .data => |data| if (data.end_stream) data.stream_id else null,
        .trailers => |trailers| trailers.stream_id,
        else => null,
    };
}

const testing = std.testing;

/// The session the tests run on, placed outside any stack frame. Test-only.
var test_session: Session = undefined;

/// Where the tests read and write. Test-only.
var test_output: [constants.write_buffer_len]u8 = @splat(0);
var test_input: [constants.read_buffer_len]u8 = @splat(0);

/// The client preface and an empty SETTINGS frame, which every test starts with. Test-only.
const client_preface = h2.constants.client_preface ++ "\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// Feeds `input` one step at a time until the session neither consumes nor writes, and returns
/// everything it wrote. A session that failed leaves the rest of the input unread, which is why the
/// count is checked only while it is running. Test-only.
fn feed(input: []const u8) ![]const u8 {
    var consumed: usize = 0;
    var written: usize = 0;
    for (0..input.len + 1) |_| {
        const step = test_session.step(input[consumed..], test_output[written..]);
        consumed += step.consumed;
        written += step.written;
        if (step.consumed == 0 and step.written == 0) break;
    }
    if (!test_session.finished) try testing.expectEqual(input.len, consumed);
    return test_output[0..written];
}

/// Writes one HEADERS frame carrying a GET request for `path` on `stream_id`. Test-only.
fn request_frame(stream_id: u32, path: []const u8) ![]const u8 {
    var block: [h2.constants.frame_size_max]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(h2.constants.header_table_size_initial, .never);
    var block_writer = h2.core.Writer.init(&block);
    try encoder.begin_block(&block_writer);
    try encoder.write_field(&block_writer, ":method", "GET", .without_indexing);
    try encoder.write_field(&block_writer, ":scheme", "http", .without_indexing);
    try encoder.write_field(&block_writer, ":path", path, .without_indexing);
    try encoder.write_field(&block_writer, ":authority", "example.com", .without_indexing);
    var writer = h2.core.Writer.init(&test_input);
    try h2.frame.write_header(&writer, .{
        .length = @intCast(block_writer.written().len),
        .type = h2.constants.frame_type_headers,
        .flags = h2.constants.flag_end_headers | h2.constants.flag_end_stream,
        .stream_id = stream_id,
    });
    try writer.write_bytes(block_writer.written());
    return writer.written();
}

test "the server answers a GET request with 200, its body and END_STREAM" {
    test_session.init();
    const preface = try feed(client_preface);
    // The server's own SETTINGS frame, then the acknowledgment of the client's.
    try testing.expectEqual(h2.constants.frame_type_settings, preface[3]);
    const request = try request_frame(1, "/");
    const answer = try feed(request);
    // A HEADERS frame without END_STREAM, then a DATA frame with it.
    try testing.expectEqual(h2.constants.frame_type_headers, answer[3]);
    try testing.expectEqual(h2.constants.flag_end_headers, answer[4]);
    const head_len = h2.constants.frame_header_len + (@as(u32, answer[1]) << @bitSizeOf(u8) | answer[2]);
    const body = answer[head_len..];
    try testing.expectEqual(h2.constants.frame_type_data, body[3]);
    try testing.expectEqual(h2.constants.flag_end_stream, body[4]);
    try testing.expectEqualStrings(constants.response_body, body[h2.constants.frame_header_len..]);
    try testing.expect(!test_session.finished);
}

test "a request on a second stream is answered too, and the streams close" {
    test_session.init();
    _ = try feed(client_preface);
    _ = try feed(try request_frame(1, "/"));
    const second = try feed(try request_frame(3, "/index.html"));
    try testing.expectEqual(h2.constants.frame_type_headers, second[3]);
    try testing.expectEqual(0, test_session.connection.streams.peer_active);
    try testing.expectEqual(0, test_session.owed_count);
}

test "a peer that breaks the protocol gets a GOAWAY and the session is done" {
    test_session.init();
    _ = try feed(client_preface);
    // RFC 9113 §5.1: a DATA frame on an idle stream ends the connection.
    var writer = h2.core.Writer.init(&test_input);
    try h2.frame.write_data(&writer, 1, "test", false, 0);
    const answer = try feed(writer.written());
    try testing.expectEqual(h2.constants.frame_type_goaway, answer[3]);
    try testing.expect(test_session.finished);
    // A finished session writes nothing more and consumes nothing.
    const after = test_session.step(writer.written(), &test_output);
    try testing.expectEqual(0, after.consumed);
    try testing.expectEqual(0, after.written);
    try testing.expect(after.done);
}

/// The Length field of the frame at the start of `bytes` (RFC 9113 §4.1). Test-only.
fn frame_length(bytes: []const u8) u32 {
    var length: u32 = 0;
    for (bytes[0..h2.constants.frame_length_len]) |octet| length = (length << @bitSizeOf(u8)) | octet;
    return length;
}

test "the body is written across steps when the output has room for the head alone" {
    // The field section of this response is as long as the same one sent whole.
    test_session.init();
    _ = try feed(client_preface);
    const whole = try feed(try request_frame(1, "/"));
    try testing.expectEqual(h2.constants.frame_type_headers, whole[3]);
    const head_len = h2.constants.frame_header_len + frame_length(whole);

    test_session.init();
    _ = try feed(client_preface);
    const request = try request_frame(1, "/");
    // A buffer with no room for the response at all: the request is read and the answer owed.
    var cramped: [1]u8 = undefined;
    const first = test_session.step(request, &cramped);
    try testing.expectEqual(request.len, first.consumed);
    try testing.expectEqual(0, first.written);
    try testing.expect(!test_session.head_written);
    // A buffer that holds the field section and nothing of the body.
    const head = test_session.step("", test_output[0..head_len]);
    try testing.expectEqual(head_len, head.written);
    try testing.expectEqual(h2.constants.frame_type_headers, test_output[3]);
    try testing.expect(test_session.head_written);
    try testing.expectEqual(0, test_session.body_sent);
    // The body follows in the next step, with END_STREAM on it.
    const rest = test_session.step("", &test_output);
    try testing.expectEqual(h2.constants.frame_type_data, test_output[3]);
    try testing.expectEqual(h2.constants.flag_end_stream, test_output[4]);
    try testing.expectEqual(h2.constants.frame_header_len + constants.response_body.len, rest.written);
    try testing.expectEqual(0, test_session.owed_count);
}
