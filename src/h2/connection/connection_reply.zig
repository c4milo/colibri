//! The frames colibri owes the peer, in fixed slots the connection owns (decision 39): a
//! SETTINGS acknowledgment (RFC 9113 §6.5.3), a PING acknowledgment (§6.7), a WINDOW_UPDATE for
//! the connection (§6.9), a RST_STREAM or a WINDOW_UPDATE for one stream, and the GOAWAY that ends
//! the connection (§6.8). `write` puts as many as the caller's buffer holds into it, in that
//! order, and keeps the rest for the next call.
//!
//! Every queue is bounded by a named limit, so a peer that never reads cannot make colibri hold
//! more. A full queue does not drop a reply and does not end the connection: the connection stops
//! reading frames until the caller writes what is pending, which `is_full` reports.
//!
//! A frame is written whole or not at all, because every writer in `frame` commits nothing when
//! the buffer is short. The GOAWAY goes last: RFC 9113 §6.8 makes it the last frame of the
//! connection, and the replies before it are ones the peer asked for.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");

const Writer = core.Writer;

/// What a reply about one stream says: RFC 9113 §6.4 ends the stream, §6.9 gives it more window.
pub const StreamReplyKind = enum { rst_stream, window_update };

/// One reply about one stream. `value` is the error code of a RST_STREAM or the increment of a
/// WINDOW_UPDATE, which the two frames carry in the same position.
pub const StreamReply = struct {
    stream_id: u32,
    kind: StreamReplyKind,
    value: u32,
};

/// The GOAWAY colibri has decided to send: the last stream it acted on and why it is going away
/// (RFC 9113 §6.8). colibri sends no Additional Debug Data, which §6.8 gives no semantic value.
pub const Goaway = struct {
    last_stream_id: u32,
    error_code: u32,
};

/// The queues, in storage the connection holds.
pub const Replies = struct {
    /// SETTINGS frames the peer sent that colibri owes an acknowledgment for (RFC 9113 §6.5.3).
    settings_acks: u32,
    /// The Opaque Data of the PING frames colibri owes an answer for, oldest first (§6.7).
    ping_acks: [constants.ping_ack_pending_max][constants.ping_len]u8,
    ping_ack_count: u32,
    /// The increment of the WINDOW_UPDATE colibri owes on the connection, or 0 for none (§6.9).
    /// One frame carries the whole increment, which §6.9.1 lets a receiver coalesce.
    connection_increment: u32,
    /// The replies about single streams, oldest first.
    stream_replies: [constants.stream_replies_max]StreamReply,
    stream_reply_count: u32,
    /// The GOAWAY colibri sends, once it has one to send (§6.8).
    goaway: ?Goaway,

    /// Empties every queue.
    pub fn init(replies: *Replies) void {
        replies.settings_acks = 0;
        replies.ping_acks = @splat(@splat(0));
        replies.ping_ack_count = 0;
        replies.connection_increment = 0;
        replies.stream_replies = @splat(.{ .stream_id = 0, .kind = .rst_stream, .value = 0 });
        replies.stream_reply_count = 0;
        replies.goaway = null;
        assert(replies.is_empty());
    }

    /// Whether every queue is empty and the caller has nothing to write.
    pub fn is_empty(replies: *const Replies) bool {
        return replies.settings_acks == 0 and replies.ping_ack_count == 0 and
            replies.connection_increment == 0 and replies.stream_reply_count == 0 and
            replies.goaway == null;
    }

    /// Whether any queue is at its limit, which is when the connection stops reading frames: the
    /// next frame could owe a reply there is no slot for.
    pub fn is_full(replies: *const Replies) bool {
        return replies.settings_acks == constants.settings_ack_pending_max or
            replies.ping_ack_count == constants.ping_ack_pending_max or
            replies.stream_reply_count == constants.stream_replies_max;
    }

    /// Owes the peer an acknowledgment of the SETTINGS frame it sent (RFC 9113 §6.5.3).
    pub fn push_settings_ack(replies: *Replies) void {
        assert(replies.settings_acks < constants.settings_ack_pending_max);
        replies.settings_acks += 1;
    }

    /// Owes the peer a PING carrying the Opaque Data it sent (RFC 9113 §6.7).
    pub fn push_ping_ack(replies: *Replies, opaque_data: [constants.ping_len]u8) void {
        assert(replies.ping_ack_count < constants.ping_ack_pending_max);
        replies.ping_acks[replies.ping_ack_count] = opaque_data;
        replies.ping_ack_count += 1;
    }

    /// Adds `increment` to the WINDOW_UPDATE colibri owes on the connection (RFC 9113 §6.9). The
    /// sum stays at or below `window_max`, because it never exceeds what the peer has sent.
    pub fn add_connection_increment(replies: *Replies, increment: u32) void {
        assert(increment > 0 and increment <= constants.window_max);
        assert(replies.connection_increment <= constants.window_max - increment);
        replies.connection_increment += increment;
    }

    /// Owes the peer a RST_STREAM or a WINDOW_UPDATE about one stream.
    pub fn push_stream_reply(replies: *Replies, reply: StreamReply) void {
        assert(replies.stream_reply_count < constants.stream_replies_max);
        assert(reply.stream_id != constants.connection_stream_id);
        assert(reply.stream_id <= constants.stream_id_max);
        assert(reply.kind != .window_update or (reply.value > 0 and reply.value <= constants.window_max));
        replies.stream_replies[replies.stream_reply_count] = reply;
        replies.stream_reply_count += 1;
    }

    /// Sets the GOAWAY colibri sends. The first one stands: invariant 16 keeps the last stream
    /// identifier from rising, and the connection sends one GOAWAY and then stops reading.
    pub fn set_goaway(replies: *Replies, goaway: Goaway) void {
        assert(goaway.last_stream_id <= constants.stream_id_max);
        if (replies.goaway != null) return;
        replies.goaway = goaway;
    }

    /// Writes as many queued frames as `output` holds, oldest queue first, and returns the octets
    /// written. A frame that does not fit is kept for the next call.
    pub fn write(replies: *Replies, output: []u8) usize {
        var writer = Writer.init(output);
        write_settings_acks(replies, &writer);
        write_ping_acks(replies, &writer);
        write_connection_increment(replies, &writer);
        write_stream_replies(replies, &writer);
        write_goaway(replies, &writer);
        return writer.written().len;
    }
};

fn write_settings_acks(replies: *Replies, writer: *Writer) void {
    while (replies.settings_acks > 0) {
        frame.write_settings_ack(writer) catch return;
        replies.settings_acks -= 1;
    }
}

fn write_ping_acks(replies: *Replies, writer: *Writer) void {
    while (replies.ping_ack_count > 0) {
        // RFC 9113 §6.7: the endpoint answers with the Opaque Data it was sent, unchanged.
        frame.write_ping(writer, replies.ping_acks[0], true) catch return;
        shift_ping_acks(replies);
    }
}

fn shift_ping_acks(replies: *Replies) void {
    assert(replies.ping_ack_count > 0);
    for (1..replies.ping_ack_count) |index| replies.ping_acks[index - 1] = replies.ping_acks[index];
    replies.ping_ack_count -= 1;
}

fn write_connection_increment(replies: *Replies, writer: *Writer) void {
    if (replies.connection_increment == 0) return;
    // RFC 9113 §6.9: a WINDOW_UPDATE on stream 0 gives the connection window the increment.
    frame.write_window_update(writer, constants.connection_stream_id, replies.connection_increment) catch return;
    replies.connection_increment = 0;
}

fn write_stream_replies(replies: *Replies, writer: *Writer) void {
    while (replies.stream_reply_count > 0) {
        const reply = replies.stream_replies[0];
        switch (reply.kind) {
            // RFC 9113 §6.4: a RST_STREAM carries the error code that ends the stream.
            .rst_stream => frame.write_rst_stream(writer, reply.stream_id, reply.value) catch return,
            // RFC 9113 §6.9: a WINDOW_UPDATE on a stream gives that stream's window the increment.
            .window_update => frame.write_window_update(writer, reply.stream_id, reply.value) catch return,
        }
        shift_stream_replies(replies);
    }
}

fn shift_stream_replies(replies: *Replies) void {
    assert(replies.stream_reply_count > 0);
    for (1..replies.stream_reply_count) |index| replies.stream_replies[index - 1] = replies.stream_replies[index];
    replies.stream_reply_count -= 1;
}

fn write_goaway(replies: *Replies, writer: *Writer) void {
    const goaway = replies.goaway orelse return;
    // RFC 9113 §6.8: the GOAWAY names the highest stream the sender acted on and why it stops.
    frame.write_goaway(writer, goaway.last_stream_id, goaway.error_code, "") catch return;
    replies.goaway = null;
}

const testing = std.testing;

/// The queues the tests run on, placed outside any stack frame. Test-only.
var test_replies: Replies = undefined;

/// Where the tests write frames. Test-only.
var test_output: [constants.frame_size_max]u8 = @splat(0);

test "an empty queue writes nothing, and init empties every queue" {
    test_replies.init();
    try testing.expect(test_replies.is_empty());
    try testing.expect(!test_replies.is_full());
    try testing.expectEqual(0, test_replies.write(&test_output));
    test_replies.push_settings_ack();
    test_replies.push_ping_ack("12345678".*);
    test_replies.add_connection_increment(7);
    test_replies.push_stream_reply(.{ .stream_id = 1, .kind = .rst_stream, .value = constants.error_cancel });
    test_replies.set_goaway(.{ .last_stream_id = 1, .error_code = constants.error_no_error });
    try testing.expect(!test_replies.is_empty());
    test_replies.init();
    try testing.expect(test_replies.is_empty());
}

test "the queues write in order: SETTINGS ACK, PING ACK, the connection window, the streams, then GOAWAY" {
    test_replies.init();
    test_replies.set_goaway(.{ .last_stream_id = 3, .error_code = constants.error_protocol_error });
    test_replies.push_stream_reply(.{ .stream_id = 3, .kind = .window_update, .value = 100 });
    test_replies.add_connection_increment(100);
    test_replies.push_ping_ack("deadbeef".*);
    test_replies.push_settings_ack();
    const written = test_replies.write(&test_output);
    const expected = "\x00\x00\x00\x04\x01\x00\x00\x00\x00" ++
        "\x00\x00\x08\x06\x01\x00\x00\x00\x00deadbeef" ++
        "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x64" ++
        "\x00\x00\x04\x08\x00\x00\x00\x00\x03\x00\x00\x00\x64" ++
        "\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x01";
    try testing.expectEqualSlices(u8, expected, test_output[0..written]);
    try testing.expect(test_replies.is_empty());
}

test "a short buffer writes what fits and keeps the rest, frame by frame" {
    test_replies.init();
    test_replies.push_settings_ack();
    test_replies.push_settings_ack();
    test_replies.push_ping_ack("01234567".*);
    // Two SETTINGS acknowledgments fit in the room given; the PING acknowledgment needs eight
    // octets more than what is left, so it stays queued.
    const room = 2 * constants.frame_header_len + 1;
    try testing.expectEqual(2 * constants.frame_header_len, test_replies.write(test_output[0..room]));
    try testing.expectEqual(0, test_replies.settings_acks);
    try testing.expectEqual(1, test_replies.ping_ack_count);
    // A buffer one octet short of the whole frame writes nothing at all.
    const short = constants.frame_header_len + constants.ping_len - 1;
    try testing.expectEqual(0, test_replies.write(test_output[0..short]));
    try testing.expectEqual(1, test_replies.ping_ack_count);
    const whole = test_replies.write(&test_output);
    try testing.expectEqual(constants.frame_header_len + constants.ping_len, whole);
    try testing.expect(test_replies.is_empty());
}

test "PING acknowledgments keep the order the peer sent them in, and the queue is bounded" {
    test_replies.init();
    for (0..constants.ping_ack_pending_max) |index| {
        var data: [constants.ping_len]u8 = @splat(0);
        data[0] = @intCast(index);
        test_replies.push_ping_ack(data);
    }
    try testing.expect(test_replies.is_full());
    const written = test_replies.write(&test_output);
    try testing.expectEqual(constants.ping_ack_pending_max * (constants.frame_header_len + constants.ping_len), written);
    for (0..constants.ping_ack_pending_max) |index| {
        const payload = test_output[constants.frame_header_len + index * (constants.frame_header_len + constants.ping_len) ..];
        try testing.expectEqual(index, payload[0]);
    }
    try testing.expect(!test_replies.is_full());
}

test "stream replies keep their order, and the connection increment coalesces into one frame" {
    test_replies.init();
    test_replies.push_stream_reply(.{ .stream_id = 5, .kind = .rst_stream, .value = constants.error_stream_closed });
    test_replies.push_stream_reply(.{ .stream_id = 1, .kind = .window_update, .value = 3 });
    test_replies.add_connection_increment(10);
    test_replies.add_connection_increment(5);
    const written = test_replies.write(&test_output);
    const expected = "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x0f" ++
        "\x00\x00\x04\x03\x00\x00\x00\x00\x05\x00\x00\x00\x05" ++
        "\x00\x00\x04\x08\x00\x00\x00\x00\x01\x00\x00\x00\x03";
    try testing.expectEqualSlices(u8, expected, test_output[0..written]);
}

test "the first GOAWAY stands, and it is written after the replies the peer asked for" {
    test_replies.init();
    test_replies.set_goaway(.{ .last_stream_id = 7, .error_code = constants.error_no_error });
    test_replies.set_goaway(.{ .last_stream_id = 9, .error_code = constants.error_internal_error });
    try testing.expectEqual(7, test_replies.goaway.?.last_stream_id);
    try testing.expectEqual(constants.error_no_error, test_replies.goaway.?.error_code);
    const written = test_replies.write(&test_output);
    try testing.expectEqual(constants.frame_header_len + constants.goaway_len_min, written);
    try testing.expectEqual(null, test_replies.goaway);
}
