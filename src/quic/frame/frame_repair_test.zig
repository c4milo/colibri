//! RFC 9000 §13.3's table, read back one frame type at a time. Split off `frame_test.zig`
//! because a hand-written source file stays at or under 500 lines with its tests included.
const std = @import("std");
const frame = @import("frame.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const Frame = frame.Frame;

/// Values the table needs and none of which it reads.
const reason = "because the peer said so";
const token = "a token the server issued";
const stream_data = "stream octets";
const connection_id = "\xaa\xbb\xcc\xdd";
const path_data: [constants.path_challenge_len]u8 = "\x01\x02\x03\x04\x05\x06\x07\x08".*;
const reset_token_octet: u8 = 0x10;
const reset_token: [constants.stateless_reset_token_len]u8 = @splat(reset_token_octet);

const ack_largest: u64 = 100;

fn ack_frame() Frame {
    return .{ .ack = .{
        .ranges = .{ .largest_acknowledged = ack_largest, .first_range = 0, .octets = &.{}, .count = 0 },
        .delay = 0,
        .ecn = null,
    } };
}

test "RFC 9000 §13.3: every frame type says what a lost packet owes for it" {
    // §13.3 is a table of rules, one per frame, and this is that table read back. The switch in
    // `Frame.repair` has no `else`, so a frame type added to the union stops the build until its
    // rule is written; this pins that the rules written are the ones §13.3 states.
    const expected = [_]struct { Frame, frame.Repair }{
        // "PING and PADDING frames contain no information, so lost PING or PADDING frames do not
        // require repair."
        .{ .{ .padding = .{ .len = 1 } }, .none },
        .{ .ping, .none },
        // "ACK frames carry the most recent set of acknowledgments", so an old one is not resent.
        .{ ack_frame(), .none },
        // "Connection close signals ... are not sent again when packet loss is detected."
        .{ .{ .connection_close = .{ .layer = .transport, .error_code = 0, .frame_type = 0, .reason = reason } }, .none },
        // "Responses to path validation using PATH_RESPONSE frames are sent just once."
        .{ .{ .path_response = .{ .data = &path_data } }, .none },
        // "PATH_CHALLENGE frames include a different payload each time they are sent."
        .{ .{ .path_challenge = .{ .data = &path_data } }, .fresh },
        // CRYPTO and STREAM data are "retransmitted ... until all data has been acknowledged".
        .{ .{ .crypto = .{ .offset = 0, .data = stream_data } }, .same_octets },
        .{ .{ .stream = .{ .stream_id = 3, .offset = 0, .data = stream_data, .fin = false, .has_length = true } }, .same_octets },
        // A RESET_STREAM "is sent until acknowledged", and its content "MUST NOT change when it
        // is sent again"; STOP_SENDING is sent until the receiving part reaches a state.
        .{ .{ .reset_stream = .{ .stream_id = 4, .error_code = 1, .final_size = 9 } }, .same_octets },
        .{ .{ .stop_sending = .{ .stream_id = 4, .error_code = 1 } }, .same_octets },
        // These three are "retransmitted if the packet containing them is lost", and a
        // NEW_CONNECTION_ID repeat carries "the same sequence number value".
        .{ .{ .new_connection_id = .{
            .sequence_number = 7,
            .retire_prior_to = 3,
            .connection_id = connection_id,
            .stateless_reset_token = &reset_token,
        } }, .same_octets },
        .{ .{ .retire_connection_id = .{ .sequence_number = 5 } }, .same_octets },
        .{ .{ .new_token = .{ .token = token } }, .same_octets },
        // "The HANDSHAKE_DONE frame MUST be retransmitted until it is acknowledged."
        .{ .handshake_done, .same_octets },
        // "The current connection maximum data is sent in MAX_DATA frames", and the same shape
        // for the other limits: what goes out is the value now, not the value that was lost.
        .{ .{ .max_data = .{ .maximum = 1 } }, .current_value },
        .{ .{ .max_stream_data = .{ .stream_id = 4, .maximum = 1 } }, .current_value },
        .{ .{ .max_streams = .{ .directionality = .bidirectional, .maximum = 1 } }, .current_value },
        // "A new frame is sent if a packet containing the most recent frame for a scope is lost,
        // but only while the endpoint is blocked on the corresponding limit."
        .{ .{ .data_blocked = .{ .limit = 1 } }, .current_value },
        .{ .{ .stream_data_blocked = .{ .stream_id = 4, .limit = 1 } }, .current_value },
        .{ .{ .streams_blocked = .{ .directionality = .unidirectional, .limit = 1 } }, .current_value },
    };
    for (expected) |held| try testing.expectEqual(held[1], held[0].repair());
    // Every tag of the union is named above, so the table is the whole of §13.3 and not a sample.
    try testing.expectEqual(@typeInfo(Frame).@"union".fields.len, expected.len);
}
