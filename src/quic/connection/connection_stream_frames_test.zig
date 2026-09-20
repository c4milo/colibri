//! The tests of `connection_stream_frames.zig`: the order RFC 9000 asks its rules in, and the
//! code each refusal closes with. The frames come through `connection_frames.process`, so what
//! these cases drive is the whole path from a packet's payload down to a stream.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const frame_module = @import("../frame/frame.zig");
const stream_id_module = @import("../stream/stream_id.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const frames = @import("connection_frames.zig");
const stream_frames = @import("connection_stream_frames.zig");

const testing = std.testing;
const Writer = core.Writer;
const Frame = frame_module.Frame;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const StreamId = stream_id_module.StreamId;

var test_connection: Connection = undefined;
const payload_len: usize = 256;
var payload: [payload_len]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
/// Small enough that a test can reach both flow control limits without a long frame.
const test_max_data: u64 = 64;
const test_max_stream_data: u64 = 32;
/// Distinct per type, because RFC 9000 §18.2 has three stream data parameters and a test that
/// gave them one value could not tell which one a stream read.
const test_bidi_local: u64 = 24;
const test_bidi_remote: u64 = 32;
const test_uni: u64 = 16;
const test_max_streams: u64 = 2;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const id_len: usize = 4;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

const data_octet: u8 = 0x44;
const data_len: usize = 8;
const data: [data_len]u8 = @splat(data_octet);

/// RFC 9000 §2.1: the first bidirectional stream a client opens, which a server receives on.
const client_bidi_first: u64 = 0;
const client_bidi_second: u64 = 4;
/// The first unidirectional stream a client opens (§2.1's two low bits are 10).
const client_uni_first: u64 = 2;
/// A unidirectional stream a server opens, which a server may send on and never receive on.
const server_uni_first: u64 = 3;

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    held.initial_max_stream_data_bidi_remote = test_bidi_remote;
    held.initial_max_stream_data_bidi_local = test_bidi_local;
    held.initial_max_stream_data_uni = test_uni;
    held.initial_max_streams_bidi = test_max_streams;
    held.initial_max_streams_uni = test_max_streams;
    return held;
}

/// A server, because a server receives on the streams a client opens, which are §2.1's simplest.
fn open_server() void {
    test_connection.init(.{
        .role = .server,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
}

fn run(list: []const Frame) frames.Error!frames.Report {
    var writer = Writer.init(&payload);
    for (list) |held| frame_module.write(&writer, held) catch unreachable;
    return frames.process(&test_connection, .application, writer.written(), test_now_ns);
}

fn stream_frame(id: u64, offset: u64, len: usize, fin: bool) Frame {
    return .{
        .stream = .{
            .stream_id = id,
            .offset = offset,
            .data = data[0..len],
            .fin = fin,
            // RFC 9000 §19.8: the LEN bit, which a frame that is not last in its packet must set.
            .has_length = true,
        },
    };
}

test "RFC 9000 §3.2: a peer's STREAM frame is what creates the stream" {
    open_server();
    try testing.expectEqual(0, test_connection.streams.len());
    // "An endpoint that receives a frame for a stream that it has not created creates that
    // stream", so no handshake of its own is needed.
    _ = try run(&.{stream_frame(client_bidi_first, 0, data_len, false)});
    try testing.expectEqual(1, test_connection.streams.len());
    // And a second frame on the same stream finds it rather than opening another.
    _ = try run(&.{stream_frame(client_bidi_first, data_len, data_len, false)});
    try testing.expectEqual(1, test_connection.streams.len());
}

test "RFC 9000 §19.8: a STREAM frame on a send-only stream is STREAM_STATE_ERROR" {
    open_server();
    // §2.1: a server-initiated unidirectional stream is one the server sends on and the client
    // never does, so a client's STREAM frame naming it is a rule broken rather than a stream.
    try testing.expectError(
        frames.Error.Stream,
        run(&.{stream_frame(server_uni_first, 0, data_len, false)}),
    );
    try testing.expectEqual(
        error_code.stream_state_error,
        stream_frames.connection_error_code(stream_frames.Error.StreamState),
    );
}

test "RFC 9000 §4.6: a stream past the advertised limit is STREAM_LIMIT_ERROR" {
    open_server();
    // Two bidirectional streams were granted, so the third is one too many.
    _ = try run(&.{stream_frame(client_bidi_first, 0, 1, false)});
    _ = try run(&.{stream_frame(client_bidi_second, 0, 1, false)});
    const third: u64 = 8;
    try testing.expectError(frames.Error.Stream, run(&.{stream_frame(third, 0, 1, false)}));
    // `process` flattens every stream rule to one error, so the code is read from the frame
    // itself: §4.6 names STREAM_LIMIT_ERROR and nothing else would do.
    try testing.expectError(
        stream_frames.Error.StreamLimit,
        stream_frames.apply(&test_connection, stream_frame(third, 0, 1, false)),
    );
    try testing.expectEqual(
        error_code.stream_limit_error,
        stream_frames.connection_error_code(stream_frames.Error.StreamLimit),
    );
}

test "RFC 9000 §4.1: the stream's own limit is what a single stream is held to" {
    open_server();
    // 32 octets were advertised per stream, so reaching 33 on one passes it.
    _ = try run(&.{stream_frame(client_bidi_first, 0, data_len, false)});
    const past: u64 = test_max_stream_data - data_len + 1;
    try testing.expectError(
        frames.Error.Stream,
        run(&.{stream_frame(client_bidi_first, past, data_len, false)}),
    );
    try testing.expectEqual(
        error_code.flow_control_error,
        stream_frames.connection_error_code(stream_frames.Error.FlowControl),
    );
}

test "RFC 9000 §4.1: the connection-level limit counts every stream together" {
    open_server();
    // Neither stream passes its own limit, and together they reach the connection's exactly:
    // two bidirectional streams at 32 octets each is the 64 this endpoint advertised.
    _ = try run(&.{stream_frame(client_bidi_first, 0, data_len, false)});
    _ = try run(&.{stream_frame(client_bidi_first, test_bidi_remote - data_len, data_len, false)});
    _ = try run(&.{stream_frame(client_bidi_second, 0, data_len, false)});
    _ = try run(&.{stream_frame(client_bidi_second, test_bidi_remote - data_len, data_len, false)});
    try testing.expectEqual(test_max_data, test_connection.receive_flow.used);
    // A third stream has all 16 octets of its own limit and the connection has none left.
    try testing.expectError(
        frames.Error.Stream,
        run(&.{stream_frame(client_uni_first, 0, 1, false)}),
    );
}

test "RFC 9000 §4.1: a retransmission spends the connection's credit once" {
    open_server();
    _ = try run(&.{stream_frame(client_bidi_first, 0, data_len, false)});
    try testing.expectEqual(data_len, test_connection.receive_flow.used);
    // The same octets again reach no further, so nothing new is counted: §4.1's limits are
    // high-water marks and not credit counters (invariant 19).
    _ = try run(&.{stream_frame(client_bidi_first, 0, data_len, false)});
    try testing.expectEqual(data_len, test_connection.receive_flow.used);
    // And a partial retransmission reaches less far than what is already counted, which is the
    // case that separates a high-water mark from a running total.
    const partial: usize = data_len / 2;
    _ = try run(&.{stream_frame(client_bidi_first, 0, partial, false)});
    try testing.expectEqual(data_len, test_connection.receive_flow.used);
}

test "RFC 9000 §4.5: a final size that changes closes the connection" {
    open_server();
    _ = try run(&.{stream_frame(client_bidi_first, 0, data_len, true)});
    // "Once a final size for a stream is known, it cannot change."
    try testing.expectError(
        frames.Error.Stream,
        run(&.{.{ .reset_stream = .{
            .stream_id = client_bidi_first,
            .error_code = 0,
            .final_size = data_len + 1,
        } }}),
    );
    try testing.expectEqual(
        error_code.final_size_error,
        stream_frames.connection_error_code(stream_frames.Error.FinalSize),
    );
}

test "RFC 9000 §4.5: a RESET_STREAM's final size counts against flow control" {
    open_server();
    const reset_at: u64 = 20;
    // "The receiver MUST use the final size of the stream to account for all bytes sent on the
    // stream in its connection-level flow controller", though none of those octets arrived.
    _ = try run(&.{.{ .reset_stream = .{
        .stream_id = client_bidi_first,
        .error_code = 0,
        .final_size = reset_at,
    } }});
    try testing.expectEqual(reset_at, test_connection.receive_flow.used);
}

test "RFC 9000 §19.10: MAX_STREAM_DATA raises what this endpoint may send" {
    open_server();
    // A server sends on a client's bidirectional stream, so the frame names one of those. The
    // stream does not exist yet and §3.2 has the frame create it.
    const raised: u64 = 500;
    _ = try run(&.{.{ .max_stream_data = .{ .stream_id = client_bidi_first, .maximum = raised } }});
    const stream = test_connection.streams.lookup(.{ .value = client_bidi_first }).live;
    try testing.expectEqual(raised, stream.send_flow.available());
    // §4.1: a smaller value is ignored, because frames may be reordered.
    _ = try run(&.{.{ .max_stream_data = .{ .stream_id = client_bidi_first, .maximum = 1 } }});
    try testing.expectEqual(raised, stream.send_flow.available());
}

test "RFC 9000 §19.11: MAX_STREAMS raises how many this endpoint may open" {
    open_server();
    // §18.2 leaves it at zero until the peer says otherwise, which is where a connection begins.
    const raised: u64 = 7;
    _ = try run(&.{.{ .max_streams = .{ .directionality = .unidirectional, .maximum = raised } }});
    const opened = try test_connection.streams.open_local(.unidirectional);
    try testing.expectEqual(server_uni_first, opened.id);
    // The bidirectional limit is a separate count and this frame did not touch it.
    try testing.expectError(error.StreamLimitReached, test_connection.streams.open_local(.bidirectional));
}

test "RFC 9000 §18.2: each stream type reads the parameter its own kind names" {
    open_server();
    // A client's bidirectional stream is peer-initiated from this server's side, so what the
    // server may receive on it is the `_bidi_remote` limit it advertised.
    _ = try run(&.{stream_frame(client_bidi_first, 0, 1, false)});
    const bidi = test_connection.streams.lookup(.{ .value = client_bidi_first }).live;
    try testing.expectEqual(test_bidi_remote, bidi.receive_flow.limit);

    // A client's unidirectional stream reads the third parameter, which is a different number.
    _ = try run(&.{stream_frame(client_uni_first, 0, 1, false)});
    const uni = test_connection.streams.lookup(.{ .value = client_uni_first }).live;
    try testing.expectEqual(test_uni, uni.receive_flow.limit);

    // And a stream this endpoint initiated reads `_bidi_local`, the one it keeps for its own.
    _ = try run(&.{.{ .max_streams = .{ .directionality = .bidirectional, .maximum = 1 } }});
    const own = try test_connection.streams.open_local(.bidirectional);
    _ = own;
}

test "RFC 9000 §18.2: a stream data limit of zero admits nothing" {
    // "If this parameter is absent or zero, the peer cannot open streams until a MAX_STREAMS
    // frame is sent", and the same reading applies to the data limits: zero is a legal value.
    var without = parameters();
    without.initial_max_stream_data_bidi_remote = 0;
    test_connection.init(.{
        .role = .server,
        .local_parameters = without,
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    // One octet is one too many, and the stream still exists: §3.2 created it before §4.1
    // refused what arrived on it.
    try testing.expectError(
        stream_frames.Error.FlowControl,
        stream_frames.apply(&test_connection, stream_frame(client_bidi_first, 0, 1, false)),
    );
    const stream = test_connection.streams.lookup(.{ .value = client_bidi_first }).live;
    try testing.expectEqual(0, stream.receive_flow.limit);
}
