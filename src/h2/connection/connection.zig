//! One h2 connection: the caller's octets in, at most one event per frame out, and the frames
//! colibri owes written back into the caller's buffer (decision 39, design §4.1).
//!
//! `receive` consumes at most one whole frame and returns how many octets it took and at most one
//! event. A count of 0 means one of two things, and `has_pending` tells them apart: the slice
//! holds no whole frame yet, or the replies must be written before more frames are read. The
//! caller loops over `receive` until it returns 0, writes what is pending, and reads more octets.
//!
//! `write_pending` writes, in order: the client connection preface at a client (RFC 9113 §3.4),
//! colibri's own SETTINGS frame, then the replies `connection_reply.zig` holds. This file writes
//! nothing else: the response a server sends is the caller's, through the send path.
//!
//! A frame the peer sends that breaks the protocol ends the connection: `receive` returns
//! `error.ConnectionFailed`, a GOAWAY carrying the code is queued, and `failure` holds that code
//! (§5.4.1). A frame that breaks one stream queues a RST_STREAM and returns an event, because the
//! connection goes on (§5.4.2). The two are never confused (invariant 27).
//!
//! The connection places every piece it needs: the settings of both endpoints, the HPACK decoder
//! and encoder, the stream table, the field-block slot, both connection flow-control windows and
//! the reply queues. The caller owns the struct and colibri allocates nothing (decision 35).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const hpack = @import("hpack");
const tls = @import("tls");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const settings = @import("../settings.zig");
const window = @import("../window.zig");
const message = @import("../message/message.zig");
const streams_table = @import("../stream/streams.zig");
const field_block = @import("../field_block.zig");
const connection_receive = @import("connection_receive.zig");
const connection_send = @import("connection_send.zig");
const connection_request = @import("connection_request.zig");
const connection_tls = @import("connection_tls.zig");
const reply = @import("connection_reply.zig");

const Role = @import("../role.zig").Role;
const Writer = core.Writer;

/// Why `receive` stopped. The peer broke the protocol, the connection is closing, and `failure`
/// names the code of the GOAWAY now queued (RFC 9113 §5.4.1). The caller writes what is pending
/// and closes the transport.
pub const Error = error{ConnectionFailed};

/// Why a send the caller asked for did not happen (`connection_send.zig`).
pub const SendError = connection_send.Error;

/// What `write_data` sent and wrote (`connection_send.zig`).
pub const DataWritten = connection_send.DataWritten;

/// Why a request the caller asked for did not go out (`connection_request.zig`).
pub const RequestError = connection_request.Error;

/// The pseudo-header fields of a request a client sends (`connection_request.zig`).
pub const Request_ = connection_request.Request;

/// What `write_request` opened and wrote (`connection_request.zig`).
pub const Sent = connection_request.Sent;

/// A request the peer sent, at a server: its pseudo-header fields, and the field section it came
/// from, which `field_section` returns until the next call (RFC 9113 §8.3.1).
pub const Request = struct {
    stream_id: u32,
    request: message.Request,
    end_stream: bool,
};

/// A response the peer sent, at a client (RFC 9113 §8.3.2).
pub const Response = struct {
    stream_id: u32,
    response: message.Response,
    end_stream: bool,
};

/// A trailer section the peer sent, which ends the stream (RFC 9113 §8.1).
pub const Trailers = struct {
    stream_id: u32,
};

/// DATA the peer sent. `payload` points into the caller's input and is valid until the next call.
pub const Data = struct {
    stream_id: u32,
    payload: []const u8,
    end_stream: bool,
};

/// A stream that ended with a RST_STREAM: the peer's (`stream_reset`) or colibri's
/// (`stream_refused`), carrying the code the frame names (RFC 9113 §6.4).
pub const StreamReset = struct {
    stream_id: u32,
    error_code: u32,
};

/// The GOAWAY the peer sent (RFC 9113 §6.8). Its Additional Debug Data carries no semantic value
/// and is not reported.
pub const PeerGoaway = struct {
    last_stream_id: u32,
    error_code: u32,
};

/// What one frame meant to the caller, at most one per `receive` (decision 39).
pub const Event = union(enum) {
    /// The peer acknowledged the SETTINGS colibri sent, which are now in force (RFC 9113 §6.5.3).
    settings_acknowledged,
    /// The peer's SETTINGS frame was applied; colibri owes the acknowledgment (§6.5.3).
    settings_applied,
    /// The peer sent a PING carrying the ACK flag, with this Opaque Data (§6.7). colibri sends no PING of its own, so it never asked for one.
    ping_acknowledged: [constants.ping_len]u8,
    request: Request,
    response: Response,
    trailers: Trailers,
    data: Data,
    /// The peer ended a stream (§6.4).
    stream_reset: StreamReset,
    /// colibri ended a stream and queued the RST_STREAM (§5.4.2).
    stream_refused: StreamReset,
    goaway: PeerGoaway,
};

/// What one `receive` call consumed and produced.
pub const Received = struct {
    /// Octets of the caller's slice the connection took. 0 when no whole frame was there, or when
    /// the replies must be written first.
    consumed: usize,
    /// What the frame meant, when it meant anything to the caller.
    event: ?Event,
};

/// One connection, in storage the caller places (decision 35).
pub const Connection = struct {
    /// Which endpoint colibri is (RFC 9113 §5.1.1, §8.3).
    role: Role,
    /// The settings colibri advertised, in force from the start for everything but the peer's
    /// view of them.
    local: settings.Values,
    /// The settings the peer advertised, applied as its SETTINGS frames arrive (§6.5.3).
    peer: settings.Values,
    /// The SETTINGS frames colibri sent and has not seen acknowledged (§6.5.3).
    pending: settings.Pending,
    /// Octets of the client connection preface colibri has read, at a server (§3.4).
    preface_read_len: u32,
    /// Whether the client connection preface has been written, at a client (§3.4).
    preface_written: bool,
    /// Whether colibri's own SETTINGS frame has been written (§3.4).
    settings_written: bool,
    /// Whether a frame has been read from the peer. The first one must be SETTINGS (§3.4).
    first_frame_read: bool,
    /// The code of the GOAWAY colibri queued once the peer broke the protocol, or null (§5.4.1).
    failure: ?u32,
    /// The decoder of the field blocks the peer sends, with colibri's own table limit (§4.3).
    decoder: hpack.Decoder,
    /// The encoder of the field blocks colibri sends, under the peer's table limit (§4.3).
    encoder: hpack.Encoder,
    /// The streams of this connection (§5.1, decision 14).
    streams: streams_table.Streams,
    /// The one field block being reassembled (invariant 14, decision 40).
    block: field_block.FieldBlock,
    /// The space the peer gave colibri for DATA on the connection (§6.9.1).
    send_window: window.Window,
    /// The space colibri gave the peer for DATA on the connection (§6.9.1).
    receive_window: window.Receiver,
    /// The frames colibri owes the peer (`connection_reply.zig`).
    replies: reply.Replies,
    /// Whether the section of the field block in progress is dropped once it is decoded: the
    /// stream it belongs to was refused, reset or never opened (`connection_headers.zig`).
    block_discarded: bool,
    /// Where a field section colibri sends is encoded before it is cut into frames
    /// (`connection_send.zig`).
    send_block: [constants.send_block_len_max]u8,
    /// The TLS provider this connection runs over, or null for the cleartext prior-knowledge
    /// endpoint of §3.3 (decision 44, `connection_tls.zig`).
    provider: ?tls.Provider,
    /// Records in a row that carried no application data, counted by `connection_tls.zig`. A
    /// peer chooses how many it sends, so the run is bounded (`records_without_data_max`).
    records_without_data: u32,
    /// RST_STREAM frames colibri has sent since `rst_stream_period_start_ns` (§10.5).
    rst_stream_sent: u32,
    /// The instant the current RST_STREAM rate period began.
    rst_stream_period_start_ns: u64,

    /// Makes a connection for an endpoint in `role`, with nothing read and nothing written. The
    /// caller writes the preface with `write_pending` before it reads the peer's.
    pub fn init(connection: *Connection, role: Role) void {
        connection.role = role;
        connection.local = settings.advertised(role);
        connection.peer = settings.initial;
        connection.pending.init();
        connection.preface_read_len = 0;
        connection.preface_written = false;
        connection.settings_written = false;
        connection.first_frame_read = false;
        connection.failure = null;
        connection.decoder.init(connection.local.header_table_size);
        connection.encoder.init(connection.peer.header_table_size, .when_shorter);
        connection.streams.init(role);
        connection.block.init();
        // RFC 9113 §6.9.2: the connection's flow-control window starts at the initial value and
        // SETTINGS_INITIAL_WINDOW_SIZE never changes it; only stream windows move with it.
        connection.send_window = window.Window.init(constants.initial_window_size_initial);
        connection.receive_window = window.Receiver.init(constants.initial_window_size_initial);
        connection.replies.init();
        connection.block_discarded = false;
        connection.send_block = @splat(0);
        connection.provider = null;
        connection.records_without_data = 0;
        connection.rst_stream_sent = 0;
        connection.rst_stream_period_start_ns = 0;
        assert(!connection.has_failed());
        assert(connection.streams.len() == 0);
    }

    /// Consumes at most one whole frame of `input` and returns what it meant. See the header for
    /// what a count of 0 means.
    pub fn receive(connection: *Connection, input: []const u8, now_ns: u64) Error!Received {
        return connection_receive.receive(connection, input, now_ns);
    }

    /// Writes the response for `stream_id` into `output`: see `connection_send.zig`.
    pub fn write_response(
        connection: *Connection,
        output: []u8,
        stream_id: u32,
        status: u16,
        fields: []const hpack.Field,
        end_stream: bool,
    ) SendError!usize {
        return connection_send.write_response(connection, output, stream_id, status, fields, end_stream);
    }

    /// Writes as much of `payload` as the windows and the room allow: see `connection_send.zig`.
    /// Opens a stream and writes `request` on it as HEADERS and the CONTINUATION frames its field
    /// section needs (RFC 9113 §8.1, §8.3.1). A client's call.
    /// Attaches the TLS provider h2 runs over, after checking everything RFC 9113 §3.2 and §9.2
    /// require of the connection (decision 44).
    pub fn attach_tls(connection: *Connection, provider: tls.Provider) connection_tls.AttachError!void {
        return connection_tls.attach(connection, provider);
    }

    pub fn write_request(
        connection: *Connection,
        output: []u8,
        request: connection_request.Request,
        fields: []const hpack.Field,
        end_stream: bool,
    ) connection_request.Error!connection_request.Sent {
        return connection_request.write_request(connection, output, request, fields, end_stream);
    }

    pub fn write_data(
        connection: *Connection,
        output: []u8,
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
    ) SendError!connection_send.DataWritten {
        return connection_send.write_data(connection, output, stream_id, payload, end_stream);
    }

    /// Queues a RST_STREAM for `stream_id` (RFC 9113 §6.4): see `connection_send.zig`.
    pub fn reset_stream(connection: *Connection, stream_id: u32, error_code: u32) SendError!void {
        return connection_send.reset(connection, stream_id, error_code);
    }

    /// Queues the GOAWAY of a graceful shutdown (RFC 9113 §6.8): see `connection_send.zig`.
    pub fn shutdown(connection: *Connection, error_code: u32) void {
        connection_send.shutdown(connection, error_code);
    }

    /// Writes the preface colibri owes and the frames it has queued into `output`, and returns the
    /// octets written. Frames that do not fit stay queued for the next call.
    pub fn write_pending(connection: *Connection, output: []u8, now_ns: u64) usize {
        var writer = Writer.init(output);
        connection.write_preface(&writer, now_ns);
        const preface_len = writer.written().len;
        return preface_len + connection.replies.write(output[preface_len..]);
    }

    /// Whether anything is waiting to be written.
    pub fn has_pending(connection: *const Connection) bool {
        return !connection.preface_done() or !connection.replies.is_empty();
    }

    /// Whether colibri's SETTINGS_ENABLE_PUSH of 0 has been acknowledged, after which RFC 9113
    /// §6.5.2 makes a PUSH_PROMISE a connection error. a client sends the value in its preface and never changes it, so the acknowledgment is the only thing to wait for (decision 17); a server omits the setting (§6.5.2) and never reaches this call, because `on_push_promise` refuses a PUSH_PROMISE on its role first.
    pub fn push_refused(connection: *const Connection) bool {
        return connection.settings_written and connection.pending.len() == 0;
    }

    /// Whether the peer broke the protocol and the connection is closing (RFC 9113 §5.4.1).
    pub fn has_failed(connection: *const Connection) bool {
        return connection.failure != null;
    }

    /// The field section of the latest `request`, `response` or `trailers` event, valid until the
    /// next call to `receive`.
    pub fn field_section(connection: *const Connection) *const http.FieldSection {
        return &connection.block.section;
    }

    /// Ends the connection with `code`: queues the GOAWAY of RFC 9113 §6.8, drops a field block in
    /// progress, and gives `receive` its error. The first failure stands.
    pub fn fail(connection: *Connection, code: u32) Error {
        if (connection.failure == null) {
            connection.failure = code;
            const last_stream_id = connection.streams.last_peer_stream_id();
            connection.streams.record_goaway_sent(last_stream_id);
            connection.replies.set_goaway(.{ .last_stream_id = last_stream_id, .error_code = code });
            if (connection.block.is_in_progress()) connection.block.abandon();
        }
        assert(connection.has_failed());
        // RFC 9113 §5.4.1: a connection error ends the connection, after the GOAWAY says why.
        return error.ConnectionFailed;
    }

    /// Whether the preface colibri owes has been written: the client's 24 octets and the SETTINGS
    /// frame of RFC 9113 §3.4.
    fn preface_done(connection: *const Connection) bool {
        return connection.settings_written and (connection.role == .server or connection.preface_written);
    }

    /// Writes the preface: the client's 24 octets, then colibri's SETTINGS, each once and whole.
    fn write_preface(connection: *Connection, writer: *Writer, now_ns: u64) void {
        if (connection.role == .client and !connection.preface_written) {
            // RFC 9113 §3.4: a client starts the connection with these 24 octets.
            writer.write_bytes(constants.client_preface) catch return;
            connection.preface_written = true;
        }
        if (connection.settings_written) return;
        var buffer: [constants.settings_count]settings.Setting = undefined;
        const entries = settings.entries(connection.local, connection.role, &buffer);
        var pairs: [constants.settings_count]frame.Setting = undefined;
        for (entries, 0..) |entry, index| pairs[index] = .{ .id = entry.id, .value = entry.value };
        // RFC 9113 §3.4: the preface ends with a SETTINGS frame, which may be empty.
        frame.write_settings(writer, pairs[0..entries.len]) catch return;
        connection.settings_written = true;
        // RFC 9113 §6.5.3: the values are in force once the peer acknowledges them.
        connection.pending.push(connection.local, now_ns) catch unreachable;
    }
};

const testing = std.testing;

/// The connection the tests run on, placed outside any stack frame. Test-only, and the other
/// files of this directory run their tests on it too.
pub var test_connection: Connection = undefined;

/// Where the tests write frames. Test-only.
pub var test_output: [constants.frame_header_len + constants.frame_size_max]u8 = @splat(0);

/// The encoder the tests build the peer's field blocks with, which is the peer's and not
/// colibri's. Test-only.
pub var test_encoder: hpack.Encoder = undefined;

/// Where the tests build the frames they feed: one header and the largest payload. Test-only.
pub var test_input: [constants.frame_header_len + constants.frame_size_max]u8 = @splat(0);

/// A SETTINGS frame with no settings in it, which RFC 9113 §3.4 lets an endpoint send. Test-only.
pub const empty_settings = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// Writes one frame into `buffer` and returns it. Test-only.
pub fn frame_bytes(buffer: []u8, frame_type: u8, flags: u8, stream_id: u32, payload: []const u8) ![]const u8 {
    var writer = Writer.init(buffer);
    try frame.write_header(&writer, .{
        .length = @intCast(payload.len),
        .type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });
    try writer.write_bytes(payload);
    return writer.written();
}

/// Encodes the field section of a GET request for `path` into `buffer`, as a peer would. Test-only.
pub fn request_block(buffer: []u8, path: []const u8) ![]const u8 {
    test_encoder.init(constants.header_table_size_initial, .never);
    var writer = Writer.init(buffer);
    try test_encoder.begin_block(&writer);
    try test_encoder.write_field(&writer, ":method", "GET", .without_indexing);
    try test_encoder.write_field(&writer, ":scheme", "http", .without_indexing);
    try test_encoder.write_field(&writer, ":path", path, .without_indexing);
    try test_encoder.write_field(&writer, ":authority", "example.com", .without_indexing);
    test_encoder.commit_block();
    return writer.written();
}

/// Feeds `input` whole and requires the connection to consume all of it. Test-only.
pub fn feed(input: []const u8) !?Event {
    const received = try test_connection.receive(input, 0);
    try testing.expectEqual(input.len, received.consumed);
    return received.event;
}

/// Starts a server that has written its preface and read the client's, with nothing else read.
/// Test-only.
pub fn start_server() !void {
    test_connection.init(.server);
    _ = test_connection.write_pending(&test_output, 0);
    try testing.expectEqual(null, try feed(constants.client_preface));
    try testing.expectEqual(Event.settings_applied, (try feed(empty_settings)).?);
    // The acknowledgment of that SETTINGS frame is written, so the queues start empty.
    _ = test_connection.write_pending(&test_output, 0);
    try testing.expect(!test_connection.has_pending());
}

/// Starts a client that has written its preface and read the server's, with nothing else read.
/// Test-only.
pub fn start_client() !void {
    test_connection.init(.client);
    _ = test_connection.write_pending(&test_output, 0);
    try testing.expectEqual(Event.settings_applied, (try feed(empty_settings)).?);
    _ = test_connection.write_pending(&test_output, 0);
    try testing.expect(!test_connection.has_pending());
}

/// Encodes the field section of a response carrying `status`, as a peer would. Test-only.
pub fn response_block(buffer: []u8, status: []const u8) ![]const u8 {
    test_encoder.init(constants.header_table_size_initial, .never);
    var writer = Writer.init(buffer);
    try test_encoder.begin_block(&writer);
    try test_encoder.write_field(&writer, ":status", status, .without_indexing);
    test_encoder.commit_block();
    return writer.written();
}

/// Feeds a HEADERS frame carrying a response with `status` on `stream_id`. Test-only.
pub fn feed_response(stream_id: u32, status: []const u8, end_stream: bool) !?Event {
    var block: [constants.frame_size_max]u8 = undefined;
    const fragment = try response_block(&block, status);
    const flags = constants.flag_end_headers | @as(u8, if (end_stream) constants.flag_end_stream else 0);
    const bytes = try frame_bytes(&test_input, constants.frame_type_headers, flags, stream_id, fragment);
    return feed(bytes);
}

/// Feeds a HEADERS frame carrying a GET request for `path` on `stream_id`. Test-only.
pub fn feed_request(stream_id: u32, path: []const u8, end_stream: bool) !?Event {
    var block: [constants.frame_size_max]u8 = undefined;
    const fragment = try request_block(&block, path);
    const flags = constants.flag_end_headers | @as(u8, if (end_stream) constants.flag_end_stream else 0);
    const bytes = try frame_bytes(&test_input, constants.frame_type_headers, flags, stream_id, fragment);
    return feed(bytes);
}

/// The frames the connection has queued, written out. Test-only.
pub fn write_queued() []const u8 {
    const queued_len = test_connection.write_pending(&test_output, 0);
    return test_output[0..queued_len];
}

test "a server writes its SETTINGS and no preface, and a client writes the 24 octets first" {
    test_connection.init(.server);
    try testing.expect(test_connection.has_pending());
    const server_len = test_connection.write_pending(&test_output, 0);
    // The server's SETTINGS omits ENABLE_PUSH, so it carries five of the six settings.
    try testing.expectEqual(constants.frame_header_len + 5 * constants.setting_len, server_len);
    try testing.expectEqual(constants.frame_type_settings, test_output[3]);
    try testing.expect(!test_connection.has_pending());
    try testing.expectEqual(1, test_connection.pending.len());
    test_connection.init(.client);
    const client_len = test_connection.write_pending(&test_output, 0);
    try testing.expectEqualStrings(constants.client_preface, test_output[0..constants.client_preface_len]);
    try testing.expectEqual(constants.client_preface_len + constants.frame_header_len + 6 * constants.setting_len, client_len);
    try testing.expect(!test_connection.has_pending());
}

test "a buffer too short for the preface writes nothing and keeps it pending" {
    test_connection.init(.client);
    try testing.expectEqual(0, test_connection.write_pending(test_output[0 .. constants.client_preface_len - 1], 0));
    try testing.expect(test_connection.has_pending());
    try testing.expectEqual(0, test_connection.pending.len());
    // The 24 octets fit, the SETTINGS frame does not.
    try testing.expectEqual(constants.client_preface_len, test_connection.write_pending(test_output[0..constants.client_preface_len], 0));
    try testing.expect(test_connection.has_pending());
    const rest = test_connection.write_pending(&test_output, 0);
    try testing.expectEqual(constants.frame_header_len + 6 * constants.setting_len, rest);
    try testing.expect(!test_connection.has_pending());
}

test "fail queues one GOAWAY, records it against the streams and stands on the first code" {
    test_connection.init(.server);
    _ = test_connection.write_pending(&test_output, 0);
    try testing.expectEqual(error.ConnectionFailed, test_connection.fail(constants.error_protocol_error));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
    try testing.expectEqual(error.ConnectionFailed, test_connection.fail(constants.error_internal_error));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
    const written = test_connection.write_pending(&test_output, 0);
    const expected = "\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
    try testing.expectEqualSlices(u8, expected, test_output[0..written]);
    try testing.expect(!test_connection.has_pending());
}
