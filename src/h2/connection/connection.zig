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
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const settings = @import("../settings.zig");
const window = @import("../window.zig");
const message = @import("../message/message.zig");
const streams_table = @import("../stream/streams.zig");
const field_block = @import("../field_block/field_block.zig");
const connection_receive = @import("connection_receive.zig");
const connection_send = @import("connection_send.zig");
const connection_request = @import("connection_request.zig");
const connection_tls = @import("connection_tls.zig");
const reply = @import("connection_reply.zig");
const connection_altsvc = @import("connection_altsvc.zig");

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
pub const ShortBy = connection_send.ShortBy;

/// The limit that ended a connection with ENHANCE_YOUR_CALM: a peer used a feature more than
/// colibri allows (RFC 9113 §10.5).
pub const Limit = enum {
    /// More CONTINUATION frames in one field block than `continuation_count_max` (§6.10).
    continuation_frames,
    /// More records in a row that carried no data than `records_without_data_max`.
    records_without_data,
    /// More streams refused with RST_STREAM in one period than `rst_stream_rate_max`.
    resets_sent,
    /// More streams the peer opened and reset in one period than `peer_reset_rate_max`: Rapid
    /// Reset, CVE-2023-44487.
    peer_resets,
};

/// Why a request the caller asked for did not go out (`connection_request.zig`).
pub const RequestError = connection_request.Error;

/// The pseudo-header fields of a request a client sends (`connection_request.zig`).
pub const Request_ = connection_request.Request;
pub const RequestIndexing = connection_request.Indexing;
pub const PseudoIndexing = connection_request.PseudoIndexing;

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

/// An ALTSVC frame the server sent, at a client (RFC 7838 §4): the Alt-Svc field value `value`
/// names alternatives for the origin of stream `stream_id`, or, on stream 0, for `origin`. Both
/// slices point into the input `receive` read.
pub const AltSvc = struct {
    stream_id: u32,
    origin: []const u8,
    value: []const u8,
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
    alt_svc: AltSvc,

    /// The stream whose peer side the event ended (RFC 9113 §8.1), or null: a request, a response
    /// or DATA that carried END_STREAM, and every trailer section, which always carries it. One
    /// call answers what three kinds of event say.
    pub fn ended_stream(event: Event) ?u32 {
        return switch (event) {
            .request => |request| if (request.end_stream) request.stream_id else null,
            .response => |response| if (response.end_stream) response.stream_id else null,
            .data => |data| if (data.end_stream) data.stream_id else null,
            .trailers => |trailers| trailers.stream_id,
            else => null,
        };
    }
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
    /// The limit that ended the connection, when `failure` is ENHANCE_YOUR_CALM for one (§10.5).
    failure_limit: ?Limit,
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
    provider: ?tls_provider.Provider,
    /// Records in a row that carried no application data, counted by `connection_tls.zig`. A
    /// peer chooses how many it sends, so the run is bounded (`records_without_data_max`).
    records_without_data: u32,
    /// Whether a KeyUpdate may have left the provider owing its reply (RFC 9846 §4.7.3), which
    /// `encrypt` asks `handshake_write` for before it seals. Without one it asks nothing, so the
    /// common record costs one crossing of the vtable.
    handshake_owed: bool,
    /// Whether the record layer failed: a record did not open or seal, or an error alert arrived
    /// (RFC 9846 §6). No record is read and no frame goes out after it, and `encrypt` writes only
    /// the alert the provider owes (`connection_tls.zig`).
    tls_failed: bool,
    /// RST_STREAM frames colibri has sent since `rst_stream_period_start_ns` (§10.5).
    rst_stream_sent: u32,
    /// The instant the current RST_STREAM rate period began.
    rst_stream_period_start_ns: u64,
    /// Streams the peer opened and then reset since `peer_reset_period_start_ns` (§10.5,
    /// decision 110).
    peer_resets: u32,
    /// The instant the current period of the peer's resets began.
    peer_reset_period_start_ns: u64,
    /// The shortest DATA frame colibri sends when a window, not the payload, decides its length,
    /// or 0 for none: below it the frame waits (§10.5, decision 110). A server sets it after
    /// `init`.
    data_frame_len_min: u32,

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
        connection.failure_limit = null;
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
        connection.handshake_owed = false;
        connection.tls_failed = false;
        connection.rst_stream_sent = 0;
        connection.rst_stream_period_start_ns = 0;
        connection.peer_resets = 0;
        connection.peer_reset_period_start_ns = 0;
        connection.data_frame_len_min = 0;
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
        connection.assert_preface_written();
        return connection_send.write_response(connection, output, stream_id, status, fields, end_stream);
    }

    /// Attaches the TLS provider h2 runs over, after checking everything RFC 9113 §3.2 and §9.2
    /// require of the connection (decision 44).
    pub fn attach_tls(connection: *Connection, provider: tls_provider.Provider) connection_tls.AttachError!void {
        return connection_tls.attach(connection, provider);
    }

    /// Opens a stream and writes `request` on it as HEADERS and the CONTINUATION frames its field
    /// section needs (RFC 9113 §8.1, §8.3.1). A client's call.
    pub fn write_request(
        connection: *Connection,
        output: []u8,
        request: connection_request.Request,
        fields: []const hpack.Field,
        indexing: []const connection_request.Indexing,
        end_stream: bool,
    ) connection_request.Error!connection_request.Sent {
        connection.assert_preface_written();
        return connection_request.write_request(connection, output, request, fields, indexing, end_stream);
    }

    /// Writes as much of `payload` as the windows and the room allow: see `connection_send.zig`.
    pub fn write_data(
        connection: *Connection,
        output: []u8,
        stream_id: u32,
        payload: []const u8,
        end_stream: bool,
    ) SendError!connection_send.DataWritten {
        connection.assert_preface_written();
        return connection_send.write_data(connection, output, stream_id, payload, end_stream);
    }

    /// Writes a trailer section on `stream_id`, which ends colibri's side of the stream (RFC 9113
    /// §8.1): see `connection_send.zig`.
    pub fn write_trailers(connection: *Connection, output: []u8, stream_id: u32, fields: []const hpack.Field) SendError!usize {
        connection.assert_preface_written();
        return connection_send.write_trailers(connection, output, stream_id, fields);
    }

    /// Writes an ALTSVC frame advertising `value` for the origin of `stream_id`'s request (RFC
    /// 7838 §4): see `connection_altsvc.zig`. A server's call.
    pub fn write_alt_svc(connection: *Connection, output: []u8, stream_id: u32, value: []const u8) SendError!usize {
        connection.assert_preface_written();
        return connection_altsvc.write_alt_svc(connection, output, stream_id, value);
    }

    /// RFC 9113 §3.4: the preface is the first thing an endpoint sends, and the server's SETTINGS
    /// "MUST be the first frame the server sends", so the caller has `write_pending` write it
    /// before it writes any frame of its own. A connection whose record layer failed writes
    /// nothing, so the call that follows fails without writing.
    fn assert_preface_written(connection: *const Connection) void {
        assert(connection.preface_done() or connection.tls_failed);
    }

    /// Lowers the streams the peer may have open at once to `max`, which colibri's SETTINGS
    /// advertise as SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 §6.5.2) and which it enforces from
    /// the first stream (§5.1.2). A server's call, before the preface is written.
    pub fn limit_peer_streams(connection: *Connection, max: u32) void {
        assert(connection.role == .server and !connection.settings_written);
        assert(max > 0 and max <= constants.concurrent_streams_max);
        connection.local.max_concurrent_streams = max;
        connection.streams.peer_active_max = max;
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
        // RFC 9846 §6: after the record layer failed, no frame goes out.
        if (connection.tls_failed) return 0;
        var writer = Writer.init(output);
        connection.write_preface(&writer, now_ns);
        const preface_len = writer.written().len;
        return preface_len + connection.replies.write(output[preface_len..]);
    }

    /// Whether anything is waiting to be written. Nothing is once the record layer failed.
    pub fn has_pending(connection: *const Connection) bool {
        if (connection.tls_failed) return false;
        return !connection.preface_done() or !connection.replies.is_empty();
    }

    /// Whether colibri's SETTINGS_ENABLE_PUSH of 0 has been acknowledged, after which RFC 9113
    /// §6.5.2 makes a PUSH_PROMISE a connection error. a client sends the value in its preface and never changes it, so the acknowledgment is the only thing to wait for (decision 17); a server omits the setting (§6.5.2) and never reaches this call, because `on_push_promise` refuses a PUSH_PROMISE on its role first.
    pub fn push_refused(connection: *const Connection) bool {
        return connection.settings_written and connection.pending.len() == 0;
    }

    /// Whether the peer broke the protocol and the connection is closing (RFC 9113 §5.4.1), or
    /// its record layer failed (RFC 9846 §6).
    pub fn has_failed(connection: *const Connection) bool {
        return connection.failure != null or connection.tls_failed;
    }

    /// The field section of the latest `request`, `response` or `trailers` event, valid until the
    /// next call to `receive`.
    pub fn field_section(connection: *const Connection) *const http.FieldSection {
        return &connection.block.section;
    }

    /// Ends the connection with ENHANCE_YOUR_CALM for `limit` (RFC 9113 §10.5), and notes which
    /// limit it was. The first failure stands.
    pub fn fail_limit(connection: *Connection, limit: Limit) Error {
        if (connection.failure == null) connection.failure_limit = limit;
        return connection.fail(constants.error_enhance_your_calm);
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

    /// The instant the peer's acknowledgment of colibri's oldest SETTINGS frame it has not
    /// acknowledged is overdue, or null (RFC 9113 §6.5.3). colibri reads no clock, so the caller
    /// ends the connection with SETTINGS_TIMEOUT once its instant has passed it.
    pub fn settings_deadline_ns(connection: *const Connection) ?u64 {
        return connection.pending.deadline_ns();
    }

    /// Whether the preface colibri owes has been written: the client's 24 octets and the SETTINGS
    /// frame of RFC 9113 §3.4.
    pub fn preface_done(connection: *const Connection) bool {
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

test {
    _ = @import("connection_test.zig");
}
