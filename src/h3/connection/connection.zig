//! One h3 connection over one QUIC connection (RFC 9114). Part of design §8 step 12.
//!
//! The caller owns both connections and every buffer (decision 35). It gives `quic` each datagram
//! as it always does, then calls `receive` until it returns null. Each call returns at most one
//! event, as h2's does (decision 39): a request or a response with its field section, content, a
//! trailer section, the end of a message, a stream the peer reset or colibri refused, the peer's
//! SETTINGS, or a GOAWAY.
//!
//! Who keeps which octets is decision 79:
//! - The control stream and QPACK's encoder and decoder streams are h3's. It keeps each in a
//!   `SendBuffer` until the peer acknowledges it (decision 78).
//! - A request stream's octets are the caller's. `write_request`, `write_response`,
//!   `write_trailers` and `write_data_header` write frames into the caller's buffer, and the caller
//!   keeps them with the content it sends and tells `quic` how far the stream reaches.
//! - `provider` wraps the caller's stream provider, so `quic` reads h3's three streams from h3 and
//!   every other stream from the caller.
//!
//! A frame read from the peer is copied out of `quic`'s receive pool and taken only once it is
//! used (decision 80). A field section blocked on the QPACK dynamic table stays in the pool.
//!
//! A peer that breaks a rule of the whole connection ends it: `receive` returns
//! `error.ConnectionFailed`, `failure` holds the code, and `quic` owes the peer a CONNECTION_CLOSE
//! carrying it (RFC 9114 §8). A rule broken on one stream refuses that stream only (§4.1.2).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const qpack = @import("qpack");
const quic = @import("quic");
const constants = @import("../constants.zig");
const frame = @import("../frame.zig");
const stream = @import("../stream.zig");
const message = @import("../message/message.zig");
const connection_local = @import("connection_local.zig");
const connection_peer = @import("connection_peer.zig");
const connection_request = @import("connection_request.zig");
const connection_send = @import("connection_send.zig");

const Writer = core.Writer;
const FieldSection = http.FieldSection;
const StreamProvider = quic.stream.StreamProvider;
const QuicConnection = quic.Connection;

pub const Role = stream.Role;

/// Writes the header of a DATA frame of `len` octets into `output` (RFC 9114 §7.2.1). The caller
/// writes the content after it.
pub fn write_data_header(len: u64, output: *Writer) SendError!void {
    return connection_send.write_data_header(len, output);
}

/// What a connection is built from. Every value is the caller's.
pub const Options = struct {
    role: Role,
    /// The settings colibri's QPACK decoder advertises (RFC 9204 §5), both zero by default, which
    /// keeps the peer's encoder to the static table.
    qpack: qpack.decoder.Settings = .{},
    /// When colibri's QPACK encoder Huffman codes a string (RFC 9204 §4.1.2).
    huffman: qpack.encoder.HuffmanUse = .when_shorter,
    /// The value RFC 9114 §7.2.4.1's reserved setting and §8.1's reserved error codes are drawn
    /// from. colibri reads no randomness (invariant 5), so the caller supplies it, and a seed
    /// replays (design §6.5).
    grease: u64 = 0,
};

/// Why `receive` stopped: the peer broke a rule of the whole connection, `failure` names the
/// code, and `quic` owes the peer a CONNECTION_CLOSE carrying it (RFC 9114 §8).
pub const Error = error{ConnectionFailed};

pub const SendError = connection_send.Error;

/// What the peer sent, one at a time.
pub const Event = union(enum) {
    /// The peer's SETTINGS frame arrived (RFC 9114 §7.2.4). `peer_settings` holds it.
    settings,
    /// A request's header section, at a server (RFC 9114 §4.1). `field_section` holds its lines
    /// until the next call.
    request: Request,
    /// A response's header section, at a client: an interim one, or the final one (§4.1).
    response: Response,
    /// Content (§4.1, §7.2.1), written to the front of the buffer `receive` was given.
    data: Data,
    /// A trailer section (§4.1). `field_section` holds its lines until the next call.
    trailers: u64,
    /// The peer ended the stream after a whole message (§4.1).
    end: u64,
    /// The peer reset the stream (RFC 9000 §19.4), which cancels its message (§4.1.1).
    reset: Ended,
    /// colibri found the message malformed or incomplete and refused the stream: it reset its
    /// side and asked the peer to stop sending (§4.1.1, §4.1.2).
    refused: Ended,
    /// The peer's GOAWAY: the stream or push ID from which nothing is processed (§5.2).
    goaway: u64,
};

pub const Request = struct {
    stream_id: u64,
    request: message.Request,
};

pub const Response = struct {
    stream_id: u64,
    response: message.Response,
};

pub const Data = struct {
    stream_id: u64,
    octets: []const u8,
};

pub const Ended = struct {
    stream_id: u64,
    error_code: u64,
};

pub const Connection = struct {
    options: Options,
    /// The peer's SETTINGS once they arrived. Until then every setting has its default (RFC 9114
    /// §7.2.4.2).
    peer_settings: ?frame.Settings,
    encoder: qpack.encoder.Encoder,
    decoder: qpack.decoder.Decoder,
    /// colibri's three streams and their octets (decision 79).
    local: connection_local.Local,
    /// The peer's unidirectional streams and its control stream's state.
    peer: connection_peer.Peer,
    /// The request streams and what each has read.
    requests: connection_request.Requests,
    /// The GOAWAY identifiers sent and received, each only ever lower than the last (§5.2).
    goaway_sent: ?u64,
    goaway_received: ?u64,
    /// The largest push ID a client allowed, at a server (§7.2.7). colibri never pushes.
    max_push_id: ?u64,
    /// The code the connection closed with, once it failed.
    failure: ?u64,
    /// How many errors the connection has sent in place of H3_NO_ERROR, which decides when one is
    /// a reserved code (§8.1).
    no_error_count: u64,
    /// The caller's stream provider, which `provider` wraps.
    caller_provider: StreamProvider,
    /// Where a frame is copied out of `quic` before it is read (decision 80), and where a field
    /// section is encoded before its frame header goes in front of it.
    scratch: [constants.scratch_len]u8,
    /// The strings a decoded field section's Huffman coded lines decode into.
    strings: [core.constants.field_section_size_max]u8,
    /// The last field section `receive` decoded.
    section: FieldSection,

    pub fn init(connection: *Connection, options: Options) void {
        connection.options = options;
        connection.peer_settings = null;
        connection.encoder.init(options.huffman);
        connection.decoder.init(options.qpack);
        connection.local.init();
        connection.peer.init();
        connection.requests.init();
        connection.goaway_sent = null;
        connection.goaway_received = null;
        connection.max_push_id = null;
        connection.failure = null;
        connection.no_error_count = 0;
        connection.caller_provider = StreamProvider.none();
        connection.section.init();
    }

    /// Opens colibri's control stream and QPACK streams and writes the SETTINGS frame (RFC 9114
    /// §6.2.1, §7.2.4.2, RFC 9204 §4.2). The caller calls it once, as soon as `quic` may open
    /// streams: §7.2.4.2 says settings "MUST be sent as soon as the transport is ready".
    pub fn start(connection: *Connection, transport: *QuicConnection) Error!void {
        return connection_local.start(connection, transport);
    }

    /// The stream provider to hand `quic`'s send path: h3's three streams come from h3, and every
    /// other stream from `caller` (decision 79).
    pub fn provider(connection: *Connection, caller: StreamProvider) StreamProvider {
        connection.caller_provider = caller;
        return connection_local.provider(connection);
    }

    /// Reads what the peer sent and returns at most one event, or null when nothing more can be
    /// read now. Content goes into the front of `body`. Before it returns null it writes the
    /// QPACK decoder instructions it owes.
    pub fn receive(connection: *Connection, transport: *QuicConnection, body: []u8) Error!?Event {
        // RFC 9000 §10.2: a connection that is closing reads nothing more from its peer.
        if (connection.failure != null) return error.ConnectionFailed;
        assert(body.len > 0);
        try connection_peer.accept(connection, transport);
        if (try connection_peer.step(connection, transport)) |event| return event;
        try connection_request.accept(connection, transport);
        if (try connection_request.step(connection, transport, body)) |event| return event;
        try connection_local.flush_decoder(connection, transport);
        return null;
    }

    /// The field section of the last `request`, `response` or `trailers` event.
    pub fn field_section(connection: *const Connection) *const FieldSection {
        return &connection.section;
    }

    /// Opens a request stream and writes a HEADERS frame carrying `section` into `output`, at a
    /// client (RFC 9114 §4.1). `indexing` gives each line's QPACK choice, or is empty. The caller
    /// keeps the octets as the stream's first, and returns the stream's ID to `quic`'s `supply`.
    pub fn write_request(
        connection: *Connection,
        transport: *QuicConnection,
        section: *const FieldSection,
        indexing: []const qpack.encoder.Indexing,
        output: *Writer,
    ) SendError!u64 {
        return connection_send.write_request(connection, transport, section, indexing, output);
    }

    /// Writes a HEADERS frame carrying a response on `stream_id` into `output`, at a server
    /// (RFC 9114 §4.1): an interim one, or the final one.
    pub fn write_response(
        connection: *Connection,
        transport: *QuicConnection,
        stream_id: u64,
        section: *const FieldSection,
        indexing: []const qpack.encoder.Indexing,
        output: *Writer,
    ) SendError!void {
        return connection_send.write_response(connection, transport, stream_id, section, indexing, output);
    }

    /// Writes a HEADERS frame carrying a trailer section on `stream_id` into `output` (§4.1).
    pub fn write_trailers(
        connection: *Connection,
        transport: *QuicConnection,
        stream_id: u64,
        section: *const FieldSection,
        output: *Writer,
    ) SendError!void {
        return connection_send.write_trailers(connection, transport, stream_id, section, output);
    }

    /// Cancels the message on `stream_id` (§4.1.1): resets colibri's side and asks the peer to
    /// stop sending, both with `error_code`.
    pub fn cancel(connection: *Connection, transport: *QuicConnection, stream_id: u64, error_code: u64) void {
        connection_request.cancel(connection, transport, stream_id, error_code);
    }

    /// Starts a graceful shutdown with a GOAWAY frame (§5.2). A server names the first request
    /// stream it has not taken, and refuses every later one; a client names push ID 0, having
    /// allowed none.
    pub fn shutdown(connection: *Connection, transport: *QuicConnection) SendError!void {
        return connection_local.write_goaway(connection, transport);
    }

    /// Ends the connection with `code` (RFC 9114 §8): `quic` owes the peer an application
    /// CONNECTION_CLOSE, and every later `receive` fails.
    pub fn fail(connection: *Connection, transport: *QuicConnection, code: u64) Error {
        if (connection.failure == null) connection.failure = code;
        quic.connection_close.owe(transport, .{ .layer = .application, .error_code = code, .frame_type = null, .reason = "" });
        // RFC 9114 §8: a connection error closes the connection, with `code` as its reason.
        return error.ConnectionFailed;
    }

    /// The code to send where RFC 9114 would have H3_NO_ERROR: every `grease_error_one_in`th time
    /// a reserved code instead (§8.1).
    pub fn no_error_code(connection: *Connection) u64 {
        connection.no_error_count += 1;
        if (connection.no_error_count % constants.grease_error_one_in != 0) return constants.error_no_error;
        const n = (connection.options.grease +% connection.no_error_count) % constants.grease_range;
        const code = constants.reserved_base + constants.reserved_step * n;
        assert(constants.is_reserved(code));
        return code;
    }

    /// The QUIC role that matches colibri's.
    pub fn initiator(connection: *const Connection) quic.stream.Initiator {
        return switch (connection.options.role) {
            .client => .client,
            .server => .server,
        };
    }
};

test {
    _ = connection_local;
    _ = connection_peer;
    _ = connection_request;
    _ = connection_send;
    _ = @import("connection_test.zig");
}
