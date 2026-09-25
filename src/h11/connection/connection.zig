//! One h11 connection (design §8 step 15b): the caller's octets in, at most one event per call
//! out, and the heads and bodies the caller sends written into the caller's buffer (design §4.1).
//!
//! `receive` consumes the octets of at most one event: a head, a run of body data, or the end of
//! a body. A count of 0 with no event means the connection needs more octets, or, at a server,
//! that the current request's final response must be written before the next request is read
//! (decision 92). The caller loops over `receive` until it returns 0 with no event.
//!
//! A server reads a request, the application answers with `write_response`, `write_body` and
//! `write_end`, and the connection then reads the next request or, when either side asked for it,
//! closes (RFC 9112 §9.3, §9.6). A malformed request ends the connection: `receive` returns
//! `error.ConnectionFailed`, `failure` names why, and the error response colibri owes is written
//! by `write_pending` (decision 92).
//!
//! A client writes requests with `write_request`, keeps them in order, and gives each response to
//! the oldest one (RFC 9112 §9.2). It pipelines as decision 88 rules: never after a request whose
//! method is not idempotent until that request has its final response, and not at all on a
//! connection opened to retry until the first response arrives.
//!
//! Over TLS, the caller attaches the provider once the handshake completes (`attach_tls`), and
//! passes every record through `connection_tls.zig`'s `decrypt` and `encrypt`.
//!
//! The caller owns the struct, which holds the head's and the trailers' field sections, and
//! colibri allocates nothing (decision 35).
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const tls = @import("tls");
const constants = @import("../constants.zig");
const message = @import("../message/message.zig");
const connection_body = @import("connection_body.zig");
const connection_server = @import("connection_server.zig");
const connection_client = @import("connection_client.zig");
const connection_tls = @import("connection_tls.zig");

pub const Role = enum { server, client };

/// A request head a server read. Its field lines are in `Connection.section` until the next call.
pub const Request = struct {
    line: message.RequestLine,
    form: message.Form,
    body: message.Body,
};

/// A response head a client read. Its field lines are in `Connection.section` until the next call.
pub const Response = struct {
    line: message.StatusLine,
    body: message.Body,
};

pub const Event = union(enum) {
    /// A request head, at a server.
    request: Request,
    /// An interim response (1xx) to the oldest outstanding request, at a client (RFC 9112 §9.2).
    interim: message.StatusLine,
    /// A final response to the oldest outstanding request, at a client.
    response: Response,
    /// Body octets, a slice of the caller's input valid until the next call.
    data: []const u8,
    /// The body ended. A chunked body's trailer fields are in `Connection.trailers`.
    end,
    /// Octets of a tunnel after a 2xx to CONNECT (RFC 9112 §6.3 rule 2), a slice of the input.
    tunnel: []const u8,
};

pub const Received = struct {
    consumed: usize,
    event: ?Event,
};

/// The connection failed: the peer sent what h11 refuses. `failure` names why, a server owes the
/// error response `write_pending` writes, and the caller closes the transport after it.
pub const Error = error{ConnectionFailed};

pub const SendError = message.WriteError || connection_body.WriteError || error{
    /// The connection has failed or closed, or the last request carried `Connection: close`.
    ConnectionClosed,
    /// A server has no request to answer, or has already answered it.
    NoRequest,
    /// A body is being written, and the next head follows it (RFC 9112 §9.3.2).
    BodyInProgress,
    /// No body is being written.
    NoBody,
    /// `pipeline_depth_max` requests are outstanding.
    PipelineFull,
    /// Decision 88 forbids pipelining this request now.
    PipelineBlocked,
    /// 101 Switching Protocols, which h11 does not implement.
    UpgradeUnsupported,
    /// More field lines than `field_count_max`, with the one colibri adds.
    TooManyFields,
};

/// Where the reading of the connection stands.
pub const Phase = enum {
    /// Before a head.
    head,
    /// Inside a body.
    body,
    /// A server that read a whole request and has not written its final response.
    waiting,
    /// A tunnel: every octet is the application's.
    tunnel,
    /// Nothing more is read or written.
    closed,
};

/// What a request asked, which decides what its response's body can be (RFC 9112 §6.3).
pub const Outstanding = struct {
    asked: message.Asked,
    /// RFC 9110 §9.2.2: a method whose repeat has the same effect as one request.
    idempotent: bool,
};

pub const Options = struct {
    /// A client connection opened to retry requests an earlier one left unanswered: it sends one
    /// request and waits for its response before pipelining (RFC 9112 §9.3.2).
    retrying: bool = false,
};

/// What the transport's close meant (RFC 9112 §8).
pub const Closed = struct {
    /// A body that runs until the close ended with it (RFC 9112 §6.3 rule 8).
    ended_body: bool,
    /// A message was cut short: its head or body had not all arrived (RFC 9112 §8).
    incomplete: bool,
    /// Requests a client sent that have no final response, in order from the oldest.
    unanswered: u32,
};

pub const Connection = struct {
    role: Role,
    phase: Phase,
    scanner: message.Scanner,
    reader: connection_body.Reader,
    writer: connection_body.Writer,
    /// The field lines of the last head read.
    section: http.FieldSection,
    /// The trailer fields of the last chunked body read.
    trailers: http.FieldSection,
    /// The body read last ended, and the `end` event is owed.
    end_owed: bool,
    /// The connection closes after the current exchange (RFC 9112 §9.3, §9.6).
    close_after: bool,
    /// Why the connection failed, once it has.
    failure: ?anyerror,
    /// The status of the error response a server owes until `write_pending` writes it.
    reply_status: ?u16,
    /// A server: what the current request asked, and whether its final response head is written
    /// and its body finished.
    asked: message.Asked,
    answered: bool,
    responded: bool,
    /// A client: the requests sent with no final response, oldest first, in a ring.
    outstanding: [constants.pipeline_depth_max]Outstanding,
    outstanding_first: u32,
    outstanding_len: u32,
    retrying: bool,
    /// A client sent `Connection: close`, and sends nothing more (RFC 9112 §9.6).
    close_sent: bool,
    /// The TLS provider the connection runs over, or null in cleartext.
    provider: ?tls.Provider,
    /// Records in a row that carried no application data. The peer chooses how many it sends, so
    /// the run is bounded (`core.constants.records_without_data_max`).
    records_without_data: u32,
    /// Whether a KeyUpdate may have left the provider owing its reply (RFC 9846 §4.7.3), which
    /// `connection_tls.encrypt` writes first.
    handshake_owed: bool,
    /// Whether the peer's `close_notify` arrived (RFC 9846 §6.1). Over TLS it alone ends a body
    /// that runs until the close (RFC 9112 §9.8).
    close_notify_received: bool,

    pub fn init(connection: *Connection, role: Role, options: Options) void {
        connection.role = role;
        connection.phase = .head;
        connection.scanner = .{};
        connection.reader = .{};
        connection.writer = .{};
        connection.section.init();
        connection.trailers.init();
        connection.end_owed = false;
        connection.close_after = false;
        connection.failure = null;
        connection.reply_status = null;
        connection.asked = .other;
        connection.answered = false;
        connection.responded = false;
        connection.outstanding_first = 0;
        connection.outstanding_len = 0;
        connection.retrying = options.retrying;
        connection.close_sent = false;
        connection.provider = null;
        connection.records_without_data = 0;
        connection.handshake_owed = false;
        connection.close_notify_received = false;
        assert(connection.phase == .head and connection.failure == null);
        assert(role == .client or !options.retrying);
    }

    /// Attaches the TLS provider h11 runs over, after checking the finished handshake
    /// (`connection_tls.zig`). Called once, before any octet of HTTP moves.
    pub fn attach_tls(connection: *Connection, provider: tls.Provider) connection_tls.AttachError!void {
        return connection_tls.attach(connection, provider);
    }

    /// Consumes the octets of at most one event from the start of `input`.
    pub fn receive(connection: *Connection, input: []const u8) Error!Received {
        if (connection.end_owed) {
            connection.end_owed = false;
            return .{ .consumed = 0, .event = .end };
        }
        return switch (connection.role) {
            .server => connection_server.receive(connection, input),
            .client => connection_client.receive(connection, input),
        };
    }

    /// Writes a request head (a client's call). See `connection_client.zig`.
    pub fn write_request(connection: *Connection, output: []u8, method: []const u8, target: []const u8, fields: []const http.field.Field) SendError!usize {
        assert(connection.role == .client);
        return connection_client.write_request(connection, output, method, target, fields);
    }

    /// Writes a response head for the current request (a server's call). See
    /// `connection_server.zig`.
    pub fn write_response(connection: *Connection, output: []u8, status: u16, reason: []const u8, fields: []const http.field.Field) SendError!usize {
        assert(connection.role == .server);
        return connection_server.write_response(connection, output, status, reason, fields);
    }

    /// Writes body octets, framed as the head the caller wrote declared.
    pub fn write_body(connection: *Connection, output: []u8, data: []const u8) SendError!usize {
        const closed = connection.phase == .closed and connection.role == .server;
        // RFC 9112 §9.6: a server that closes the connection sends nothing after its last response.
        if (closed) return error.ConnectionClosed;
        // RFC 9112 §6: a message has a body only where its head declared one.
        if (!connection.writer.open()) return error.NoBody;
        return connection_body.write(&connection.writer, output, data);
    }

    /// Ends the body the caller is writing, with `trailers` for a chunked one.
    pub fn write_end(connection: *Connection, output: []u8, trailers: []const http.field.Field) SendError!usize {
        // RFC 9112 §6: a message has a body only where its head declared one.
        if (!connection.writer.open()) return error.NoBody;
        const written = try connection_body.end(&connection.writer, output, trailers);
        if (connection.role == .server) connection_server.finish_response(connection);
        return written;
    }

    /// Whether colibri owes octets `write_pending` writes.
    pub fn has_pending(connection: *const Connection) bool {
        return connection.reply_status != null;
    }

    /// Writes the error response a server owes (decision 92). Returns the octets written.
    pub fn write_pending(connection: *Connection, output: []u8) message.WriteError!usize {
        const status = connection.reply_status orelse return 0;
        const written = try connection_server.write_error_response(output, status);
        connection.reply_status = null;
        return written;
    }

    /// Whether the caller should close the transport once `write_pending` has nothing left.
    pub fn should_close(connection: *const Connection) bool {
        return connection.phase == .closed and !connection.has_pending();
    }

    /// The transport closed: the peer closed it, or it failed.
    pub fn transport_closed(connection: *Connection) Closed {
        const close_delimited = connection.phase == .body and connection.reader.kind == .close_delimited;
        // RFC 9112 §9.8: over TLS, a response with neither chunked nor Content-Length is complete
        // only if a valid closure alert has been received.
        const secure_close = connection.provider == null or connection.close_notify_received;
        const ended = close_delimited and secure_close;
        const mid_message = !ended and (connection.phase == .body or connection.scanner.scanned > 0);
        const unanswered = if (ended) connection.outstanding_len - 1 else connection.outstanding_len;
        connection.phase = .closed;
        connection.reader = .{};
        return .{ .ended_body = ended, .incomplete = mid_message, .unanswered = if (connection.role == .client) unanswered else 0 };
    }

    /// Ends the connection on `failure`: nothing more is read, and a server owes `status` when it
    /// has not written a response to the current request.
    pub fn fail(connection: *Connection, failure: anyerror, status: ?u16) Error {
        connection.failure = failure;
        connection.phase = .closed;
        connection.writer = .{};
        if (connection.role == .server and !connection.answered) connection.reply_status = status;
        // RFC 9112 §2.2 and §9.6: a peer that breaks the message framing leaves no next message to
        // read, so the connection closes.
        return error.ConnectionFailed;
    }
};

/// Whether a Connection field line of `section` carries the "close" option (RFC 9110 §7.6.1).
pub fn section_asks_close(section: *const http.FieldSection) bool {
    for (0..section.len()) |index| {
        const line = section.get(@intCast(index));
        if (line_asks_close(line)) return true;
    }
    return false;
}

/// Whether a Connection field line in `fields` carries the "close" option (RFC 9110 §7.6.1).
pub fn fields_ask_close(fields: []const http.field.Field) bool {
    for (fields) |line| {
        if (line_asks_close(line)) return true;
    }
    return false;
}

/// Connection = #connection-option, and an option is a token compared case-insensitively
/// (RFC 9110 §7.6.1).
fn line_asks_close(line: http.field.Field) bool {
    if (!http.field.names_equal(line.name, "Connection")) return false;
    var options = std.mem.splitScalar(u8, line.value, ',');
    // Bounded: a value of n octets holds at most n + 1 members.
    for (0..line.value.len + 1) |_| {
        const option = options.next() orelse return false;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, option, " \t"), "close")) return true;
    }
    return false;
}

/// What a request's method asks of its response's body (RFC 9112 §6.3 rules 1 and 2).
pub fn asked_of(method: []const u8) message.Asked {
    return switch (http.method.standard(method) orelse return .other) {
        .head => .head,
        .connect => .connect,
        else => .other,
    };
}

/// RFC 9110 §9.2.2: GET, HEAD, OPTIONS, TRACE, PUT and DELETE are idempotent.
pub fn is_idempotent(method: []const u8) bool {
    return switch (http.method.standard(method) orelse return false) {
        .get, .head, .options, .trace, .put, .delete => true,
        .post, .connect => false,
    };
}
