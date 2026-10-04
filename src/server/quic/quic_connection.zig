//! One connection of the server over QUIC (decision 103, design §8 step 17b): h3 (RFC 9114) over
//! `quic`, with the TLS handshake run through `tls.quic.Server`, reporting the same events and
//! answering with the same calls as the TCP `Connection`. `Endpoint` owns each one: it starts it
//! from a client's first Initial, passes it the datagrams its connection IDs name, and sends what
//! it writes (RFC 9000 §5.2).
//!
//! The caller loops over `receive`, as it does for a TCP connection, until it returns no event,
//! after each datagram the endpoint passed. It answers each request by its id, the stream's, with
//! `respond`, `write_body` and `write_trailers`. `write_body` copies nothing: QUIC reads the
//! caller's octets in place as often as it sends them, so they stay the caller's until the request
//! is `done`, once the peer has acknowledged every octet of the response (RFC 9000 §3.1), or
//! `cancelled` (decision 103). The frames around them are the connection's (decision 79).
//!
//! `QuicConnection`'s functions are the calls a program makes. What the endpoint calls is in
//! `quic_connection_internal.zig`, which the module's root does not export (design §8 step 17f).
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("../connection/connection.zig");
const quic_request = @import("quic_request.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");
const quic_deadline = @import("quic_deadline.zig");
const quic_body = @import("quic_body.zig");
const quic_sends = @import("quic_sends.zig");
const deadline = @import("../deadline.zig");
const coding_pool = @import("../coding/coding_pool.zig");
const http = @import("http");

pub const Id = event.Id;
pub const Received = event.Received;
pub const Field = connection_module.Field;
pub const Error = connection_module.Error;
pub const SendError = connection_module.SendError;
pub const PeerAddress = quic.PeerAddress;
/// Where a QUIC connection's received octets wait until h3 reads them (decision 61): the storage
/// of a `quic.stream.stream_incoming.Pool` the caller places.
pub const ReceiveStorage = quic.stream.stream_incoming.Storage;

/// What every QUIC connection of an endpoint borrows. The caller keeps it alive while any
/// connection holds it.
pub const Config = struct {
    /// The TLS configuration, whose ALPN list names "h3" (RFC 9114 §3.1).
    tls: *const tls.quic.ServerConfig,
    /// Decision 68: whether the caller reads each datagram's ECN codepoint and sets the one `send`
    /// names.
    ecn: bool = false,
    /// The idle timeout the server advertises (RFC 9000 §10.1), in milliseconds.
    idle_timeout_ms: u64 = constants.quic_idle_timeout_ms_default,
    /// The content codings the server applies to a response the caller marks `codable`, in its
    /// order of preference, and the pool their encoders come from, which connections may share
    /// (decision 101). Both or neither, and only `gzip` and `deflate`, which the server encodes.
    codings: []const http.content_coding.Coding = &.{},
    encoders: ?coding_pool.Encoders = null,
    /// The version the server switches a client to when the client lists it (RFC 9368 §2.3,
    /// decision 111), or null to keep every client in its original version.
    switch_to: ?quic.packet.header.Version = .v2,
    /// The limits each connection starts with (decision 110 as amended). Null turns a deadline
    /// off. An endpoint asserts they are limits `Deadlines.validate` and `validate_units` take,
    /// so a program that reads them from outside validates them first.
    deadlines: deadline.Deadlines = .{},
};

/// What a connection starts from, which the endpoint read off the client's first Initial or drew
/// from its caller's source (invariant 5).
pub const Start = struct {
    /// The version of the client's first Initial, which the connection runs (RFC 9368 §2).
    version: quic.packet.header.Version = .v1,
    /// The connection ID the server chose (RFC 9000 §7.2).
    local_id: [constants.quic_id_len]u8,
    /// The client's first Destination and Source Connection IDs (RFC 9000 §7.3), and a Retry's
    /// Source Connection ID when the Initial returned a Retry token (RFC 9000 §17.2.5.1).
    original_destination: []const u8,
    peer_source: []const u8,
    retry_source: ?[]const u8 = null,
    /// The value h3's reserved setting and error codes are drawn from (RFC 9114 §7.2.4.1, §8.1).
    grease: u64,
    /// Where the client sent from, which the connection's datagrams go to (decision 72).
    peer: PeerAddress,
};

pub const StartError = error{
    /// chapulin would not take the transport parameters or the Initial keys.
    TlsRefused,
    /// A limit of `Config.deadlines` is 0 or past `timeout_ns_max` (decision 110).
    DeadlineInvalid,
};

/// A datagram `send` wrote, the ECN codepoint for its IP header (decision 68), and the address it
/// goes to (decision 72).
pub const Sent = struct {
    octets: []const u8,
    ecn: quic.connection_send.Ecn,
    to: PeerAddress,
};

pub const QuicConnection = struct {
    config: *const Config,
    transport: quic.Connection,
    session: tls.quic.Server,
    send_scratch: quic.connection_send.DefaultScratch,
    scratch: quic.connection_datagram.Scratch,
    h3: h3.Connection,
    /// Where a response's field section is built, and where h3 copies a request's content.
    section: h3.http.FieldSection,
    body: [constants.quic_read_len]u8,
    requests: quic_request.Requests,
    owed: quic_request.Owed,
    /// Whether h3 runs: the handshake completed.
    started: bool,
    /// The caller asked the connection to end once its requests are answered.
    shutting_down: bool,
    /// Whether a request may be owed a 100 (Continue) (RFC 9110 §10.1.1), so the next `send`
    /// settles the requests before it writes a datagram (`quic_continue.zig`).
    continue_owed: bool,
    /// The connection failed or is ending, so it reads no request, and the next `receive` says
    /// so once.
    stopped: bool,
    failure_owed: bool,
    /// The caller's transport is gone, so nothing more is read or written.
    closed: bool,
    /// The latest instant a call passed, which the qlog events of the writes that take none carry
    /// (decision 102).
    last_ns: u64,
    /// The request streams the client opened and then cancelled in the period that began at
    /// `peer_reset_period_start_ns` (decision 110 as amended).
    peer_resets: u32,
    peer_reset_period_start_ns: u64,
    /// This connection's limits and where its deadlines stand (decision 110 as amended).
    deadlines: deadline.Deadlines,
    clock: quic_deadline.Clock,
    /// The request bodies the connection waits for, and the responses its peer has yet to take.
    bodies: quic_body.Bodies,
    sends: quic_sends.Sends,
    /// The caller's source, which the connection IDs it issues, their reset tokens and each
    /// PATH_CHALLENGE's data are drawn from (invariant 5).
    random: tls.Random,
    /// Whether the spare connection IDs went out (`issue_spare_ids`).
    spare_ids_issued: bool,

    /// Reports the next event: a request's head, its content, its trailer section, its
    /// cancellation, or that its response is done. `consumed` is always 0: the endpoint passed the
    /// datagrams already. Every slice points into storage the connection holds until the next call.
    /// A request that expects a 100 (Continue) gets one at the next `receive`, or before the next
    /// datagram the endpoint sends for the connection, unless the caller answers it first: with a
    /// final response, with its own 100, or with `cancel` (RFC 9110 §10.1.1).
    pub fn receive(connection: *QuicConnection, now_ns: u64) Error!Received {
        connection.last_ns = now_ns;
        quic_deadline.fire(connection, now_ns);
        const received = try connection.receive_event(now_ns);
        quic_deadline.observe(connection, now_ns);
        return received;
    }

    fn receive_event(connection: *QuicConnection, now_ns: u64) Error!Received {
        if (connection.failure_owed) {
            connection.failure_owed = false;
            // RFC 9000 §10.2: a connection that failed reads nothing more from its peer.
            return error.ConnectionFailed;
        }
        quic_connection_h3.settle(connection);
        if (connection.owed.take()) |owed| return .{ .consumed = 0, .event = owed };
        if (!connection.started or connection.stopped) return .{ .consumed = 0, .event = null };
        return .{ .consumed = 0, .event = try quic_connection_h3.read_event(connection, now_ns) };
    }

    /// Writes the head of the response to request `id`: an interim one (1xx) or the final one.
    /// With `end`, the final response carries no content.
    pub fn respond(connection: *QuicConnection, id: Id, response: event.Response) SendError!void {
        return quic_connection_h3.respond(connection, id, response);
    }

    /// Takes `content.octets` whole as the next content of the response to request `id`, and ends
    /// the content with `end`. Nothing is copied: the octets stay the caller's until the request
    /// is `done` or `cancelled`. A coded response instead takes as many octets as its encoder's
    /// ring has room for, and returns them, coded, to the caller at once (decision 101).
    /// `error.Blocked` says the response holds as many runs, or its ring as many octets, as it can
    /// until the peer acknowledges some: `receive`, then call again.
    pub fn write_body(connection: *QuicConnection, id: Id, content: event.Content) SendError!usize {
        return quic_connection_h3.write_body(connection, id, content);
    }

    /// Ends the response to request `id` with a trailer section (RFC 9110 §6.5).
    pub fn write_trailers(connection: *QuicConnection, id: Id, fields: []const Field) SendError!void {
        return quic_connection_h3.write_trailers(connection, id, fields);
    }

    /// Ends request `id` before its response is whole: its stream is reset with
    /// H3_REQUEST_CANCELLED (RFC 9114 §4.1.1), after which nothing reads the caller's octets, and
    /// nothing more is reported of it.
    pub fn cancel(connection: *QuicConnection, id: Id) void {
        quic_connection_h3.cancel(connection, id);
    }

    /// Ends the connection once the requests it holds are answered: a GOAWAY refuses every later
    /// request (RFC 9114 §5.2), and QUIC closes with H3_NO_ERROR once the last is done.
    pub fn shutdown(connection: *QuicConnection, now_ns: u64) void {
        connection.last_ns = now_ns;
        connection.shutting_down = true;
        quic_connection_h3.shut_down(connection, now_ns);
    }

    /// h3 once the handshake completed, or null.
    pub fn protocol(connection: *const QuicConnection) ?event.Protocol {
        return if (connection.started) .h3 else null;
    }

    /// The server_name the client sent (RFC 9846 §9.2), or null.
    pub fn server_name(connection: *const QuicConnection) ?[]const u8 {
        return connection.session.sni();
    }
};

test "design §8 step 17f: the QUIC connection's public functions are the calls a program makes" {
    const public_names = @import("core").public_names;
    try public_names.expect(QuicConnection, &.{
        "receive",  "respond",  "write_body",  "write_trailers", "cancel",
        "shutdown", "protocol", "server_name",
    });
}
