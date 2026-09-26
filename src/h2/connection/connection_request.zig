//! The request a client sends: the HEADERS frame that opens a stream, the pseudo-header fields
//! RFC 9113 §8.3.1 defines, and the CONTINUATION frames the field section needs (§4.3, §6.10).
//! This is the client's counterpart of `write_response` in `connection_send.zig`, and like every
//! send it writes into the caller's buffer and touches no socket (design §4.1).
//!
//! The order of the steps is the point of this file. Everything that can be refused without
//! changing the connection is checked first: the shape of the request (§8.3.1, §8.5) and every
//! field line the caller passes. Only then does `open_local` spend an identifier, which §5.1.1
//! forbids reusing, so a request refused for its own contents costs no stream.
//!
//! A client sends no trailer section here, and neither role sends one yet.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const hpack = @import("hpack");
const constants = @import("../constants.zig");
const stream = @import("../stream/stream.zig");
const streams_open = @import("../stream/streams_open.zig");
const connection = @import("connection.zig");
const connection_send = @import("connection_send.zig");

const Connection = connection.Connection;
const Writer = core.Writer;

/// Why a request did not go out. Every one leaves the connection and the caller's buffer as they
/// were, and none of them ends the connection.
pub const Error = error{
    /// The caller's buffer is too small for the frames, or the field section does not fit the
    /// connection's `send_block_len_max` buffer. A section past that buffer is refused whole
    /// (RFC 9113 §4.3).
    OutputTooSmall,
    /// `:method` is not a token (RFC 9110 §9, RFC 9113 §8.3.1).
    MethodInvalid,
    /// A request other than CONNECT carries no `:scheme` (RFC 9113 §8.3.1).
    SchemeMissing,
    /// A request other than CONNECT carries no `:path` (RFC 9113 §8.3.1).
    PathMissing,
    /// A `:scheme`, `:path` or `:authority` value that is empty where §8.3.1 requires one, or
    /// that is not a field value RFC 9110 §5.5 admits.
    PseudoHeaderInvalid,
    /// A CONNECT request carries `:scheme` or `:path` (RFC 9113 §8.5).
    ConnectWithSchemeOrPath,
    /// A CONNECT request carries no `:authority` (RFC 9113 §8.5).
    ConnectWithoutAuthority,
    /// A field line the caller passed is not one RFC 9110 §5.1 and §5.5 admit, is longer than
    /// colibri accepts, or is connection-specific, which RFC 9113 §8.2.2 forbids.
    FieldLineInvalid,
    /// The streams colibri has open have reached the peer's SETTINGS_MAX_CONCURRENT_STREAMS
    /// (RFC 9113 §5.1.2). One may open once one of them closes.
    PeerLimitReached,
    /// The peer has sent a GOAWAY, after which no stream may open (RFC 9113 §6.8).
    AfterGoawayReceived,
    /// colibri has opened its largest identifier (RFC 9113 §5.1.1).
    IdentifiersExhausted,
    /// Every slot holds an open or half-closed stream.
    Full,
};

/// How the encoder writes one field line of a request (RFC 7541 §6.2.2, §6.2.3), as h3's callers
/// choose for QPACK (decision 76). `never_indexed` also tells every intermediary not to index the
/// line (§7.1.3), for a value such as a credential. Neither choice inserts into the dynamic table:
/// an insert travels inside the block, and a request refused after its block was encoded would
/// leave the peer's table without it, where this file promises to change nothing.
pub const Indexing = enum { without_indexing, never_indexed };

/// How each pseudo-header field of a request is written.
pub const PseudoIndexing = struct {
    method: Indexing = .without_indexing,
    scheme: Indexing = .without_indexing,
    authority: Indexing = .without_indexing,
    path: Indexing = .without_indexing,
};

/// The pseudo-header fields of one request (RFC 9113 §8.3.1). `scheme` and `path` are null in a
/// CONNECT request and set in every other one (§8.5). `authority` is null when the caller has no
/// authority information to convey (§8.3.1).
pub const Request = struct {
    method: []const u8,
    scheme: ?[]const u8 = null,
    path: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    indexing: PseudoIndexing = .{},
};

/// What `write_request` did.
pub const Sent = struct {
    /// The identifier of the stream it opened (RFC 9113 §5.1.1).
    stream_id: u32,
    /// Octets written into the caller's buffer.
    written: usize,
};

/// Opens a stream and writes `request` on it as a HEADERS frame and the CONTINUATION frames its
/// field section needs (RFC 9113 §8.1, §8.3.1). A client's call. `indexing` is empty, which writes
/// every line of `fields` without indexing, or holds one choice for each of them.
pub fn write_request(
    target: *Connection,
    output: []u8,
    request: Request,
    fields: []const hpack.Field,
    indexing: []const Indexing,
    end_stream: bool,
) Error!Sent {
    // RFC 9113 §8.1: a client sends a request, and §5.1 gives a server no way to open a stream,
    // because decision 17 refuses push.
    assert(target.role == .client);
    assert(indexing.len == 0 or indexing.len == fields.len);
    try validate(request, fields);
    const record = streams_open.open_local(
        &target.streams,
        target.peer.max_concurrent_streams,
        target.peer.initial_window_size,
    ) catch |failure| return switch (failure) {
        error.PeerLimitReached => error.PeerLimitReached,
        error.AfterGoawayReceived => error.AfterGoawayReceived,
        error.IdentifiersExhausted => error.IdentifiersExhausted,
        error.Full => error.Full,
    };
    const stream_id: u32 = @intCast(record.id);
    // RFC 9113 §4.3: a field block is one sequence, so a section past the buffer is refused whole
    // rather than cut.
    const block = encode_request(target, request, fields, indexing) catch return error.OutputTooSmall;
    // RFC 9113 §6.2: the block opens in a HEADERS frame, whole or not at all.
    const written = connection_send.write_block(target, output, stream_id, block, end_stream) catch
        return error.OutputTooSmall;
    const verdict = stream.on_send(record.state, record.closed, .headers, end_stream, target.role, record.peer_initiated);
    target.streams.transition(record, verdict, .send, .headers, end_stream);
    return .{ .stream_id = stream_id, .written = written };
}

/// Refuses a request colibri would put on the wire malformed, before anything changes. RFC 9113
/// §8.3.1 and §8.5 give the pseudo-header rules and §8.2 the field-line rules.
fn validate(request: Request, fields: []const hpack.Field) Error!void {
    // RFC 9113 §8.3.1: `:method` carries the method, which RFC 9110 §9 makes a token.
    http.method.validate(request.method) catch return error.MethodInvalid;
    // RFC 9113 §8.5, RFC 9110 §9.1: the method is CONNECT when it is exactly that token.
    if (http.method.standard(request.method) == .connect) {
        try validate_connect(request);
    } else {
        try validate_target(request);
    }
    if (request.authority) |authority| try validate_pseudo_value(authority);
    for (fields) |line| try validate_field_line(line);
}

/// The pseudo-header rules of a CONNECT request (RFC 9113 §8.5).
fn validate_connect(request: Request) Error!void {
    // RFC 9113 §8.5: the `:scheme` and `:path` pseudo-header fields are omitted.
    if (request.scheme != null or request.path != null) return error.ConnectWithSchemeOrPath;
    // RFC 9113 §8.5: the `:authority` pseudo-header field contains the host and port to connect to.
    const authority = request.authority orelse return error.ConnectWithoutAuthority;
    // RFC 9113 §8.5: the value is the host and port, so an empty one names no target.
    if (authority.len == 0) return error.PseudoHeaderInvalid;
}

/// The pseudo-header rules of every request but CONNECT (RFC 9113 §8.3.1).
fn validate_target(request: Request) Error!void {
    // RFC 9113 §8.3.1: a request includes exactly one valid value for `:scheme`.
    const scheme = request.scheme orelse return error.SchemeMissing;
    // RFC 9113 §8.3.1: the value is taken from the target URI, so an empty one is not a value.
    if (scheme.len == 0) return error.PseudoHeaderInvalid;
    try validate_pseudo_value(scheme);
    // RFC 9113 §8.3.1: a request includes exactly one valid value for `:path`, and the value MUST
    // NOT be empty for an http or https URI.
    const path = request.path orelse return error.PathMissing;
    // RFC 9113 §8.3.1: the value MUST NOT be empty for an http or https URI.
    if (path.len == 0) return error.PseudoHeaderInvalid;
    try validate_pseudo_value(path);
}

/// A pseudo-header value colibri will encode: within the limits the encoder asserts, and a field
/// value RFC 9110 §5.5 admits.
fn validate_pseudo_value(value: []const u8) Error!void {
    // RFC 9113 §8.2.1: a field value carrying NUL, CR or LF, or surrounded by whitespace, is
    // malformed, and RFC 9110 §5.5 gives the octets a value admits.
    http.field.validate_value(value) catch return error.PseudoHeaderInvalid;
}

/// One field line the caller passed, under the rules a request carries them by.
fn validate_field_line(line: hpack.Field) Error!void {
    // RFC 9113 §8.2: field names are lowercase when an HTTP/2 message is constructed, and §8.2.1
    // makes an uppercase name malformed on receipt, so colibri sends none.
    if (!is_lowercase(line.name)) return error.FieldLineInvalid;
    // RFC 9113 §8.2.1: a field name that is not a token is malformed, so colibri sends none.
    http.field.validate_name(line.name) catch return error.FieldLineInvalid;
    // RFC 9113 §8.2.1: a value carrying NUL, CR or LF, or surrounded by whitespace, is malformed,
    // and RFC 9110 §5.5 gives the octets a value admits.
    http.field.validate_value(line.value) catch return error.FieldLineInvalid;
    // RFC 9113 §8.2.2: an endpoint MUST NOT generate a message containing connection-specific
    // field lines, and the TE it permits carries no value but "trailers".
    const kind = http.connection_specific.classify(line.name) orelse return;
    // RFC 9113 §8.2.2: TE is the one such name a request may carry.
    if (kind != .te) return error.FieldLineInvalid;
    // RFC 9113 §8.2.2: a TE field value MUST NOT contain any value other than "trailers".
    if (!http.connection_specific.te_is_trailers(line.value)) return error.FieldLineInvalid;
}

/// True when `name` holds no uppercase letter (RFC 9113 §8.2).
fn is_lowercase(name: []const u8) bool {
    for (name) |octet| {
        // RFC 9113 §8.2.1: a field name containing an octet in the range 0x41 to 0x5a is malformed.
        if (octet >= 'A' and octet <= 'Z') return false;
    }
    return true;
}

/// Encodes the request's field section into the connection's block buffer, the pseudo-header
/// fields first (RFC 9113 §8.3).
fn encode_request(target: *Connection, request: Request, fields: []const hpack.Field, indexing: []const Indexing) !([]const u8) {
    var writer = Writer.init(&target.send_block);
    // RFC 7541 §4.2: a block may open with the size updates the encoder owes.
    try target.encoder.begin_block(&writer);
    const pseudo = request.indexing;
    // RFC 9113 §8.3: all pseudo-header fields appear before the regular field lines.
    try write_line(target, &writer, ":method", request.method, pseudo.method);
    if (request.scheme) |scheme| try write_line(target, &writer, ":scheme", scheme, pseudo.scheme);
    // RFC 9113 §8.3.1: a client that generates a request uses `:authority` in place of the Host
    // field, and omits it when it has no authority information to convey.
    if (request.authority) |authority| try write_line(target, &writer, ":authority", authority, pseudo.authority);
    if (request.path) |path| try write_line(target, &writer, ":path", path, pseudo.path);
    for (fields, 0..) |line, index| {
        const how: Indexing = if (indexing.len == 0) .without_indexing else indexing[index];
        try write_line(target, &writer, line.name, line.value, how);
    }
    // RFC 7541 §4.2: the block is whole, so the capacity its updates named is the peer's now.
    target.encoder.commit_block();
    return writer.written();
}

/// One field line, never inserted into the dynamic table (`Indexing`).
fn write_line(target: *Connection, writer: *Writer, name: []const u8, value: []const u8, how: Indexing) !void {
    const representation: hpack.encoder.Indexing = switch (how) {
        .without_indexing => .without_indexing,
        .never_indexed => .never_indexed,
    };
    try target.encoder.write_field(writer, name, value, representation);
}

const testing = std.testing;
const test_connection = &connection.test_connection;
const test_output = &connection.test_output;
const start_client = connection.start_client;
const feed_response = connection.feed_response;

/// A request the tests send, with every pseudo-header field §8.3.1 requires. Test-only.
const test_request: Request = .{
    .method = "GET",
    .scheme = "https",
    .path = "/",
    .authority = "example.com",
};

test "§8.3.1: a client opens stream 1 and writes the request pseudo-header fields" {
    try start_client();
    const sent = try write_request(test_connection, test_output, test_request, &.{}, &.{}, true);
    try testing.expectEqual(1, sent.stream_id);
    try testing.expectEqual(constants.frame_type_headers, test_output[3]);
    try testing.expectEqual(constants.flag_end_stream | constants.flag_end_headers, test_output[4]);
    try testing.expect(sent.written > constants.frame_header_len);
    const record = test_connection.streams.lookup(1).live;
    // RFC 9113 §5.1: HEADERS with END_STREAM opens the stream and half-closes it at once.
    try testing.expectEqual(stream.State.half_closed_local, record.state);
    try testing.expectEqual(1, test_connection.streams.local_active);
}

test "§5.1.1: each request opens the next odd identifier, and a refused one opens none" {
    try start_client();
    const first = try write_request(test_connection, test_output, test_request, &.{}, &.{}, true);
    const second = try write_request(test_connection, test_output, test_request, &.{}, &.{}, true);
    try testing.expectEqual(1, first.stream_id);
    try testing.expectEqual(3, second.stream_id);
    // RFC 9113 §5.1.1: an identifier a refused request would have spent cannot be reused, so the
    // refusal happens before the stream opens.
    const bad: Request = .{ .method = "GET", .scheme = "https", .path = "" };
    try testing.expectEqual(error.PseudoHeaderInvalid, write_request(test_connection, test_output, bad, &.{}, &.{}, true));
    const third = try write_request(test_connection, test_output, test_request, &.{}, &.{}, true);
    try testing.expectEqual(5, third.stream_id);
}

test "§8.3.1: a request without :scheme or :path, or with an empty one, is refused" {
    try start_client();
    const no_scheme: Request = .{ .method = "GET", .path = "/" };
    try testing.expectEqual(error.SchemeMissing, write_request(test_connection, test_output, no_scheme, &.{}, &.{}, true));
    const no_path: Request = .{ .method = "GET", .scheme = "https" };
    try testing.expectEqual(error.PathMissing, write_request(test_connection, test_output, no_path, &.{}, &.{}, true));
    const empty_scheme: Request = .{ .method = "GET", .scheme = "", .path = "/" };
    try testing.expectEqual(error.PseudoHeaderInvalid, write_request(test_connection, test_output, empty_scheme, &.{}, &.{}, true));
    const bad_method: Request = .{ .method = "GE T", .scheme = "https", .path = "/" };
    try testing.expectEqual(error.MethodInvalid, write_request(test_connection, test_output, bad_method, &.{}, &.{}, true));
}

test "§8.5: a CONNECT request carries :authority alone" {
    try start_client();
    const connect: Request = .{ .method = "CONNECT", .authority = "example.com:443" };
    const sent = try write_request(test_connection, test_output, connect, &.{}, &.{}, false);
    try testing.expectEqual(1, sent.stream_id);
    const with_path: Request = .{ .method = "CONNECT", .authority = "example.com:443", .path = "/" };
    try testing.expectEqual(
        error.ConnectWithSchemeOrPath,
        write_request(test_connection, test_output, with_path, &.{}, &.{}, false),
    );
    const no_authority: Request = .{ .method = "CONNECT" };
    try testing.expectEqual(
        error.ConnectWithoutAuthority,
        write_request(test_connection, test_output, no_authority, &.{}, &.{}, false),
    );
}

test "§8.2 and §8.2.2: an uppercase name and a connection-specific line are refused" {
    try start_client();
    const upper = [_]hpack.Field{.{ .name = "Accept", .value = "*/*" }};
    try testing.expectEqual(
        error.FieldLineInvalid,
        write_request(test_connection, test_output, test_request, &upper, &.{}, true),
    );
    const keep_alive = [_]hpack.Field{.{ .name = "keep-alive", .value = "timeout=5" }};
    try testing.expectEqual(
        error.FieldLineInvalid,
        write_request(test_connection, test_output, test_request, &keep_alive, &.{}, true),
    );
    // RFC 9113 §8.2.2: TE is the one connection-specific name a request may carry, and only with
    // the value "trailers".
    const te_other = [_]hpack.Field{.{ .name = "te", .value = "gzip" }};
    try testing.expectEqual(
        error.FieldLineInvalid,
        write_request(test_connection, test_output, test_request, &te_other, &.{}, true),
    );
    const te_trailers = [_]hpack.Field{.{ .name = "te", .value = "trailers" }};
    _ = try write_request(test_connection, test_output, test_request, &te_trailers, &.{}, true);
}

test "§6.8: no stream opens after a GOAWAY the peer sent" {
    try start_client();
    const goaway = try connection.frame_bytes(&connection.test_input, constants.frame_type_goaway, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x00");
    _ = try connection.feed(goaway);
    try testing.expectEqual(
        error.AfterGoawayReceived,
        write_request(test_connection, test_output, test_request, &.{}, &.{}, true),
    );
}

test "§8.1: an interim response is not a trailer section, and the final response follows it" {
    try start_client();
    const sent = try write_request(test_connection, test_output, test_request, &.{}, &.{}, true);
    // RFC 9113 §8.1: any number of interim responses may precede the final one.
    const first = (try feed_response(sent.stream_id, "103", false)).?;
    try testing.expect(first.response.response.status.is_interim());
    const second = (try feed_response(sent.stream_id, "100", false)).?;
    try testing.expect(second.response.response.status.is_interim());
    // The section after the interim ones is the response, not a trailer section.
    const final = (try feed_response(sent.stream_id, "200", false)).?;
    try testing.expect(!final.response.response.status.is_interim());
    try testing.expectEqual(200, final.response.response.status.code);
}

test "§8.1: the trailer section is the one after the final response" {
    try start_client();
    const sent = try write_request(test_connection, test_output, test_request, &.{}, &.{}, true);
    _ = try feed_response(sent.stream_id, "103", false);
    _ = try feed_response(sent.stream_id, "200", false);
    var block: [constants.frame_size_max]u8 = undefined;
    connection.test_encoder.init(constants.header_table_size_initial, .never);
    var writer = Writer.init(&block);
    try connection.test_encoder.begin_block(&writer);
    try connection.test_encoder.write_field(&writer, "grpc-status", "0", .without_indexing);
    connection.test_encoder.commit_block();
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    const bytes = try connection.frame_bytes(&connection.test_input, constants.frame_type_headers, flags, sent.stream_id, writer.written());
    const event = (try connection.feed(bytes)).?;
    try testing.expectEqual(sent.stream_id, event.trailers.stream_id);
}

test "§8.1.1: an interim response does not set the content-length the DATA is compared with" {
    try start_client();
    const sent = try write_request(test_connection, test_output, test_request, &.{}, &.{}, true);
    // An interim response carrying content-length: its value belongs to no message, because the
    // message the final response begins is the one §8.1.1 compares.
    var block: [constants.frame_size_max]u8 = undefined;
    connection.test_encoder.init(constants.header_table_size_initial, .never);
    var writer = Writer.init(&block);
    try connection.test_encoder.begin_block(&writer);
    try connection.test_encoder.write_field(&writer, ":status", "103", .without_indexing);
    try connection.test_encoder.write_field(&writer, "content-length", "5", .without_indexing);
    connection.test_encoder.commit_block();
    const interim = try connection.frame_bytes(&connection.test_input, constants.frame_type_headers, constants.flag_end_headers, sent.stream_id, writer.written());
    _ = try connection.feed(interim);
    try testing.expectEqual(null, test_connection.streams.lookup(sent.stream_id).live.content_length);
    _ = try feed_response(sent.stream_id, "200", false);
    // Three octets end the stream, which a content-length of 5 left over from the interim
    // response would refuse.
    const data = try connection.frame_bytes(&connection.test_input, constants.frame_type_data, constants.flag_end_stream, sent.stream_id, "abc");
    const event = (try connection.feed(data)).?;
    try testing.expectEqual(3, event.data.payload.len);
}

test "§8.3: the block carries the pseudo-header fields, then the regular field lines" {
    try start_client();
    const lines = [_]hpack.Field{.{ .name = "accept", .value = "*/*" }};
    const sent = try write_request(test_connection, test_output, test_request, &lines, &.{}, true);
    hpack.decoder.test_decoder.init(constants.header_table_size_initial);
    // RFC 9113 §8.3: all pseudo-header fields appear before the regular field lines.
    try hpack.decoder.expect_lines(test_output[constants.frame_header_len..sent.written], &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "accept", .value = "*/*" },
    });
}

/// The lines of one HEADERS block the tests wrote, with whether each is never indexed. Test-only.
fn expect_never_indexed(block: []const u8, expected: []const bool) !void {
    hpack.decoder.test_decoder.init(constants.header_table_size_initial);
    var lines = hpack.decoder.test_decoder.block(block);
    for (expected) |never_indexed| {
        const line = (try lines.next()) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(never_indexed, line.never_indexed);
    }
    try testing.expectEqual(null, try lines.next());
}

test "RFC 7541 §6.2.3: the lines a caller marks go out never indexed, and no other" {
    try start_client();
    var marked = test_request;
    marked.path = "/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE";
    marked.indexing.path = .never_indexed;
    const lines = [_]hpack.Field{
        .{ .name = "accept", .value = "application/dns-message" },
        .{ .name = "authorization", .value = "secret" },
    };
    const sent = try write_request(test_connection, test_output, marked, &lines, &.{ .without_indexing, .never_indexed }, true);
    // RFC 7541 §7.1.3: an intermediary MUST NOT index a line sent in this representation, so the
    // DoH query in :path and the credential stay out of every table on the path.
    try expect_never_indexed(test_output[constants.frame_header_len..sent.written], &.{ false, false, false, true, false, true });
    // `Indexing`: no choice a request offers inserts, so the block leaves the tables as they were.
    try testing.expectEqual(0, test_connection.encoder.table.count);
}

test "RFC 7541 §6.2.2: a request the caller marks nothing on writes every line without indexing" {
    try start_client();
    const lines = [_]hpack.Field{.{ .name = "accept", .value = "*/*" }};
    const sent = try write_request(test_connection, test_output, test_request, &lines, &.{}, true);
    try expect_never_indexed(test_output[constants.frame_header_len..sent.written], &.{ false, false, false, false, false });
    try testing.expectEqual(0, test_connection.encoder.table.count);
}

test "§8.5: a CONNECT block carries :method and :authority alone" {
    try start_client();
    const connect: Request = .{ .method = "CONNECT", .authority = "example.com:443" };
    const sent = try write_request(test_connection, test_output, connect, &.{}, &.{}, false);
    hpack.decoder.test_decoder.init(constants.header_table_size_initial);
    // RFC 9113 §8.5: the :scheme and :path pseudo-header fields are omitted.
    try hpack.decoder.expect_lines(test_output[constants.frame_header_len..sent.written], &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    });
}

test "RFC 7541 §4.2: a table-size change is declared once and not repeated on the next request" {
    try start_client();
    // RFC 9113 §6.5.2: SETTINGS_HEADER_TABLE_SIZE is the limit the peer sets on colibri's encoder.
    const settings = try connection.frame_bytes(&connection.test_input, constants.frame_type_settings, 0, 0, "\x00\x01\x00\x00\x00\x64");
    _ = try connection.feed(settings);
    const first = try write_request(test_connection, test_output, test_request, &.{}, &.{}, true);
    // RFC 7541 §4.2: the block opens with the size update the change owes.
    try testing.expectEqual(0x3f, test_output[constants.frame_header_len]);
    try testing.expectEqual(0x45, test_output[constants.frame_header_len + 1]);
    _ = first;
    _ = try write_request(test_connection, test_output, test_request, &.{}, &.{}, true);
    // The first block reached the peer, so the second owes nothing.
    try testing.expect(test_output[constants.frame_header_len] != 0x3f);
}
