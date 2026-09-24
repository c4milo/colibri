//! The harness the h3 connection's tests share, and the tests of a whole exchange.
//!
//! Two endpoints, each a caller as design §4 has one: a QUIC connection, an h3 connection, and
//! the octets it keeps for each request stream (decision 79). No packet is protected: `transfer`
//! frames what one side's `quic` would send, one STREAM frame at a time with `quic`'s own writer,
//! and applies each frame to the other side's `quic`. The simulator check runs the packet path.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const qpack = @import("qpack");
const quic = @import("quic");
const constants = @import("../constants.zig");
const frame_write = @import("../frame_write.zig");
const connection_module = @import("connection.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const FieldSection = http.FieldSection;
const Connection = connection_module.Connection;
const Event = connection_module.Event;
const StreamId = quic.stream.StreamId;
const testing = std.testing;

/// Test-only sizes: the receive pool each side places, the streams a caller keeps octets for, and
/// the octets it keeps for each.
const pool_blocks: usize = 64;
const pool_capacity: usize = pool_blocks * quic.stream.stream_incoming.block_len;
const kept_max: usize = 8;
pub const kept_len: usize = 16384;
/// Enough credit and streams that no test reaches a limit it does not set. A window is at most
/// the pool (decision 61).
const window: u64 = pool_capacity;
const bidirectional_max: u64 = 16;
const test_now_ns: u64 = 1_000_000;
const id_len: usize = 4;
const id_octet: u8 = 0xc1;
const id_octets: [id_len]u8 = @splat(id_octet);

/// A field line as a test writes it: a name and a value. Test-only.
pub const Line = struct { []const u8, []const u8 };

/// The octets a caller keeps for one stream it sends on. Test-only.
pub const Kept = struct {
    id: ?u64 = null,
    octets: [kept_len]u8 = undefined,
    len: usize = 0,
};

/// One endpoint as a caller runs it. Test-only.
pub const Endpoint = struct {
    transport: quic.Connection,
    h3: Connection,
    pool: quic.stream.stream_incoming.Pool(pool_capacity),
    kept: [kept_max]Kept,
    body: [kept_len]u8,

    /// The octets kept for `id`, taking a free entry the first time.
    pub fn kept_for(endpoint: *Endpoint, id: u64) *Kept {
        for (&endpoint.kept) |*held| {
            if (held.id == id) return held;
        }
        for (&endpoint.kept) |*held| {
            if (held.id != null) continue;
            held.* = .{ .id = id };
            return held;
        }
        unreachable; // A test keeps fewer streams than `kept_max`.
    }

    /// A writer over the free part of `id`'s octets.
    pub fn writer_for(endpoint: *Endpoint, id: u64) Writer {
        const held = endpoint.kept_for(id);
        return Writer.init(held.octets[held.len..]);
    }

    /// Counts what `writer_for`'s writer wrote and tells `quic` how far the stream reaches.
    pub fn commit(endpoint: *Endpoint, id: u64, written: []const u8, fin: bool) !void {
        const held = endpoint.kept_for(id);
        held.len += written.len;
        try quic.connection_stream_send.supply(&endpoint.transport, .{ .value = id }, held.len, fin);
    }

    /// Writes raw `octets` on `id`, as a peer that breaks a rule would.
    pub fn send_raw(endpoint: *Endpoint, id: u64, octets: []const u8, fin: bool) !void {
        var writer = endpoint.writer_for(id);
        try writer.write_bytes(octets);
        try endpoint.commit(id, writer.written(), fin);
    }

    fn provider(endpoint: *Endpoint) quic.stream.StreamProvider {
        return endpoint.h3.provider(.{ .context = endpoint, .vtable = &kept_vtable });
    }
};

const kept_vtable: quic.stream.stream_provider.VTable = .{ .read = read_kept };

fn read_kept(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const endpoint: *Endpoint = @ptrCast(@alignCast(context));
    const held = endpoint.kept_for(stream_id);
    if (offset >= held.len) return 0;
    const len = @min(output.len, held.len - @as(usize, @intCast(offset)));
    @memcpy(output[0..len], held.octets[@intCast(offset)..][0..len]);
    return len;
}

pub var client: Endpoint = undefined;
pub var server: Endpoint = undefined;
var frame_octets: [quic.constants.datagram_len_min]u8 = undefined;
var packet_number: u64 = 0;

fn parameters() quic.transport_parameters.Parameters {
    var granted = quic.transport_parameters.Parameters.initial();
    granted.initial_max_data = window;
    granted.initial_max_stream_data_bidi_local = window;
    granted.initial_max_stream_data_bidi_remote = window;
    granted.initial_max_stream_data_uni = window;
    granted.initial_max_streams_bidi = bidirectional_max;
    granted.initial_max_streams_uni = constants.uni_streams_max;
    return granted;
}

fn open(endpoint: *Endpoint, role: connection_module.Role, options: connection_module.Options) void {
    endpoint.transport.init(.{
        .role = if (role == .client) .client else .server,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &id_octets, .original_destination = &id_octets },
        .receive = endpoint.pool.storage(),
    });
    endpoint.transport.apply_peer_parameters(parameters());
    endpoint.transport.handshake_complete = true;
    endpoint.h3.init(options);
    endpoint.kept = @splat(.{});
}

/// Two endpoints whose QUIC connections are past the handshake, with h3 not started.
pub fn pair_unstarted(client_options: connection_module.Options, server_options: connection_module.Options) void {
    open(&client, .client, client_options);
    open(&server, .server, server_options);
    packet_number = 0;
}

/// Two endpoints with h3 started on each, and the SETTINGS frames exchanged and read.
pub fn pair(client_options: connection_module.Options, server_options: connection_module.Options) !void {
    pair_unstarted(client_options, server_options);
    try client.h3.start(&client.transport);
    try server.h3.start(&server.transport);
    try exchange();
    try testing.expectEqual(Event.settings, (try next(&client)).?);
    try testing.expectEqual(Event.settings, (try next(&server)).?);
}

/// Moves every STREAM, RESET_STREAM and STOP_SENDING frame `from` owes to `to`.
pub fn transfer(from: *Endpoint, to: *Endpoint) !void {
    return transfer_frames(from, to, kept_max * kept_len);
}

/// Moves at most `count` STREAM frames `from` owes to `to`, in the order `quic` sends them, and
/// every RESET_STREAM and STOP_SENDING frame.
pub fn transfer_frames(from: *Endpoint, to: *Endpoint, count: usize) !void {
    const stream_provider = from.provider();
    // Bounded by `count`.
    for (0..count) |_| {
        const written = quic.connection_stream_send.write(&from.transport, stream_provider, &frame_octets);
        if (written.len == 0) break;
        try apply_all(to, frame_octets[0..written.len]);
        acknowledge(from, .{
            .number = next_packet(),
            .sent_at_ns = test_now_ns,
            .sent_len = @intCast(written.len),
            .ack_eliciting = true,
            .in_flight = true,
            .carries = if (written.fin) .stream_fin else .stream,
            .data_offset = written.offset,
            .data_len = written.data_len,
            .stream_id = written.stream_id,
        });
    }
    var writer = Writer.init(&frame_octets);
    const number = next_packet();
    if (quic.connection_stream_send.write_endings(&from.transport, .application, &writer, number)) {
        try apply_all(to, writer.written());
        acknowledge(from, .{ .number = number, .sent_at_ns = test_now_ns, .sent_len = @intCast(writer.written().len), .ack_eliciting = true, .in_flight = true });
    }
}

fn next_packet() u64 {
    packet_number += 1;
    return packet_number;
}

/// Acknowledges the packet `record` stands for at once, through the path an ACK frame takes, so
/// every framed octet is acknowledged as invariant 29 has it.
fn acknowledge(from: *Endpoint, record: quic.recovery_sent.Record) void {
    var completed: [kept_max]StreamId = undefined;
    _ = quic.connection_stream_recovery.on_packets_acknowledged(&from.transport, .application, &.{record}, &completed);
}

fn apply_all(to: *Endpoint, octets: []const u8) !void {
    var reader = Reader.init(octets);
    // Bounded by the octets, which each frame read shortens.
    while (reader.remaining_len() > 0) {
        try quic.connection_stream_frames.apply(&to.transport, try quic.frame.read(&reader));
    }
}

/// Moves what each side owes to the other.
pub fn exchange() !void {
    try transfer(&client, &server);
    try transfer(&server, &client);
}

/// The next event `endpoint` reads, or null.
pub fn next(endpoint: *Endpoint) !?Event {
    return endpoint.h3.receive(&endpoint.transport, &endpoint.body);
}

/// A section of `lines`, each a name and a value, in `section`.
pub fn section_of(section: *FieldSection, lines: []const Line) !*const FieldSection {
    section.init();
    for (lines) |line| try section.append(line[0], line[1]);
    return section;
}

pub var test_section: FieldSection = undefined;

/// Sends a request of `lines` from the client with `content`, and ends the stream. Returns its ID.
pub fn request(lines: []const Line, content: []const u8) !u64 {
    const section = try section_of(&test_section, lines);
    const next_id = StreamId.of(.client, .bidirectional, client.transport.streams.next_index[0]).value;
    var writer = client.writer_for(next_id);
    const id = try client.h3.write_request(&client.transport, section, &.{}, &writer);
    try testing.expectEqual(next_id, id);
    if (content.len > 0) {
        try connection_module.write_data_header(content.len, &writer);
        try writer.write_bytes(content);
    }
    try client.commit(id, writer.written(), true);
    return id;
}

/// Sends a response of `lines` on `id` from the server with `content`, and ends the stream.
pub fn respond(id: u64, lines: []const Line, content: []const u8) !void {
    const section = try section_of(&test_section, lines);
    var writer = server.writer_for(id);
    try server.h3.write_response(&server.transport, id, section, &.{}, &writer);
    if (content.len > 0) {
        try connection_module.write_data_header(content.len, &writer);
        try writer.write_bytes(content);
    }
    try server.commit(id, writer.written(), true);
}

pub const get_lines = [_]Line{
    .{ ":method", "GET" },
    .{ ":scheme", "https" },
    .{ ":authority", "example.com" },
    .{ ":path", "/index.html" },
};

pub const ok_lines = [_]Line{
    .{ ":status", "200" },
    .{ "content-type", "text/plain" },
};

test "§6.2.1, §7.2.4: each side opens its control stream with SETTINGS, and the other reads it" {
    try pair(.{ .role = .client, .grease = 5 }, .{ .role = .server });
    const settings = server.h3.peer_settings.?;
    // §7.2.4.1: colibri advertises the field section size it accepts, and the reserved setting it
    // also sent is ignored.
    try testing.expectEqual(core.constants.field_section_size_max, settings.max_field_section_size.?);
    try testing.expectEqual(null, settings.reserved);
    // RFC 9204 §5: a decoder left at the defaults advertises neither QPACK setting.
    try testing.expectEqual(null, settings.qpack_max_table_capacity);
    try testing.expectEqual(null, try next(&server));
}

test "§4.1: a GET and its response travel end to end, content included" {
    try pair(.{ .role = .client }, .{ .role = .server });
    const id = try request(&get_lines, "");
    try exchange();
    const got = (try next(&server)).?.request;
    try testing.expectEqual(id, got.stream_id);
    try testing.expectEqualStrings("GET", got.request.method);
    try testing.expectEqualStrings("/index.html", got.request.path.?);
    try testing.expectEqualStrings("example.com", server.h3.field_section().find(":authority").?.value);
    try testing.expectEqual(Event{ .end = id }, (try next(&server)).?);
    try testing.expectEqual(null, try next(&server));

    try respond(id, &ok_lines, "hello");
    try exchange();
    const response = (try next(&client)).?.response;
    try testing.expectEqual(200, response.response.status.code);
    const data = (try next(&client)).?.data;
    try testing.expectEqualStrings("hello", data.octets);
    try testing.expectEqual(Event{ .end = id }, (try next(&client)).?);
    try testing.expectEqual(null, try next(&client));
}

test "§4.1: a request's content and trailers arrive in order, and content-length is checked" {
    try pair(.{ .role = .client }, .{ .role = .server });
    const post = [_]Line{ .{ ":method", "POST" }, .{ ":scheme", "https" }, .{ ":path", "/upload" }, .{ ":authority", "a" }, .{ "content-length", "7" } };
    const section = try section_of(&test_section, &post);
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, section, &.{}, &writer);
    // The content in two DATA frames, then a trailer section.
    try connection_module.write_data_header(3, &writer);
    try writer.write_bytes("abc");
    try connection_module.write_data_header(4, &writer);
    try writer.write_bytes("defg");
    try client.h3.write_trailers(&client.transport, id, try section_of(&test_section, &.{.{ "x-checksum", "1" }}), &writer);
    try client.commit(id, writer.written(), true);
    try exchange();
    try testing.expectEqual(7, (try next(&server)).?.request.request.content_length.?);
    try testing.expectEqualStrings("abc", (try next(&server)).?.data.octets);
    try testing.expectEqualStrings("defg", (try next(&server)).?.data.octets);
    try testing.expectEqual(Event{ .trailers = id }, (try next(&server)).?);
    try testing.expectEqualStrings("1", server.h3.field_section().find("x-checksum").?.value);
    try testing.expectEqual(Event{ .end = id }, (try next(&server)).?);
}

test {
    _ = @import("connection_request_test.zig");
    _ = @import("connection_peer_test.zig");
    _ = @import("connection_qpack_test.zig");
}
