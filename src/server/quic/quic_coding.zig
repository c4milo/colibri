//! Content codings on a server connection over QUIC (decision 101, design §8 step 17e). A coded
//! response's octets are its encoder's: h3 frames each run the encoder writes into the slot's ring
//! as DATA, and QUIC reads the run in place, as it reads a caller's octets, until the peer
//! acknowledges it and the ring frees it (the owner's ruling of 2026-09-28). The content ends once
//! the encoder has finished, which `go_on` continues as acknowledgments free the ring.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const coding_fields = @import("../coding/coding_fields.zig");
const coding_response = @import("../coding/coding_response.zig");
const quic_request = @import("quic_request.zig");
const quic_connection = @import("quic_connection.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");

const QuicConnection = quic_connection.QuicConnection;
const Request = quic_request.Request;
const SendError = quic_connection.SendError;

/// The head `response` goes out with: the caller's for an interim response or when the connection
/// codes nothing, and as decision 101 plans it for a final one.
pub fn plan_head(connection: *QuicConnection, record: *const Request, response: event.Response, into: *coding_fields.Rewritten) coding_fields.Error!coding_response.Head {
    const encoders = connection.config.encoders orelse return .{ .fields = response.fields, .slot = null };
    if (response.status < final_min) return .{ .fields = response.fields, .slot = null };
    return coding_response.plan_head(encoders, record.asked, response, into);
}

const final_min: u16 = 200;

/// Codes `content` into the ring and frames each run the encoder writes as DATA. Returns the
/// octets taken.
pub fn write_body(connection: *QuicConnection, record: *Request, content: event.Content) SendError!usize {
    const coded = &record.coded.?;
    // RFC 9110 §6.4.1: the content ended, and nothing follows it.
    if (coded.finishing) return error.SectionOutOfOrder;
    var consumed: usize = 0;
    // The room ends at the ring's end or at its oldest octet held, so two steps fill it.
    for (0..coding_response.steps_max) |_| {
        if (consumed == content.octets.len) break;
        consumed += step(connection, record, content.octets[consumed..]) orelse break;
    }
    if (content.end and consumed == content.octets.len) {
        coded.finishing = true;
        finish(connection, record);
    }
    try quic_connection_h3.supply(connection, record, ends(record));
    // RFC 9000 §3.1: the ring's octets stay until the peer acknowledges them, so a full ring, or a
    // response holding its most runs, takes nothing more until then.
    if (consumed == 0 and content.octets.len > 0) return error.Blocked;
    return consumed;
}

/// Ends a coded response's content before its trailer section, or returns `error.Blocked` while
/// the encoder's last octets wait for room.
pub fn end_before_trailers(connection: *QuicConnection, record: *Request) SendError!void {
    const coded = &record.coded.?;
    // RFC 9110 §6.5: a trailer section follows the content, and content that ended has none.
    if (coded.finishing and !coded.trailers) return error.SectionOutOfOrder;
    coded.finishing = true;
    coded.trailers = true;
    finish(connection, record);
    try quic_connection_h3.supply(connection, record, false);
    // RFC 9110 §6.5: the trailer section follows the content, so it waits for the encoder's last
    // octets: `receive`, then call again.
    if (!coded.finished) return error.Blocked;
}

/// Goes on with a coded response whose content ended, once acknowledgments freed octets of its
/// ring: codes its last octets, and ends the stream once the encoder has finished.
pub fn go_on(connection: *QuicConnection, record: *Request) void {
    const coded = if (record.coded) |*coded| coded else return;
    if (!coded.finishing or record.finished) return;
    const end_before = record.response.end;
    if (!coded.finished) finish(connection, record);
    if (record.response.end == end_before and !ends(record)) return;
    // RFC 9000 §3.5: a stream the peer stopped takes no more octets, and `settle` reports its
    // reset.
    quic_connection_h3.supply(connection, record, ends(record)) catch {};
}

/// Gives back the encoder of `record`'s coded response, which QUIC reads no more: the peer
/// acknowledged every octet, the stream was reset, or the connection stopped.
pub fn give_back(connection: *QuicConnection, record: *Request) void {
    const coded = record.coded orelse return;
    connection.config.encoders.?.give_back(coded.slot);
    record.coded = null;
    // No run may point into a ring another response takes next.
    record.response.init();
}

/// Gives back every encoder the connection's responses hold.
pub fn give_back_all(connection: *QuicConnection) void {
    if (connection.config.encoders == null) return;
    for (&connection.requests.records) |*record| {
        if (record.in_use) give_back(connection, record);
    }
}

/// Whether the response's end goes out now: the encoder has finished, and no trailer section
/// follows.
fn ends(record: *const Request) bool {
    const coded = record.coded.?;
    return coded.finished and !coded.trailers;
}

/// Ends the coding as far as the ring and the response's runs have room.
fn finish(connection: *QuicConnection, record: *Request) void {
    assert(record.coded.?.finishing);
    for (0..coding_response.steps_max) |_| {
        if (record.coded.?.finished) break;
        _ = step(connection, record, &.{}) orelse break;
    }
}

/// One step of the encoder into the ring's room, its output framed as DATA. Returns the octets of
/// `input` taken, or null when the ring or the response's runs have no room.
fn step(connection: *QuicConnection, record: *Request, input: []const u8) ?usize {
    const coded = &record.coded.?;
    const encoders = connection.config.encoders.?;
    const pieces = &record.response;
    // RFC 9000 §3.1: the octets stay until the peer acknowledges them, and a DATA frame takes two
    // runs: its header, which the response keeps, and the coded octets, which stay in the ring.
    if (pieces.runs_len + data_runs > pieces.runs.len) return null;
    // h3 writes a head only with room for its longest frame, which counts `field_line_overhead`
    // for each line, and a coded head has three lines at least: `:status`, Content-Encoding and
    // Vary. Each line takes far less, so the room left holds every DATA frame's header the runs
    // allow.
    assert(pieces.kept_room().len >= h3.constants.frame_header_len_max);
    if (coded.room_len(encoders) == 0) return null;
    const stepped = coded.step(encoders, input);
    if (stepped.written.len > 0) frame(connection, record, stepped.written);
    return stepped.consumed;
}

/// The runs one DATA frame takes.
const data_runs: usize = 2;

/// The lines every coded head carries: `:status`, Content-Encoding and Vary.
const coded_head_lines: usize = 3;

/// Octets of a DATA frame's header at most: its type, one octet, and its length's variable-length
/// integer (RFC 9114 §7.1, RFC 9000 §16).
const data_header_len_max: usize = 1 + h3.wire.constants.varint_len_max;

comptime {
    // What `step` asserts: after a coded head, the kept frames hold every DATA frame's header the
    // runs allow. h3 writes a head only with room for `field_line_overhead` more than each line's
    // name and value, and a line takes `line_representation_len_max` more at most.
    const head_room = coded_head_lines * (h3.core.constants.field_line_overhead - h3.constants.line_representation_len_max);
    const data_frames = (constants.quic_response_pieces_max - 1) / data_runs;
    assert(head_room >= (data_frames - 1) * data_header_len_max + h3.constants.frame_header_len_max);
}

/// Frames `octets`, the ring's newest, as one DATA frame of the response (RFC 9114 §7.2.1).
fn frame(connection: *QuicConnection, record: *Request, octets: []const u8) void {
    const pieces = &record.response;
    var writer = quic.core.Writer.init(pieces.kept_room());
    // `step` left room for the frame's header, the longest h3 writes.
    connection.h3.write_data_header(record.stream_id, octets.len, &writer, connection.last_ns) catch unreachable;
    pieces.add_kept(writer.written().len);
    pieces.add_caller(octets);
}
