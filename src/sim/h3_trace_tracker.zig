//! What the h3 trace run (https://github.com/c4milo/colibri/issues/58) keeps across its steps so
//! it can compute the model's state: the units each side wrote on h3's own streams, and what each
//! request stream went through.
//!
//! h3 drops the octets of its own streams once the peer acknowledged them (decision 78), so the
//! tracker parses each stream's new octets after every step, before anything written in it can
//! have been sent, let alone acknowledged. It keeps each unit with the offset where it ends, and
//! `h3_trace_state.zig` compares that offset with how far QUIC framed or delivered the stream:
//! - the client's encoder stream: each insert (RFC 9204 §4.3);
//! - the server's control stream: SETTINGS and each GOAWAY (RFC 9114 §7.2.4, §7.2.6);
//! - the server's decoder stream: each instruction (RFC 9204 §4.4).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const wire = @import("wire");
const qpack = @import("qpack");
const h3 = @import("h3");
const h3_trace_endpoint = @import("h3_trace_endpoint.zig");

const Reader = quic.core.Reader;
const Writer = quic.core.Writer;
const Endpoint = h3_trace_endpoint.Endpoint;
const constants = sim.constants;

/// One frame of the server's control stream the model has.
pub const ControlFrame = struct {
    kind: enum { settings, goaway },
    /// A GOAWAY's request index: the stream ID over the ID step. 0 for SETTINGS.
    id: u64,
    end: u64,
};

/// One decoder instruction, with the request index its stream ID names.
pub const Instruction = struct {
    kind: enum { acknowledgment, cancellation, increment },
    stream: u64,
    count: u64,
    end: u64,
};

/// Units one stream may carry in a trace run: every request's instructions and a few more.
const units_max: usize = constants.h3_trace_units_max;

pub fn Log(comptime Unit: type) type {
    return struct {
        units: [units_max]Unit = undefined,
        len: usize = 0,
        /// The stream offset parsed up to: every octet below it is in `units`.
        parsed_end: u64 = 0,

        pub fn items(log: *const @This()) []const Unit {
            return log.units[0..log.len];
        }
    };
}

pub const Tracker = struct {
    inserts: Log(u64) = .{},
    control: Log(ControlFrame) = .{},
    decoder: Log(Instruction) = .{},
    /// Per request: the frames the client's QUIC framed at least once, whether the client reset
    /// its side, whether that reset arrived at the server, and the server's consumed frames.
    request_sent: [constants.h3_trace_requests_max]u64 = @splat(0),
    reset_sent: [constants.h3_trace_requests_max]bool = @splat(false),
    reset_arrived: [constants.h3_trace_requests_max]bool = @splat(false),
    consumed: [constants.h3_trace_requests_max]u64 = @splat(0),

    /// Parses what each side wrote in the step that just ended, and notes what its request
    /// streams went through. Called after the endpoints act and before they send.
    pub fn observe(tracker: *Tracker, client: *const Endpoint, server: *const Endpoint) void {
        const client_local = &client.h3.local;
        if (client_local.encoder_id != null) parse_encoder(&tracker.inserts, &client_local.encoder);
        const server_local = &server.h3.local;
        if (server_local.control_id != null) parse_control(&tracker.control, &server_local.control);
        if (server_local.decoder_id != null) parse_decoder(&tracker.decoder, &server_local.decoder);
        for (0..client.opened) |r| tracker.observe_request(client, r);
    }

    fn observe_request(tracker: *Tracker, client: *const Endpoint, r: usize) void {
        const id: quic.stream.StreamId = .{ .value = r * h3_trace_endpoint.request_stream_step };
        if (live(&client.transport.connection, id)) |stream| {
            tracker.request_sent[r] = @max(tracker.request_sent[r], frames_below(client, r, stream.outgoing.framed_end));
            const state = stream.sending.state;
            if (state == .reset_sent or state == .reset_recvd) tracker.reset_sent[r] = true;
        }
        if (client.outcome[r] == .cancelled) tracker.reset_sent[r] = true;
    }

    /// Notes the resets the step's datagrams delivered to the server, before its h3 reads them:
    /// on a stream h3 refused, reading one reports nothing, and QUIC then forgets the stream.
    pub fn observe_arrivals(tracker: *Tracker, server: *const Endpoint) void {
        for (0..server.plan.requests) |r| {
            const id: quic.stream.StreamId = .{ .value = r * h3_trace_endpoint.request_stream_step };
            const stream = live(&server.transport.connection, id) orelse continue;
            if (stream.receiving.state == .reset_recvd) tracker.reset_arrived[r] = true;
        }
    }
};

/// The stream `id` while its QUIC endpoint still holds it, or null once it was forgotten.
pub fn live(connection: *const quic.Connection, id: quic.stream.StreamId) ?*const quic.stream.Stream {
    const streams = @constCast(&connection.streams);
    return switch (streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => null,
    };
}

/// How many of request `r`'s frames end at or below `offset`: its HEADERS frame, then DATA
/// frames of one length each.
pub fn frames_below(client: *const Endpoint, r: usize, offset: u64) u64 {
    const headers_end = client.headers_end[r];
    if (offset < headers_end) return 0;
    const data_frames = (offset - headers_end) / data_frame_len();
    return 1 + @min(data_frames, client.plan.content);
}

/// The octets of one DATA frame the trace run writes: its header and `h3_trace_data_len` octets.
pub fn data_frame_len() u64 {
    var octets: [h3.constants.frame_header_len_max]u8 = undefined;
    var writer = Writer.init(&octets);
    h3.connection.write_data_header(constants.h3_trace_data_len, &writer) catch unreachable;
    return writer.written().len + constants.h3_trace_data_len;
}

/// The octets of `buffer` after what `parsed_end` already covers.
fn unparsed(buffer: anytype, parsed_end: u64) []const u8 {
    // Nothing unparsed was ever sent, so none of it was dropped.
    assert(parsed_end >= buffer.start_offset and parsed_end <= buffer.end_offset());
    return buffer.octets[@intCast(parsed_end - buffer.start_offset)..buffer.len];
}

/// Each stream opens with its type (RFC 9114 §6.2), which no unit is.
fn skip_stream_type(reader: *Reader, parsed_end: u64) void {
    if (parsed_end == 0) _ = wire.varint.decode(reader) catch unreachable;
}

fn parse_encoder(log: *Log(u64), buffer: anytype) void {
    var reader = Reader.init(unparsed(buffer, log.parsed_end));
    const base = log.parsed_end;
    skip_stream_type(&reader, base);
    var strings: [qpack.constants.encoder_instruction_len_max]u8 = undefined;
    // Bounded: a stream carries no more units than the log holds.
    for (0..units_max) |_| {
        if (reader.remaining_len() == 0) break;
        var string_writer = Writer.init(&strings);
        const held = qpack.instruction.read_encoder(&reader, &string_writer) catch unreachable;
        const end = base + reader.consumed().len;
        switch (held) {
            // RFC 9204 §4.3.1: a capacity change inserts nothing.
            .set_capacity => {},
            .insert_name_reference, .insert_literal, .duplicate => append(u64, log, end),
        }
    }
    log.parsed_end = base + reader.consumed().len;
}

fn parse_control(log: *Log(ControlFrame), buffer: anytype) void {
    var reader = Reader.init(unparsed(buffer, log.parsed_end));
    const base = log.parsed_end;
    skip_stream_type(&reader, base);
    // Bounded: a stream carries no more units than the log holds, and reserved frames among them.
    for (0..constants.h3_trace_control_frames_per_unit_max * units_max) |_| {
        if (reader.remaining_len() == 0) break;
        const frame_type = (wire.varint.decode(&reader) catch unreachable).value;
        const length = (wire.varint.decode(&reader) catch unreachable).value;
        const payload = reader.take(@intCast(length)) catch unreachable;
        const end = base + reader.consumed().len;
        if (frame_type == h3.constants.frame_settings) {
            append(ControlFrame, log, .{ .kind = .settings, .id = 0, .end = end });
        } else if (frame_type == h3.constants.frame_goaway) {
            var goaway = Reader.init(payload);
            const id = (wire.varint.decode(&goaway) catch unreachable).value;
            append(ControlFrame, log, .{ .kind = .goaway, .id = id / h3_trace_endpoint.request_stream_step, .end = end });
        }
        // RFC 9114 §7.2.8: a reserved frame type is one the model does not have.
    }
    log.parsed_end = base + reader.consumed().len;
}

fn parse_decoder(log: *Log(Instruction), buffer: anytype) void {
    var reader = Reader.init(unparsed(buffer, log.parsed_end));
    const base = log.parsed_end;
    skip_stream_type(&reader, base);
    // Bounded: a stream carries no more units than the log holds.
    for (0..units_max) |_| {
        if (reader.remaining_len() == 0) break;
        const held = qpack.instruction.read_decoder(&reader) catch unreachable;
        const end = base + reader.consumed().len;
        const step = h3_trace_endpoint.request_stream_step;
        append(Instruction, log, switch (held) {
            .section_acknowledgment => |id| .{ .kind = .acknowledgment, .stream = id / step, .count = 0, .end = end },
            .stream_cancellation => |id| .{ .kind = .cancellation, .stream = id / step, .count = 0, .end = end },
            .insert_count_increment => |count| .{ .kind = .increment, .stream = 0, .count = count, .end = end },
        });
    }
    log.parsed_end = base + reader.consumed().len;
}

fn append(comptime Unit: type, log: *Log(Unit), unit: Unit) void {
    assert(log.len < log.units.len);
    log.units[log.len] = unit;
    log.len += 1;
}
