//! The hostile peers of the deadline check (`deadline_plan.zig`, decision 110). Each writes a script
//! up front: its octets, cut into pieces, each with the instant it goes out. It reads what the
//! server sends only to acknowledge an h2 SETTINGS frame and to learn how the server ended a
//! request or the connection: with a 408 in h11, and in h2 with the status of a response, a
//! RST_STREAM or a GOAWAY.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const h2 = @import("h2");
const plan_module = @import("deadline_plan.zig");

const limits = sim.constants.deadline;
const Plan = plan_module.Plan;
const Writer = h2.core.Writer;
const constants = h2.constants;

/// Octets of the script that go out at one instant.
pub const Piece = struct {
    at_ms: u64,
    start: u32,
    len: u32,
};

pub const Error = h2.core.writer.Error || h2.hpack.encoder.Error || error{
    /// The script holds more pieces than `pieces_max`.
    ScriptFull,
};

/// An h11 request a peer sends whole, and the head a hostile peer sends slowly. The filler keeps
/// the slow head long enough that its pieces outlast every deadline.
const h11_request = "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n";
const h11_slow_head = "GET /slow HTTP/1.1\r\nHost: a.example\r\nX-Filler: " ++ filler ++ "\r\n\r\n";
const filler = "abcdefghijklmnopqrstuvwxyz0123456789";

/// The head of the request a slow body follows. Its Content-Length is more than the peer ever
/// sends, so the body never ends.
const h11_upload_head = "POST /upload HTTP/1.1\r\nHost: a.example\r\nContent-Length: " ++ upload_length ++ "\r\n\r\n";
const upload_length = "1000000";

/// The octets of a slow body's piece, the longest one included.
const body_filler: [body_piece_len_max]u8 = @splat('b');
const body_piece_len_max: usize = limits.slow_body_rate_max * limits.hostile_gap_ms_max / limits.ms_per_s;

/// The octets of the h11 status line of a 408 (RFC 9110 §15.5.9), which the check looks for.
pub const h11_timeout_line = "HTTP/1.1 408 ";

/// The streams a hostile h2 peer opens: its whole request or the one its slow body follows, and
/// its slow head's.
const whole_stream_id: u32 = 1;
const slow_stream_id: u32 = 3;

/// The instant a peer's first octets go out.
const start_ms: u64 = 0;

/// How long after its opening an h2 peer starts a slow field block, so its acknowledgment of the
/// server's SETTINGS goes out first: RFC 9113 §6.10 lets no other frame into a field block.
const block_after_opening_ms: u64 = 1;

/// The instant the first octet of a slow first head goes out: an h11 head starts the script, and
/// an h2 field block follows the opening.
pub fn slow_head_start_ms(protocol: plan_module.Protocol) u64 {
    return switch (protocol) {
        .h11 => start_ms,
        .h2 => start_ms + block_after_opening_ms,
    };
}

pub const Hostile = struct {
    script: [limits.script_len_max]u8,
    script_len: u32,
    pieces: [limits.pieces_max]Piece,
    pieces_len: u32,
    /// The next piece to go out.
    next_piece: u32,
    /// The octets of the server's output this peer has read as whole frames (h2).
    parsed: usize,
    /// SETTINGS frames of the server this peer has not acknowledged (RFC 9113 §6.5.3).
    acks_owed: u32,
    /// The error code of the GOAWAY the server sent, if one arrived (h2).
    goaway_code: ?u32,
    /// The status of the last response the server sent, and the error code of the first RST_STREAM
    /// it sent and the instant it arrived (h2). Later ones answer frames on the stream it reset.
    response_status: ?u16,
    reset_code: ?u32,
    reset_at_ms: ?u64,
    /// The RST_STREAM frames with NO_ERROR the server sent, and with REFUSED_STREAM (h2).
    resets_no_error: u32,
    resets_refused: u32,
    encoder: h2.hpack.Encoder,
    /// Reads the server's field blocks, all of them, so its table follows the server's encoder.
    decoder: h2.hpack.Decoder,

    /// Writes the script `plan` names. A silent peer's is empty.
    pub fn start(hostile: *Hostile, plan: *const Plan) Error!void {
        assert(!plan.honest());
        hostile.script_len = 0;
        hostile.pieces_len = 0;
        hostile.next_piece = 0;
        hostile.parsed = 0;
        hostile.acks_owed = 0;
        hostile.goaway_code = null;
        hostile.response_status = null;
        hostile.reset_code = null;
        hostile.reset_at_ms = null;
        hostile.resets_no_error = 0;
        hostile.resets_refused = 0;
        hostile.decoder.init(constants.header_table_size_initial);
        switch (plan.protocol) {
            .h11 => try hostile.script_h11(plan),
            .h2 => try hostile.script_h2(plan),
        }
    }

    /// The instant the next piece goes out, or null when the script is over.
    pub fn next_ms(hostile: *const Hostile) ?u64 {
        if (hostile.next_piece == hostile.pieces_len) return null;
        return hostile.pieces[hostile.next_piece].at_ms;
    }

    /// The pieces due at `now_ms`, one at a time, or null when none is.
    pub fn due(hostile: *Hostile, now_ms: u64) ?[]const u8 {
        const at_ms = hostile.next_ms() orelse return null;
        if (at_ms > now_ms) return null;
        const piece = hostile.pieces[hostile.next_piece];
        hostile.next_piece += 1;
        return hostile.script[piece.start..][0..piece.len];
    }

    /// Reads the server's whole frames from `received` at `now_ms`, noting each SETTINGS frame it
    /// owes an acknowledgment, the responses and resets of its streams, and the GOAWAY that ends
    /// the connection (h2).
    pub fn read_h2(hostile: *Hostile, received: []const u8, now_ms: u64) void {
        // Bounded: each pass reads one whole frame of `received`, or stops.
        for (0..received.len + 1) |_| {
            const left = received[hostile.parsed..];
            if (left.len < constants.frame_header_len) return;
            const length = std.mem.readInt(u24, left[0..constants.frame_length_len], .big);
            const whole = constants.frame_header_len + length;
            if (left.len < whole) return;
            hostile.on_frame(left[frame_type_offset], left[frame_flags_offset], left[constants.frame_header_len..whole], now_ms);
            hostile.parsed += whole;
        }
    }

    fn on_frame(hostile: *Hostile, frame_type: u8, flags: u8, payload: []const u8, now_ms: u64) void {
        const settings = frame_type == constants.frame_type_settings and flags & constants.flag_ack == 0;
        if (settings) hostile.acks_owed += 1;
        if (frame_type == constants.frame_type_goaway and payload.len >= goaway_code_end) {
            hostile.goaway_code = std.mem.readInt(u32, payload[goaway_code_start..goaway_code_end], .big);
        }
        const reset = frame_type == constants.frame_type_rst_stream and payload.len == constants.rst_stream_len;
        if (reset) hostile.on_reset(std.mem.readInt(u32, payload[0..constants.rst_stream_len], .big), now_ms);
        if (frame_type == constants.frame_type_headers) hostile.on_headers(flags, payload);
    }

    fn on_reset(hostile: *Hostile, code: u32, now_ms: u64) void {
        if (hostile.reset_code == null) {
            hostile.reset_code = code;
            hostile.reset_at_ms = now_ms;
        }
        if (code == constants.error_no_error) hostile.resets_no_error += 1;
        if (code == constants.error_refused_stream) hostile.resets_refused += 1;
    }

    /// Decodes a field block the server sent whole, and notes its status.
    fn on_headers(hostile: *Hostile, flags: u8, payload: []const u8) void {
        // The server's responses are short, so each fits one HEADERS frame.
        if (flags & constants.flag_end_headers == 0) return;
        const block = field_block(flags, payload) orelse return;
        var lines = hostile.decoder.block(block);
        // Bounded: each line takes an octet of the block at least.
        for (0..block.len + 1) |_| {
            const line = (lines.next() catch return) orelse return;
            if (std.mem.eql(u8, line.name, ":status")) {
                hostile.response_status = std.fmt.parseInt(u16, line.value, status_radix) catch null;
            }
        }
    }

    /// The field block of a HEADERS frame's payload, or null for a payload too short for its flags.
    fn field_block(flags: u8, payload: []const u8) ?[]const u8 {
        var block = payload;
        // RFC 9113 §6.2: the Pad Length and the priority fields come before the field block, and
        // the padding after it.
        if (flags & constants.flag_padded != 0) {
            if (block.len < constants.pad_length_len or block[0] >= block.len) return null;
            block = block[constants.pad_length_len .. block.len - block[0]];
        }
        if (flags & constants.flag_priority != 0) {
            if (block.len < constants.priority_fields_len) return null;
            block = block[constants.priority_fields_len..];
        }
        return block;
    }

    /// Writes the SETTINGS acknowledgments owed into `output`, and returns the octets written.
    pub fn write_acks(hostile: *Hostile, output: []u8) Error!usize {
        var writer = Writer.init(output);
        // Bounded by the SETTINGS frames the server sent.
        for (0..hostile.acks_owed) |_| try h2.frame.write_settings_ack(&writer);
        hostile.acks_owed = 0;
        return writer.written().len;
    }

    fn script_h11(hostile: *Hostile, plan: *const Plan) Error!void {
        var slow_start_ms = start_ms;
        switch (plan.peer) {
            .silent => return,
            // h11 has no PING, so an idle pinger makes its exchange and sends nothing more.
            .idle_pinger => return hostile.add(start_ms, h11_request),
            .slow_body, .long_body => {
                try hostile.add(start_ms, h11_upload_head);
                return hostile.add_body(plan, null);
            },
            // A peer that reads slowly or not at all makes its request and sends nothing more.
            .reads_nothing, .reads_slowly => return hostile.add(start_ms, h11_request),
            .slow_second_head => {
                try hostile.add(start_ms, h11_request);
                slow_start_ms = plan.answer_delay_ms[0] + limits.second_head_after_ms;
            },
            .slow_head => {},
            // `draw` makes an h11 pinger silent, an h11 peer that would open a window read
            // nothing and one that would open many streams send a slow body, and colibri's client
            // plays an honest peer.
            .honest, .slow_honest, .upload, .slow_reader, .pinger, .opens_window_slowly, .opens_no_connection_window, .many_streams => unreachable,
        }
        try hostile.add_slowly(slow_start_ms, plan, h11_slow_head);
    }

    fn script_h2(hostile: *Hostile, plan: *const Plan) Error!void {
        if (plan.peer == .silent) return;
        var opening: [preface_len_max]u8 = undefined;
        var writer = Writer.init(&opening);
        try writer.write_bytes(constants.client_preface);
        try h2.frame.write_settings(&writer, settings_of(plan));
        // A peer that reads nothing acknowledges the server's SETTINGS without reading them: the
        // server writes them before it reads a frame (RFC 9113 §3.4).
        if (plan.peer == .reads_nothing) try h2.frame.write_settings_ack(&writer);
        hostile.encoder.init(constants.header_table_size_initial, .never);
        var slow_start_ms = start_ms + block_after_opening_ms;
        // A peer that makes one exchange sends its request whole, in its opening, and a slow body's
        // head leaves its stream open.
        if (plan.exchanges_len > 0) try hostile.write_request(&writer, whole_stream_id, "GET", "/", true);
        if (plan.peer == .slow_body or plan.peer == .long_body) try hostile.write_request(&writer, whole_stream_id, "POST", "/upload", false);
        if (plan.peer == .slow_second_head) slow_start_ms = plan.answer_delay_ms[0] + limits.second_head_after_ms;
        try hostile.add(start_ms, writer.written());
        switch (plan.peer) {
            .pinger, .idle_pinger => try hostile.add_pings(plan),
            .slow_head, .slow_second_head => try hostile.add_slow_block(slow_start_ms, plan),
            .slow_body, .long_body => try hostile.add_body(plan, whole_stream_id),
            .opens_window_slowly => try hostile.add_window_updates(plan),
            .many_streams => try hostile.add_uploads(),
            .reads_nothing, .reads_slowly, .opens_no_connection_window => {},
            .honest, .slow_honest, .upload, .slow_reader, .silent => unreachable,
        }
    }

    /// A HEADERS frame carrying a whole request head for `path` on `stream_id`, which ends the
    /// stream when `end_stream` says so.
    fn write_request(hostile: *Hostile, writer: *Writer, stream_id: u32, method: []const u8, path: []const u8, end_stream: bool) Error!void {
        var block_storage: [block_len_max]u8 = undefined;
        const block = try hostile.encode(&block_storage, method, path);
        try h2.frame.write_headers(writer, stream_id, block, end_stream, true, 0, null);
    }

    fn encode(hostile: *Hostile, storage: []u8, method: []const u8, path: []const u8) Error![]const u8 {
        var block = Writer.init(storage);
        try hostile.encoder.begin_block(&block);
        try hostile.encoder.write_field(&block, ":method", method, .without_indexing);
        try hostile.encoder.write_field(&block, ":scheme", "http", .without_indexing);
        try hostile.encoder.write_field(&block, ":path", path, .without_indexing);
        try hostile.encoder.write_field(&block, ":authority", "a.example", .without_indexing);
        hostile.encoder.commit_block();
        return block.written();
    }

    /// A field block cut into a HEADERS frame and `continuation_frames` CONTINUATION frames, the
    /// HEADERS frame at `first_ms` and each CONTINUATION frame a gap after the one before.
    fn add_slow_block(hostile: *Hostile, first_ms: u64, plan: *const Plan) Error!void {
        var block_storage: [block_len_max]u8 = undefined;
        const block = try hostile.encode(&block_storage, "GET", "/slow");
        const fragments = limits.continuation_frames + 1;
        assert(block.len >= fragments);
        const fragment_len = block.len / fragments;
        var frame_storage: [frame_len_max]u8 = undefined;
        for (0..fragments) |index| {
            const last = index + 1 == fragments;
            const fragment = if (last) block[index * fragment_len ..] else block[index * fragment_len ..][0..fragment_len];
            var writer = Writer.init(&frame_storage);
            if (index == 0) {
                try h2.frame.write_headers(&writer, slow_stream_id, fragment, true, false, 0, null);
            } else {
                try h2.frame.write_continuation(&writer, slow_stream_id, fragment, last);
            }
            try hostile.add(first_ms + index * plan.gap_ms, writer.written());
        }
    }

    /// `many_streams_len` requests at the start, each on a stream of its own and each leaving its
    /// stream open for a body that never comes.
    fn add_uploads(hostile: *Hostile) Error!void {
        var frame_storage: [frame_len_max]u8 = undefined;
        for (0..limits.many_streams_len) |index| {
            var writer = Writer.init(&frame_storage);
            const stream_id: u32 = @intCast(whole_stream_id + stream_id_step * index);
            try hostile.write_request(&writer, stream_id, "POST", "/upload", false);
            try hostile.add(start_ms, writer.written());
        }
    }

    /// A WINDOW_UPDATE of one octet on the stream of its request every gap, from one gap after
    /// the start until the horizon.
    fn add_window_updates(hostile: *Hostile, plan: *const Plan) Error!void {
        var frame_storage: [constants.frame_header_len + constants.window_update_len]u8 = undefined;
        var at_ms = start_ms + plan.gap_ms;
        // Bounded: `pieces_max` holds a piece for each of the run's shortest gaps.
        for (0..limits.pieces_max) |_| {
            if (at_ms >= limits.horizon_ms) return;
            var writer = Writer.init(&frame_storage);
            try h2.frame.write_window_update(&writer, whole_stream_id, window_step);
            try hostile.add(at_ms, writer.written());
            at_ms += plan.gap_ms;
        }
    }

    /// A PING every gap, from one gap after the start until the horizon.
    fn add_pings(hostile: *Hostile, plan: *const Plan) Error!void {
        var frame_storage: [frame_len_max]u8 = undefined;
        var at_ms = start_ms + plan.gap_ms;
        // Bounded: `pieces_max` holds a PING for each of the run's shortest gaps.
        for (0..limits.pieces_max) |_| {
            if (at_ms >= limits.horizon_ms) return;
            var writer = Writer.init(&frame_storage);
            try h2.frame.write_ping(&writer, @splat(0), false);
            try hostile.add(at_ms, writer.written());
            at_ms += plan.gap_ms;
        }
    }

    /// A body of `piece_len` octets every gap, from one gap after the start until the plan's body
    /// stops: raw octets in h11, and a DATA frame on `stream_id` for each piece in h2.
    fn add_body(hostile: *Hostile, plan: *const Plan, stream_id: ?u32) Error!void {
        assert(plan.piece_len <= body_piece_len_max);
        const piece = body_filler[0..plan.piece_len];
        var frame_storage: [constants.frame_header_len + body_piece_len_max]u8 = undefined;
        var at_ms = start_ms + plan.gap_ms;
        // Bounded: `pieces_max` holds a piece for each of the run's shortest gaps.
        for (0..limits.pieces_max) |_| {
            if (at_ms >= plan_module.body_end_ms(plan)) return;
            const id = stream_id orelse {
                try hostile.add(at_ms, piece);
                at_ms += plan.gap_ms;
                continue;
            };
            var writer = Writer.init(&frame_storage);
            try h2.frame.write_data(&writer, id, piece, false, 0);
            try hostile.add(at_ms, writer.written());
            at_ms += plan.gap_ms;
        }
    }

    /// `octets` in pieces of the plan's length, the first at `first_ms` and each a gap later.
    fn add_slowly(hostile: *Hostile, first_ms: u64, plan: *const Plan, octets: []const u8) Error!void {
        var at_ms = first_ms;
        var offset: usize = 0;
        // Bounded: each pass sends a piece of at least one octet.
        for (0..octets.len) |_| {
            if (offset == octets.len) return;
            const len = @min(plan.piece_len, octets.len - offset);
            try hostile.add(at_ms, octets[offset..][0..len]);
            offset += len;
            at_ms += plan.gap_ms;
        }
    }

    fn add(hostile: *Hostile, at_ms: u64, octets: []const u8) Error!void {
        // A piece holds octets, and pieces go out in order.
        assert(octets.len > 0);
        assert(hostile.pieces_len == 0 or hostile.pieces[hostile.pieces_len - 1].at_ms <= at_ms);
        if (hostile.pieces_len == limits.pieces_max) return error.ScriptFull;
        if (hostile.script_len + octets.len > hostile.script.len) return error.ScriptFull;
        @memcpy(hostile.script[hostile.script_len..][0..octets.len], octets);
        hostile.pieces[hostile.pieces_len] = .{ .at_ms = at_ms, .start = hostile.script_len, .len = @intCast(octets.len) };
        hostile.pieces_len += 1;
        hostile.script_len += @intCast(octets.len);
    }
};

/// The SETTINGS a peer opens with: a stream window of 0 for one that opens it slowly, the largest
/// for one that leaves the connection's window alone, and the defaults for the rest.
fn settings_of(plan: *const Plan) []const h2.frame.Setting {
    return switch (plan.peer) {
        .opens_window_slowly => &.{.{ .id = constants.setting_initial_window_size, .value = 0 }},
        .opens_no_connection_window => &.{.{ .id = constants.setting_initial_window_size, .value = constants.window_max }},
        else => &.{},
    };
}

/// The octets each WINDOW_UPDATE of a peer that opens its window slowly adds.
const window_step: u32 = 1;

/// A client's streams take odd identifiers, one after another (RFC 9113 §5.1.1).
const stream_id_step: u32 = 2;

/// Where a frame header's type and flags lie, after its length (RFC 9113 §4.1).
const frame_type_offset: usize = constants.frame_length_len;
const frame_flags_offset: usize = frame_type_offset + @sizeOf(u8);

/// Where a GOAWAY's error code lies in its payload: after the last stream identifier (RFC 9113
/// §6.8).
const goaway_code_start: usize = 4;
const goaway_code_end: usize = 8;

/// A status code is three decimal digits (RFC 9110 §15).
const status_radix: u8 = 10;

/// The longest field block and frame a hostile peer writes, and its opening: the preface, then
/// its SETTINGS frame, an acknowledgment of the server's, and a whole request.
const block_len_max: usize = 128;
const frame_len_max: usize = constants.frame_header_len + block_len_max;
const opening_frames: usize = 3;
const preface_len_max: usize = constants.client_preface_len + opening_frames * frame_len_max;

comptime {
    assert(goaway_code_end - goaway_code_start == @sizeOf(u32));
    assert(h11_slow_head.len > h11_request.len);
    assert(body_piece_len_max > 0 and body_piece_len_max <= constants.max_frame_size_initial);
}
