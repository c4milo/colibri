//! The stream the connection gate feeds (design §8 step 4): the octets a client sends a server.
//!
//! A seed draws a `Plan`: the client connection preface (RFC 9113 §3.4), one SETTINGS frame, then
//! 1 to `connection_gate_frames_max` frames. `write` encodes the plan into a stream, which
//! `connection_gate.zig` hands to one `h2.Connection` through the byte pipe.
//!
//! The drawn frames reach invariants 13 to 16: requests on increasing identifiers, with and
//! without END_STREAM and some cut across CONTINUATION frames (§6.10); DATA (§6.1); PING (§6.7); a
//! SETTINGS frame whose SETTINGS_INITIAL_WINDOW_SIZE sweeps every stream's send window (§6.9.2);
//! WINDOW_UPDATE on stream 0 and on a stream (§6.9); and RST_STREAM (§6.4).
//!
//! Every drawn frame is one the connection accepts, because the plan's outcome is what the gate
//! compares against. Two rules keep it that way. The draw opens identifiers in increasing order
//! and steps over some, which RFC 9113 §5.1.1 closes implicitly. And a stream the client resets
//! leaves the draw's list: §5.1 makes a later DATA or WINDOW_UPDATE on a stream closed by the
//! peer's RST_STREAM a connection error of STREAM_CLOSED.
//!
//! One seed in `connection_gate_refusal_one_in` then appends the frames of a `Refusal`, each of
//! which the connection refuses, so the run ends `rejected` rather than `pass`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const h2 = @import("h2");
const sim = @import("sim");

const Writer = core.Writer;
const Random = sim.Random;
const constants = sim.constants;
const h2_constants = h2.constants;
const frame = h2.frame;

/// What one drawn frame is. Each is a frame a client may send a server at any point in a plan.
pub const Kind = enum {
    /// A HEADERS frame carrying a request, whole in one frame (RFC 9113 §6.2).
    request,
    /// The same request, its field block cut across CONTINUATION frames (§6.10).
    request_continued,
    /// A DATA frame on a stream the plan opened (§6.1).
    data,
    /// A PING frame, which the connection answers (§6.7).
    ping,
    /// A SETTINGS frame carrying one SETTINGS_INITIAL_WINDOW_SIZE (§6.5.2, §6.9.2).
    settings,
    /// A WINDOW_UPDATE frame on stream 0 (§6.9).
    connection_window_update,
    /// A WINDOW_UPDATE frame on a stream the plan opened (§6.9).
    stream_window_update,
    /// A RST_STREAM frame on a stream the plan opened (§6.4).
    rst_stream,
};

/// The frames a seed can append after its own. Each is a connection error that one invariant of
/// docs/invariants.md names.
pub const Refusal = enum {
    /// A HEADERS frame on the identifier the plan's requests left below the watermark
    /// (invariant 13).
    headers_below_watermark,
    /// A PING frame between the frames of a field block (invariant 14).
    frame_inside_field_block,
    /// A WINDOW_UPDATE on stream 0 whose increment takes the window above its maximum
    /// (invariant 15).
    connection_window_overflow,
    /// A second GOAWAY naming a higher last stream identifier (invariant 16).
    goaway_last_id_rises,
};

/// One drawn frame. Every field but `kind` has a default, because each kind fills the few it uses.
pub const Frame = struct {
    kind: Kind,
    /// The stream the frame names, or 0 for the frames that name none.
    stream_id: u32 = 0,
    /// The END_STREAM flag of a HEADERS or DATA frame (RFC 9113 §6.1, §6.2).
    end_stream: bool = false,
    /// `request_continued`: fragments the field block is cut into, the HEADERS frame included.
    fragments: u32 = 1,
    /// `request` and `request_continued`: whether the field block carries `:authority`.
    with_authority: bool = false,
    /// `data`: payload octets.
    data_len: u32 = 0,
    /// The WINDOW_UPDATE increment, the RST_STREAM error code, or the SETTINGS_INITIAL_WINDOW_SIZE.
    value: u32 = 0,
    /// The ACK flag of a PING or SETTINGS frame, which answers one the peer sent rather than
    /// asking for an answer (RFC 9113 §6.5.3, §6.7).
    ack: bool = false,
    /// `ping`: the Opaque Data the frame carries and the connection echoes (RFC 9113 §6.7).
    opaque_data: [h2_constants.ping_len]u8 = @splat(0),
};

/// The field block of the request a plan sends: `:method: GET`, `:scheme: http` and `:path: /`,
/// each an index into HPACK's static table (RFC 7541 §6.1, Appendix A). RFC 9113 §8.3.1 asks for
/// no more of a request that is not CONNECT.
const request_block = "\x82\x86\x84";

/// The same request with `:authority: example.com` after it: a literal field line with an indexed
/// name and without indexing, whose 4-bit prefix holds static index 1, `:authority` (RFC 7541
/// §6.2.2), then the value's length and the value.
const request_block_authority = request_block ++ "\x01\x0bexample.com";

/// The octets a DATA frame carries. The connection hands the payload to its caller without reading
/// it (RFC 9113 §6.1), so one repeated octet says as much as any other.
const data_payload: [constants.connection_gate_data_len_max]u8 = @splat('d');

/// The Opaque Data of the PING frame `frame_inside_field_block` sends (RFC 9113 §6.7).
const refusal_ping_data: [h2_constants.ping_len]u8 = @splat('p');

/// The last stream identifiers of the two GOAWAY frames `goaway_last_id_rises` sends. The second
/// is the higher, which RFC 9113 §6.8 refuses.
const goaway_last_id_first: u32 = 0;
const goaway_last_id_second: u32 = h2_constants.stream_id_client_first;

/// The outcomes a drawn flag takes.
const flag_outcomes: u64 = 2;

/// No padding and no priority fields: RFC 9113 §6.2 makes both optional and decision 18 gives
/// priority no meaning, so a plan sends neither.
const no_padding: u8 = 0;

/// The values a plan's SETTINGS_INITIAL_WINDOW_SIZE is drawn from: no space at all, one octet, a
/// small window, and the initial value RFC 9113 §6.5.2 gives.
const initial_window_sizes = [_]u32{
    0,
    1,
    constants.connection_gate_window_size_small,
    h2_constants.initial_window_size_initial,
};

pub const Plan = struct {
    frames: [constants.connection_gate_frames_max]Frame,
    count: u32,
    /// The SETTINGS_INITIAL_WINDOW_SIZE the SETTINGS frame of the preface carries.
    initial_window_size: u32,
    /// The identifier a refusal opens a field block on, which no drawn frame used.
    refusal_stream_id: u32,
    refusal: ?Refusal,

    /// Draws a plan from `random`.
    pub fn draw(random: *Random) Plan {
        var plan: Plan = .{
            .frames = @splat(.{ .kind = .ping }),
            .count = @intCast(random.between(1, constants.connection_gate_frames_max)),
            .initial_window_size = initial_window_sizes[random.below(initial_window_sizes.len)],
            .refusal_stream_id = 0,
            .refusal = null,
        };
        var opened = Opened.init(random);
        // The first frame is always a request, so every later frame has a stream to name and the
        // watermark is above `stream_id_client_first` for `headers_below_watermark` to use.
        plan.frames[0] = draw_request(random, &opened, .request);
        for (plan.frames[1..plan.count]) |*drawn| drawn.* = draw_frame(random, &opened);
        plan.refusal_stream_id = opened.next_id;
        if (random.below(constants.connection_gate_refusal_one_in) == 0) {
            const refusals = std.enums.values(Refusal);
            plan.refusal = refusals[random.below(refusals.len)];
        }
        assert(plan.count >= 1 and plan.count <= constants.connection_gate_frames_max);
        assert(plan.refusal_stream_id > h2_constants.stream_id_client_first);
        return plan;
    }

    /// Encodes the preface, every frame and the refusal into `output`.
    pub fn write(plan: *const Plan, output: *Writer) core.writer.Error!void {
        // RFC 9113 §3.4: a client starts the connection with 24 octets and a SETTINGS frame.
        try output.write_bytes(h2_constants.client_preface);
        try write_settings(plan.initial_window_size, output);
        for (plan.frames[0..plan.count]) |*drawn| try write_frame(drawn, output);
        if (plan.refusal != null) try write_refusal(plan, output);
    }
};

/// The streams a draw has opened and the identifier it opens next. The file header says why a
/// stream the client resets leaves the list.
const Opened = struct {
    ids: [constants.connection_gate_streams_max]u32,
    count: u32,
    /// The identifier the next request opens.
    next_id: u32,

    fn init(random: *Random) Opened {
        const drawn = random.below(constants.connection_gate_first_stream_ids);
        const step = h2_constants.stream_id_step * (drawn + 1);
        // Above the first identifier a client may use, which stays below the watermark.
        const first = h2_constants.stream_id_client_first + step;
        return .{ .ids = @splat(0), .count = 0, .next_id = @intCast(first) };
    }

    /// Takes the next identifier and advances past it, stepping over identifiers RFC 9113 §5.1.1
    /// closes implicitly.
    fn open(opened: *Opened, random: *Random) u32 {
        assert(opened.count < opened.ids.len);
        const id = opened.next_id;
        opened.ids[opened.count] = id;
        opened.count += 1;
        const steps = random.between(1, constants.connection_gate_stream_id_steps);
        opened.next_id += @intCast(h2_constants.stream_id_step * steps);
        assert(opened.next_id > id and opened.next_id <= h2_constants.stream_id_max);
        return id;
    }

    /// One of the streams still open, or null once the client has reset every one.
    fn pick(opened: *const Opened, random: *Random) ?u32 {
        if (opened.count == 0) return null;
        return opened.ids[random.below(opened.count)];
    }

    /// Drops `id`, which the client is about to reset. The last entry takes its place, which keeps
    /// the list packed and every choice a function of the seed alone.
    fn forget(opened: *Opened, id: u32) void {
        assert(opened.count > 0);
        for (opened.ids[0..opened.count], 0..) |held, index| {
            if (held != id) continue;
            opened.count -= 1;
            opened.ids[index] = opened.ids[opened.count];
            return;
        }
        unreachable; // `pick` returned the identifier, so the list holds it.
    }
};

fn draw_flag(random: *Random) bool {
    return random.below(flag_outcomes) == 1;
}

fn draw_increment(random: *Random) u32 {
    // RFC 9113 §6.9: an increment of 0 is an error, so every increment drawn is above it.
    return @intCast(random.between(1, constants.connection_gate_increment_max));
}

fn draw_frame(random: *Random, opened: *Opened) Frame {
    const kinds = std.enums.values(Kind);
    const kind = kinds[random.below(kinds.len)];
    return switch (kind) {
        .request, .request_continued => draw_request(random, opened, kind),
        .data, .stream_window_update, .rst_stream => draw_stream_frame(random, opened, kind),
        .ping => draw_ping(random),
        .settings => .{
            .kind = .settings,
            .value = initial_window_sizes[random.below(initial_window_sizes.len)],
            .ack = draw_flag(random),
        },
        .connection_window_update => .{
            .kind = .connection_window_update,
            .value = draw_increment(random),
        },
    };
}

fn draw_request(random: *Random, opened: *Opened, kind: Kind) Frame {
    const continued = kind == .request_continued;
    return .{
        .kind = kind,
        .stream_id = opened.open(random),
        .end_stream = draw_flag(random),
        .with_authority = draw_flag(random),
        .fragments = if (continued) @intCast(random.between(
            constants.connection_gate_fragments_min,
            constants.connection_gate_fragments_max,
        )) else 1,
    };
}

/// A frame on a stream the plan opened, or a PING once the client has reset every one.
fn draw_stream_frame(random: *Random, opened: *Opened, kind: Kind) Frame {
    const id = opened.pick(random) orelse return draw_ping(random);
    if (kind == .rst_stream) {
        opened.forget(id);
        return .{ .kind = .rst_stream, .stream_id = id, .value = h2_constants.error_cancel };
    }
    if (kind == .stream_window_update) {
        return .{ .kind = kind, .stream_id = id, .value = draw_increment(random) };
    }
    return .{
        .kind = .data,
        .stream_id = id,
        .end_stream = draw_flag(random),
        .data_len = @intCast(random.between(0, constants.connection_gate_data_len_max)),
    };
}

fn draw_ping(random: *Random) Frame {
    var drawn: Frame = .{ .kind = .ping, .ack = draw_flag(random) };
    for (&drawn.opaque_data) |*octet| octet.* = @truncate(random.next());
    return drawn;
}

/// The field block of `drawn`, which every request kind carries.
fn block_of(drawn: *const Frame) []const u8 {
    return if (drawn.with_authority) request_block_authority else request_block;
}

fn write_settings(initial_window_size: u32, output: *Writer) core.writer.Error!void {
    const setting: frame.Setting = .{
        .id = h2_constants.setting_initial_window_size,
        .value = initial_window_size,
    };
    try frame.write_settings(output, &.{setting});
}

fn write_request(drawn: *const Frame, output: *Writer, end_headers: bool) core.writer.Error!void {
    const block = block_of(drawn);
    const fragment = if (end_headers) block else block[0 .. block.len / drawn.fragments];
    try frame.write_headers(output, drawn.stream_id, fragment, drawn.end_stream, end_headers, no_padding, null);
}

fn write_frame(drawn: *const Frame, output: *Writer) core.writer.Error!void {
    const id = drawn.stream_id;
    switch (drawn.kind) {
        .request => try write_request(drawn, output, true),
        .request_continued => try write_continued(drawn, output),
        .data => try frame.write_data(output, id, data_payload[0..drawn.data_len], drawn.end_stream, no_padding),
        .ping => try frame.write_ping(output, drawn.opaque_data, drawn.ack),
        // RFC 9113 §6.5: a SETTINGS frame carrying ACK has an empty payload.
        .settings => if (drawn.ack)
            try frame.write_settings_ack(output)
        else
            try write_settings(drawn.value, output),
        .connection_window_update => try frame.write_window_update(output, h2_constants.connection_stream_id, drawn.value),
        .stream_window_update => try frame.write_window_update(output, id, drawn.value),
        .rst_stream => try frame.write_rst_stream(output, id, drawn.value),
    }
}

/// Writes one request as a HEADERS frame without END_HEADERS and the CONTINUATION frames that
/// carry the rest of its field block (RFC 9113 §6.10). Every fragment but the last is the same
/// length, which may be 0: §6.10 sets no lower bound on a fragment.
fn write_continued(drawn: *const Frame, output: *Writer) core.writer.Error!void {
    const block = block_of(drawn);
    assert(drawn.fragments >= constants.connection_gate_fragments_min);
    assert(drawn.fragments <= constants.connection_gate_fragments_max);
    try write_request(drawn, output, false);
    const fragment_len = block.len / drawn.fragments;
    var offset = fragment_len;
    for (1..drawn.fragments) |index| {
        const last = index + 1 == drawn.fragments;
        const end = if (last) block.len else offset + fragment_len;
        // RFC 9113 §6.10: END_HEADERS on the last CONTINUATION frame ends the field block.
        try frame.write_continuation(output, drawn.stream_id, block[offset..end], last);
        offset = end;
    }
    assert(offset == block.len);
}

fn write_refusal(plan: *const Plan, output: *Writer) core.writer.Error!void {
    const id = plan.refusal_stream_id;
    switch (plan.refusal.?) {
        // RFC 9113 §5.1.1: the first use of an identifier closes every lower idle one the peer
        // could have opened, so a HEADERS frame on the identifier the plan's requests left behind
        // is a connection error of PROTOCOL_ERROR.
        .headers_below_watermark => try write_bare_headers(h2_constants.stream_id_client_first, true, output),
        // RFC 9113 §4.3: the frames of a field block are contiguous, so a PING frame between a
        // HEADERS frame and the CONTINUATION it waits for ends the connection.
        .frame_inside_field_block => {
            try write_bare_headers(id, false, output);
            try frame.write_ping(output, refusal_ping_data, false);
        },
        // RFC 9113 §6.9.1: an increment that takes the connection's window above 2^31 - 1 is a
        // connection error of FLOW_CONTROL_ERROR, and the window starts above 0.
        .connection_window_overflow => try frame.write_window_update(
            output,
            h2_constants.connection_stream_id,
            h2_constants.window_max,
        ),
        // RFC 9113 §6.8: a GOAWAY may not name a higher last stream identifier than the one before.
        .goaway_last_id_rises => {
            try frame.write_goaway(output, goaway_last_id_first, h2_constants.error_no_error, "");
            try frame.write_goaway(output, goaway_last_id_second, h2_constants.error_no_error, "");
        },
    }
}

/// One HEADERS frame carrying the whole short request block, with END_STREAM unset.
fn write_bare_headers(stream_id: u32, end_headers: bool, output: *Writer) core.writer.Error!void {
    try frame.write_headers(output, stream_id, request_block, false, end_headers, no_padding, null);
}

comptime {
    // The preface: the client's octets and a SETTINGS frame carrying one setting.
    const preface_len = h2_constants.client_preface_len +
        h2_constants.frame_header_len + h2_constants.setting_len;
    assert(preface_len <= constants.connection_gate_preface_len_max);
    // The frames that write the most: a DATA frame at its longest payload, and a request cut into
    // the most fragments, each fragment carrying a frame header of its own.
    const data_len = h2_constants.frame_header_len + constants.connection_gate_data_len_max;
    const continued_len = constants.connection_gate_fragments_max * h2_constants.frame_header_len +
        request_block_authority.len;
    assert(data_len <= constants.connection_gate_frame_len_max);
    assert(continued_len <= constants.connection_gate_frame_len_max);
    // The refusal that writes the most: a HEADERS frame and the PING frame inside its block.
    const refusal_len = 2 * h2_constants.frame_header_len + request_block.len + h2_constants.ping_len;
    const refusal_room = constants.connection_gate_refusal_frames_max *
        constants.connection_gate_frame_len_max;
    assert(refusal_len <= refusal_room);
    // A plan draws fewer frames than RFC 9113 §10.5's RST_STREAM rate limit admits, so no plan can
    // reach it: the instants the pipe supplies cannot decide a verdict, and neither can chunking.
    assert(constants.connection_gate_frames_max < h2_constants.rst_stream_rate_max);
    // The CONTINUATION frames one request is cut into stay under §6.10's bound (invariant 14).
    assert(constants.connection_gate_fragments_max <= h2_constants.continuation_count_max + 1);
}

const testing = std.testing;

/// Where the tests write a plan's stream, placed outside any stack frame. Test-only.
var test_stream: [constants.connection_gate_stream_len_max]u8 = @splat(0);

/// The stream `plan` writes, inside `test_stream`. Test-only.
fn stream_of(plan: *const Plan) ![]const u8 {
    var output = Writer.init(&test_stream);
    try plan.write(&output);
    return output.written();
}

test "every plan opens increasing identifiers above the one its refusal names" {
    for (0..constants.gate_seeds_default) |seed| {
        var random = Random.init(seed);
        const plan = Plan.draw(&random);
        var highest: u32 = h2_constants.stream_id_client_first;
        for (plan.frames[0..plan.count]) |drawn| {
            if (drawn.kind != .request and drawn.kind != .request_continued) continue;
            try testing.expect(drawn.stream_id > highest);
            try testing.expectEqual(1, drawn.stream_id % h2_constants.stream_id_step);
            highest = drawn.stream_id;
        }
        try testing.expectEqual(Kind.request, plan.frames[0].kind);
        try testing.expect(plan.refusal_stream_id > highest);
    }
}

test "every plan's stream opens with the preface and fits the named length" {
    var refused: u32 = 0;
    for (0..constants.gate_seeds_default) |seed| {
        var random = Random.init(seed);
        const plan = Plan.draw(&random);
        const stream = try stream_of(&plan);
        try testing.expectEqualStrings(h2_constants.client_preface, stream[0..h2_constants.client_preface_len]);
        // RFC 9113 §3.4: the preface ends with a SETTINGS frame, which the frame header names.
        try testing.expectEqual(h2_constants.frame_type_settings, stream[h2_constants.client_preface_len + 3]);
        try testing.expect(stream.len <= constants.connection_gate_stream_len_max);
        if (plan.refusal != null) refused += 1;
    }
    try testing.expect(refused > 0 and refused < constants.gate_seeds_default);
}

test "a request cut into fragments writes the same field block as one written whole" {
    const whole: Frame = .{ .kind = .request, .stream_id = 3, .with_authority = true };
    var output = Writer.init(&test_stream);
    try write_frame(&whole, &output);
    const block = output.written()[h2_constants.frame_header_len..];
    try testing.expectEqualStrings(request_block_authority, block);
    for (2..constants.connection_gate_fragments_max + 1) |fragments| {
        const cut: Frame = .{
            .kind = .request_continued,
            .stream_id = 3,
            .with_authority = true,
            .fragments = @intCast(fragments),
        };
        var cut_output = Writer.init(&test_stream);
        try write_frame(&cut, &cut_output);
        try testing.expectEqual(fragments, count_frames(cut_output.written()));
    }
}

/// The frames `octets` holds, read by walking each frame header's Length field. Test-only.
fn count_frames(octets: []const u8) usize {
    var offset: usize = 0;
    var frames: usize = 0;
    for (0..octets.len) |_| {
        if (offset == octets.len) return frames;
        var reader = core.Reader.init(octets[offset..]);
        const header = frame.read_header(&reader) catch unreachable;
        offset += h2_constants.frame_header_len + header.length;
        frames += 1;
    }
    unreachable; // Every frame takes at least a header, so the octets run out first.
}
