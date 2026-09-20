//! The check of design §8 step 5's colibri side: one h2 connection driven over the null TLS
//! provider, with the records cut at places the seed draws.
//!
//! What it proves is the property step 2 proved for raw octets, now for records: where a record
//! ends changes nothing a connection decides. RFC 9846 §5.1 sizes records and RFC 9113 §4.1 sizes
//! frames, and neither divides the other, so one frame may span records and one record may hold
//! several frames. A run that cuts the same stream into different records must accept the same
//! frames, report the same events and end the same way.
//!
//! This is not step 5's recorded check. That one is `h2spec -t -k` and interop in both directions,
//! and both need a TLS 1.3 server with certificate signing, which no implementation in this tree
//! supplies (decision 10).
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const sim = @import("sim");
const constants = sim.constants;

const h2_constants = h2.constants;
const connection_invariants = @import("connection_invariants.zig");

/// The digest of every run's events, over `check_seeds_default` seeds. It changes when the
/// connection's behaviour changes, and is committed with the new value after both build modes
/// agree.
pub const census_crc32_expected: u32 = 0x795236bd;

/// How a seed failed.
pub const Violation = error{
    /// Two runs of the seed cut into different records reported different events.
    RecordCuttingChangedVerdict,
    /// The connection refused a stream the plan requires it to accept.
    OutcomeUnexpected,
} || connection_invariants.Violation;

/// What one run of a seed produced: the events, in order, as one octet each.
const Events = struct {
    held: [constants.tls_check_events_max]u8,
    len: usize,

    fn init(events: *Events) void {
        events.held = @splat(0);
        events.len = 0;
    }

    fn push(events: *Events, event: h2.Event) void {
        // The loop is bounded by the frames one fixed stream carries (non-negotiable 4).
        assert(events.len < constants.tls_check_events_max);
        events.held[events.len] = @intFromEnum(std.meta.activeTag(event));
        events.len += 1;
    }

    fn written(events: *const Events) []const u8 {
        return events.held[0..events.len];
    }
};

/// The storage one run needs, which the caller places (decision 35).
pub const Storage = struct {
    connection: h2.Connection,
    provider: sim.NullProvider,
    stream: [constants.tls_check_stream_len_max]u8,
    records: [
        constants.tls_check_stream_len_max +
            constants.tls_check_records_max * constants.record_overhead_len
    ]u8,
    plaintext: [constants.tls_check_plaintext_len_max]u8,
    /// Record octets delivered but not yet whole, which is what a socket read leaves behind.
    pending: [
        constants.tls_check_stream_len_max +
            constants.tls_check_records_max * constants.record_overhead_len
    ]u8,
    held: [constants.tls_check_plaintext_len_max]u8,
    output: [constants.tls_check_output_len_max]u8,
    events: Events,
    invariants: connection_invariants.Invariants,

    /// Storage with nothing in it, which every run fills before it reads (invariant 5).
    pub const zeroed: Storage = .{
        .connection = undefined,
        .provider = .{},
        .stream = @splat(0),
        .records = @splat(0),
        .plaintext = @splat(0),
        .pending = @splat(0),
        .held = @splat(0),
        .output = @splat(0),
        .events = .{ .held = @splat(0), .len = 0 },
        .invariants = undefined,
    };
};

/// Builds the h2 byte stream every seed carries: the client preface, a SETTINGS frame, and one
/// request that ends its stream (RFC 9113 §3.4, §6.5, §8.3.1).
fn build_stream(buffer: []u8) []const u8 {
    var writer = sim.core.Writer.init(buffer);
    writer.write_bytes(h2_constants.client_preface) catch unreachable;
    write_frame(&writer, h2_constants.frame_type_settings, 0, 0, &.{});
    var block: [constants.tls_check_stream_len_max]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(h2_constants.header_table_size_initial, .never);
    var block_writer = sim.core.Writer.init(&block);
    encoder.begin_block(&block_writer) catch unreachable;
    encoder.write_field(&block_writer, ":method", "GET", .without_indexing) catch unreachable;
    encoder.write_field(&block_writer, ":scheme", "https", .without_indexing) catch unreachable;
    encoder.write_field(&block_writer, ":path", "/", .without_indexing) catch unreachable;
    encoder.write_field(&block_writer, ":authority", "example.com", .without_indexing) catch unreachable;
    encoder.commit_block();
    const flags = h2_constants.flag_end_headers | h2_constants.flag_end_stream;
    write_frame(&writer, h2_constants.frame_type_headers, flags, 1, block_writer.written());
    return writer.written();
}

/// One frame header and its payload (RFC 9113 §4.1).
fn write_frame(writer: *sim.core.Writer, frame_type: u8, flags: u8, stream_id: u32, payload: []const u8) void {
    h2.frame.write_header(writer, .{
        .length = @intCast(payload.len),
        .type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    }) catch unreachable;
    writer.write_bytes(payload) catch unreachable;
}

/// Cuts `stream` into records at points `random` draws, and returns the octets. One record when
/// `cuts` is 0, which is the run every other run is compared against.
fn cut_into_records(storage: *Storage, stream: []const u8, cuts: u64, random: *sim.Random) []const u8 {
    var writer = sim.core.Writer.init(&storage.records);
    var scratch: [constants.tls_check_stream_len_max + constants.record_overhead_len]u8 = undefined;
    var offset: usize = 0;
    // The loop is bounded by the records one stream may be cut into (non-negotiable 4).
    for (0..constants.tls_check_records_max) |_| {
        if (offset == stream.len) break;
        const left = stream.len - offset;
        const body_len = if (cuts == 0) left else @min(left, 1 + random.below(left));
        const body = stream[offset .. offset + body_len];
        const written = sim.null_provider.write_application_record(&scratch, body) catch unreachable;
        writer.write_bytes(scratch[0..written]) catch unreachable;
        offset += body_len;
    }
    assert(offset == stream.len);
    return writer.written();
}

/// Runs one seed and fills `storage.events`. `cuts` says whether the stream is cut into many
/// records or one, and `chunked` whether those records are delivered whole or in pieces a socket
/// read would leave behind, so a record arrives in parts as often as it arrives whole.
fn run_once(storage: *Storage, cuts: u64, chunked: bool, seed: u64) Violation!void {
    var random = sim.Random.init(seed);
    const stream = build_stream(&storage.stream);
    const records = cut_into_records(storage, stream, cuts, &random);
    storage.provider = .{};
    storage.connection.init(.server);
    h2.connection_tls.attach(&storage.connection, storage.provider.provider()) catch
        return error.OutcomeUnexpected;
    storage.events.init();
    storage.invariants.init();
    var held_len: usize = 0;
    var pending_len: usize = 0;
    var delivered: usize = 0;
    // Each turn delivers at least one octet and then opens what it can, so the turns are at most
    // one per octet of the stream and the loop is bounded (non-negotiable 4).
    for (0..records.len + 1) |_| {
        if (delivered == records.len and pending_len == 0) break;
        if (delivered < records.len) {
            const left = records.len - delivered;
            const chunk = if (chunked) 1 + random.below(left) else left;
            @memcpy(storage.pending[pending_len .. pending_len + chunk], records[delivered .. delivered + chunk]);
            pending_len += chunk;
            delivered += chunk;
        }
        pending_len, held_len = try open_records(storage, pending_len, held_len);
    }
    assert(delivered == records.len and pending_len == 0);
}

/// Opens every whole record the pending octets hold, feeding what each yields to the connection.
/// RFC 9846 §5.1: a record that is not whole yet is not an error, and the caller reads more.
fn open_records(storage: *Storage, pending_len_in: usize, held_len_in: usize) Violation!struct { usize, usize } {
    var pending_len = pending_len_in;
    var held_len = held_len_in;
    // The loop is bounded by the records the pending octets can hold (non-negotiable 4).
    for (0..constants.tls_check_records_max + 1) |_| {
        const opened = h2.connection_tls.decrypt(
            &storage.connection,
            storage.pending[0..pending_len],
            &storage.plaintext,
            0,
        ) catch return error.OutcomeUnexpected;
        if (opened.consumed == 0) break;
        @memcpy(storage.held[held_len .. held_len + opened.plaintext_len], storage.plaintext[0..opened.plaintext_len]);
        held_len += opened.plaintext_len;
        std.mem.copyForwards(
            u8,
            storage.pending[0 .. pending_len - opened.consumed],
            storage.pending[opened.consumed..pending_len],
        );
        pending_len -= opened.consumed;
        held_len = try drain(storage, held_len);
    }
    return .{ pending_len, held_len };
}

/// Feeds what the records yielded to the connection, one frame at a time, until it consumes no
/// more, and reads the invariants after every frame (design §4.1).
fn drain(storage: *Storage, held_len_in: usize) Violation!usize {
    var held_len = held_len_in;
    // The loop is bounded by the frames one fixed stream carries (non-negotiable 4).
    for (0..constants.tls_check_events_max) |_| {
        // RFC 9113 §3.4: a connection reads the whole client preface before any frame.
        if (storage.connection.preface_read_len != h2_constants.client_preface_len and
            held_len < h2_constants.client_preface_len) return held_len;
        _ = storage.connection.write_pending(&storage.output, 0);
        const received = storage.connection.receive(storage.held[0..held_len], 0) catch
            return error.OutcomeUnexpected;
        if (received.consumed == 0) return held_len;
        std.mem.copyForwards(u8, storage.held[0 .. held_len - received.consumed], storage.held[received.consumed..held_len]);
        held_len -= received.consumed;
        if (storage.invariants.read(&storage.connection)) |broken| return broken;
        if (received.event) |event| storage.events.push(event);
    }
    return held_len;
}

/// What the check counted over every seed.
pub const Census = struct {
    seeds: u64 = 0,
    events: u64 = 0,
    records: u64 = 0,
    crc32: std.hash.Crc32 = std.hash.Crc32.init(),
};

/// Runs the check over `[0, seeds)` and fills `census`.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        // One record holding everything, delivered whole, is what every other run is compared
        // against.
        try run_once(storage, 0, false, seed);
        const whole: Events = storage.events;
        // RFC 9846 §5.1 and RFC 9113 §4.1: neither length divides the other, so where a record
        // ends must change nothing the connection decides, and neither must where a read ends.
        try run_once(storage, 1, false, seed);
        if (!std.mem.eql(u8, whole.written(), storage.events.written())) {
            return error.RecordCuttingChangedVerdict;
        }
        try run_once(storage, 1, true, seed);
        if (!std.mem.eql(u8, whole.written(), storage.events.written())) {
            return error.RecordCuttingChangedVerdict;
        }
        census.seeds += 1;
        census.events += storage.events.len;
        census.records += 1;
        census.crc32.update(storage.events.written());
    }
    assert(census.seeds == seeds);
}

var check_storage: Storage = .zeroed;

test "the records a stream is cut into change nothing the connection decides" {
    sim.NullProvider.install();
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("tls check: seed 0x{x} broke {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    try std.testing.expect(census.events > census.seeds);
    try std.testing.expectEqual(census_crc32_expected, census.crc32.final());
}
