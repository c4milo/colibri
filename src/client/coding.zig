//! Content codings at the client (decision 101, design §8 steps 17e and 17h). A client whose
//! configuration names codings, and a pool of decoders for each, offers the codings in each
//! request's Accept-Encoding, in its order of preference. As it writes the request it takes a
//! decoder from the pool of each coding it offers, so the response always finds one, and it
//! offers no coding whose pool has none free. It decodes a response whose Content-Encoding names
//! one coding it offered into the exchange's body, gives back the decoders the response did not
//! need, and passes any other content on as it arrived, with the field.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const h11 = @import("h11");
const slots_module = @import("slots.zig");
const coding_pool = @import("coding_pool.zig");

pub const Coding = http.content_coding.Coding;
const Slot = slots_module.Slot;
const FieldSection = http.FieldSection;

/// Octets of the Accept-Encoding value the client writes at most: each coding it decodes, and a
/// weight after each but the first.
pub const offer_len_max: usize = 64;

pub const Error = error{
    /// The decoded content passed the exchange's `body`.
    NoSpaceLeft,
    /// The coded content breaks its format (RFC 1950, 1951, 1952, 8878, 7932), uses a feature
    /// stdx refuses, such as a window past the limit, ends before its stream does, or goes on
    /// past it.
    CodingCorrupt,
};

/// The pools a connection decodes with, as its configuration names them (decision 101 as
/// amended): h11's for `gzip` and `deflate`, and one each for `zstd` and `br`.
pub const Pools = struct {
    deflate: ?h11.coding.Storage = null,
    zstd: ?coding_pool.ZstdDecoders = null,
    br: ?coding_pool.BrotliDecoders = null,

    /// The pools of a client configuration, TCP's or QUIC's.
    pub fn of(config: anytype) Pools {
        return .{ .deflate = config.decoders, .zstd = config.zstd_decoders, .br = config.br_decoders };
    }

    fn has(pools: Pools, coding: Coding) bool {
        return switch (coding) {
            .gzip, .deflate => pools.deflate != null,
            .zstd => pools.zstd != null,
            .br => pools.br != null,
        };
    }
};

/// Whether a configuration's codings and pools agree: it names each coding once at most, each
/// coding it names has its pool, and each pool it gives serves a coding it names. A connection
/// asserts it as it starts.
pub fn codings_valid(codings: []const Coding, pools: Pools) bool {
    var named: std.EnumSet(Coding) = .initEmpty();
    for (codings) |coding| {
        if (named.contains(coding) or !pools.has(coding)) return false;
        named.insert(coding);
    }
    if (pools.deflate != null and !names(codings, .gzip) and !names(codings, .deflate)) return false;
    if (pools.zstd != null and !names(codings, .zstd)) return false;
    return pools.br == null or names(codings, .br);
}

fn names(codings: []const Coding, coding: Coding) bool {
    return std.mem.indexOfScalar(Coding, codings, coding) != null;
}

/// The Accept-Encoding value for `slot`'s request, written into `into`, with a decoder taken for
/// each coding it names; or null when the client offers nothing: its configuration names no
/// codings, the caller's request names Accept-Encoding itself, or every pool is out of decoders.
pub fn offer(codings: []const Coding, pools: Pools, slot: *Slot, into: *[offer_len_max]u8) ?[]const u8 {
    if (codings.len == 0) return null;
    // Decision 101: a request that names Accept-Encoding goes out as its caller wrote it.
    for (slot.exchange.fields) |field| {
        if (http.field.names_equal(field.name, accept_encoding)) return null;
    }
    assert(codings.len <= codings_max);
    var offered: [codings_max]Coding = undefined;
    var offered_len: usize = 0;
    for (codings) |coding| {
        // Decision 101 as amended: a coding whose pool has no decoder free is not offered.
        if (!reserve(slot, pools, coding)) continue;
        slot.offered.insert(coding);
        offered[offered_len] = coding;
        offered_len += 1;
    }
    if (offered_len == 0) return null;
    return write_offer(offered[0..offered_len], into);
}

/// The codings the client decodes, each of which an offer names once at most.
const codings_max = std.enums.values(Coding).len;

/// Takes a decoder of `coding` for the slot's response, or finds one it took already, and returns
/// false when the coding's pool has none free. `gzip` and `deflate` share one decoder, and a head
/// that waits for room offers again with the decoders its first try took.
fn reserve(slot: *Slot, pools: Pools, coding: Coding) bool {
    switch (coding) {
        .gzip, .deflate => {
            if (slot.decoders != null) return true;
            const storage = pools.deflate.?;
            if (!h11.coding.reserve(&slot.decoding, storage)) return false;
            slot.decoders = storage;
            return true;
        },
        .zstd => return slot.zstd.holds() or slot.zstd.reserve(pools.zstd.?),
        .br => return slot.br.holds() or slot.br.reserve(pools.br.?),
    }
}

/// "gzip, deflate;q=0.9": each coding after the first weighs a tenth less, so a server that has
/// several follows the client's order (RFC 9110 §12.5.3, §12.4.2).
fn write_offer(codings: []const Coding, into: *[offer_len_max]u8) []const u8 {
    assert(codings.len > 0 and codings.len <= weight_steps);
    var len: usize = 0;
    for (codings, 0..) |coding, index| {
        if (index > 0) len += copy(into[len..], list_separator);
        len += copy(into[len..], coding.name());
        if (index == 0) continue;
        const weight = http.content_coding.weight_max - index * weight_step;
        len += (std.fmt.bufPrint(into[len..], ";q=0.{d}", .{weight / weight_step}) catch unreachable).len;
    }
    return into[0..len];
}

/// What each coding after the first weighs less, in thousandths, and the most codings that leaves
/// a nonzero weight for.
const weight_step: usize = 100;
const weight_steps: usize = http.content_coding.weight_max / weight_step - 1;

fn copy(into: []u8, text: []const u8) usize {
    @memcpy(into[0..text.len], text);
    return text.len;
}

const accept_encoding = "accept-encoding";
const content_encoding = "content-encoding";
/// RFC 9110 §5.6.1: a sender separates list elements with a comma and a space.
const list_separator = ", ";

/// Whether the slot holds a decoder, reserved or decoding.
fn holds_any(slot: *const Slot) bool {
    return slot.decoders != null or slot.zstd.holds() or slot.br.holds();
}

/// Whether the slot decodes its response's content.
pub fn active(slot: *const Slot) bool {
    return slot.decoding.active() or slot.zstd.active or slot.br.active;
}

/// Reads what the final response's Content-Encoding says of its content, in the regular field
/// lines of `section` from `first`. It starts the decoder of the coding they name, when it is one
/// the client offered, and gives back every other decoder the slot holds.
pub fn begin(slot: *Slot, status: u16, section: *const FieldSection, first: u32) void {
    if (!holds_any(slot)) return;
    const coding = decodable(slot, status, section, first) orelse return slots_module.give_back(slot);
    switch (coding) {
        .gzip, .deflate => {
            h11.coding.begin(&slot.decoding, slot.decoders.?, if (coding == .gzip) .gzip else .deflate);
            slot.zstd.release();
            slot.br.release();
        },
        .zstd => {
            slot.zstd.begin();
            give_back_deflate(slot);
            slot.br.release();
        },
        .br => {
            slot.br.begin();
            give_back_deflate(slot);
            slot.zstd.release();
        },
    }
    slot.exchange.coding = coding;
}

fn give_back_deflate(slot: *Slot) void {
    const storage = slot.decoders orelse return;
    h11.coding.release(&slot.decoding, storage);
    slot.decoders = null;
}

/// The coding the client removes from a final response's content, or null for content it passes
/// on as it arrived.
fn decodable(slot: *const Slot, status: u16, section: *const FieldSection, first: u32) ?Coding {
    // RFC 9110 §14.1.2: a 206's ranges count the coded octets, and part of a coded stream does
    // not decode alone.
    if (status == partial_content) return null;
    var named: ?Coding = null;
    var lines: http.field_section.Iterator = .{ .section = section, .index = first };
    // Bounded by the section's lines.
    for (0..section.len()) |_| {
        const line = lines.next() orelse break;
        if (!http.field.names_equal(line.name, content_encoding)) continue;
        // Decision 101: content coded twice goes on as it arrived (RFC 9110 §8.4).
        if (named != null) return null;
        named = one_coding(line.value) orelse return null;
    }
    const coding = named orelse return null;
    // Decision 101: the client decodes only a coding its request offered, for which it holds a
    // decoder.
    if (!slot.offered.contains(coding)) return null;
    return coding;
}

const partial_content: u16 = @intFromEnum(http.status.Code.partial_content);

/// The one coding a Content-Encoding value names, or null when it names another or more than one:
/// a list of codings, applied in order (RFC 9110 §8.4), is no name `from_name` knows.
fn one_coding(value: []const u8) ?Coding {
    // RFC 9110 §8.4.1.3: "x-gzip" is gzip.
    return http.content_coding.from_name(std.mem.trim(u8, value, whitespace));
}

/// RFC 9110 §5.6.3: optional whitespace is spaces and horizontal tabs.
const whitespace = " \t";

/// Decodes the coded `octets` into the exchange's body, after the octets already there.
pub fn decode(slot: *Slot, octets: []const u8) Error!void {
    assert(active(slot));
    const exchange = slot.exchange;
    slot.coded_len += octets.len;
    var taken: usize = 0;
    // The last octets of a stream, its checksum, decode to nothing, so they are fed with room for
    // one octet that must stay unwritten.
    var spill: [1]u8 = undefined;
    // Bounded: each pass takes an octet or writes one, and the body holds `body.len`.
    for (0..octets.len + exchange.body.len + 1) |_| {
        if (taken == octets.len) return;
        const room = exchange.body[exchange.body_len..];
        const output = if (room.len > 0) room else &spill;
        const progress = try step(slot, octets[taken..], output);
        if (room.len == 0 and progress.written > 0) return error.NoSpaceLeft;
        taken += progress.consumed;
        exchange.body_len += progress.written;
    }
    unreachable;
}

/// One call into the decoder the slot's response took.
fn step(slot: *Slot, input: []const u8, output: []u8) Error!h11.coding.Progress {
    if (slot.decoding.active()) {
        return h11.coding.decode(&slot.decoding, slot.decoders.?, input, output) catch {
            // RFC 1950 §2.2, RFC 1951 §3.2 and RFC 1952 §2.3: content that breaks its coding's
            // format fails the response (decision 101).
            return error.CodingCorrupt;
        };
    }
    if (slot.zstd.active) return slot.zstd.decode(input, output);
    assert(slot.br.active);
    return slot.br.decode(input, output);
}

/// The response's content ended. Coded content must end with its stream (RFC 1950 §2.2, RFC 1952
/// §2.3, RFC 8878 §3.1.1, RFC 7932 §9.2), and the decoder goes back. A response with no content,
/// such as one to HEAD, decoded nothing, and names no coding removed.
pub fn end(slot: *Slot) Error!void {
    if (!active(slot)) return;
    if (slot.coded_len == 0) {
        slots_module.give_back(slot);
        slot.exchange.coding = null;
        return;
    }
    if (slot.decoding.active()) {
        const storage = slot.decoders.?;
        slot.decoders = null;
        // RFC 1950 §2.2 and RFC 1952 §2.3: a stream ends with its checksum, so content that ends
        // before it is corrupt.
        h11.coding.finish(&slot.decoding, storage) catch return error.CodingCorrupt;
        return;
    }
    if (slot.zstd.active) return slot.zstd.finish();
    return slot.br.finish();
}

const testing = std.testing;

test "a configuration names each coding once, each with its pool, and gives no pool it names no coding for" {
    var deflate_header: h11.coding.Header = undefined;
    var zstd_header: coding_pool.Header = undefined;
    var br_header: coding_pool.Header = undefined;
    var deflate_slots: [0]h11.coding.Slot = .{};
    var zstd_slots: [0]coding_pool.Slot(coding_pool.Zstd.Decoder) = .{};
    var br_slots: [0]coding_pool.Slot(coding_pool.Brotli.Decoder) = .{};
    const all: Pools = .{
        .deflate = .{ .header = &deflate_header, .slots = &deflate_slots },
        .zstd = .{ .header = &zstd_header, .slots = &zstd_slots },
        .br = .{ .header = &br_header, .slots = &br_slots },
    };
    try testing.expect(codings_valid(&.{ .zstd, .br, .gzip, .deflate }, all));
    try testing.expect(codings_valid(&.{}, .{}));
    // A coding named twice, which would overflow the offer.
    try testing.expect(!codings_valid(&.{ .br, .zstd, .br, .gzip }, all));
    // A coding with no pool.
    try testing.expect(!codings_valid(&.{ .zstd, .br, .gzip }, .{ .zstd = all.zstd, .br = all.br }));
    // A pool for no coding named: `gzip` and `deflate`'s, `zstd`'s and `br`'s.
    try testing.expect(!codings_valid(&.{ .zstd, .br }, all));
    try testing.expect(!codings_valid(&.{ .br, .gzip }, all));
    try testing.expect(!codings_valid(&.{ .zstd, .deflate }, all));
}
