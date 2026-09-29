//! Content codings at the client (decision 101, design §8 step 17e). A client whose configuration
//! names codings and a pool of decoders offers the codings in each request's Accept-Encoding, in
//! its order of preference, and takes a decoder as it writes the request, so the response always
//! finds one. It decodes a response whose Content-Encoding names one coding it offered into the
//! exchange's body, and passes any other on as it arrived, with the field.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const h11 = @import("h11");
const slots_module = @import("slots.zig");

pub const Coding = http.content_coding.Coding;
const Slot = slots_module.Slot;
const FieldSection = http.FieldSection;

/// Octets of the Accept-Encoding value the client writes at most: each coding it decodes, and a
/// weight after each but the first.
pub const offer_len_max: usize = 64;

pub const Error = error{
    /// The decoded content passed the exchange's `body`.
    NoSpaceLeft,
    /// The coded content breaks its format (RFC 1950, 1951, 1952), uses a feature stdx refuses,
    /// or ends before its stream does.
    CodingCorrupt,
};

/// The Accept-Encoding value for `slot`'s request, written into `into`, with a decoder taken for
/// its response; or null when the client offers nothing: its configuration names no codings, the
/// caller's request names Accept-Encoding itself, or every decoder is taken.
pub fn offer(codings: []const Coding, decoders: ?h11.coding.Storage, slot: *Slot, into: *[offer_len_max]u8) ?[]const u8 {
    const storage = decoders orelse return null;
    // Decision 101: a request that names Accept-Encoding goes out as its caller wrote it.
    for (slot.exchange.fields) |field| {
        if (http.field.names_equal(field.name, accept_encoding)) return null;
    }
    if (slot.decoders == null) {
        // Decision 101: with every decoder taken, the client offers nothing.
        if (!h11.coding.reserve(&slot.decoding, storage)) return null;
        slot.decoders = storage;
    }
    return write_offer(codings, into);
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

/// Reads what the final response's Content-Encoding says of its content, in the regular field
/// lines of `section` from `first`. It starts the decoder on the content when they name one coding
/// the client offered, and gives the decoder back otherwise.
pub fn begin(slot: *Slot, codings: []const Coding, status: u16, section: *const FieldSection, first: u32) void {
    const storage = slot.decoders orelse return;
    const coding = decodable(codings, status, section, first) orelse return slots_module.give_back(slot);
    h11.coding.begin(&slot.decoding, storage, switch (coding) {
        .gzip => .gzip,
        .deflate => .deflate,
    });
    slot.exchange.coding = coding;
}

/// The coding the client removes from a final response's content, or null for content it passes
/// on as it arrived.
fn decodable(codings: []const Coding, status: u16, section: *const FieldSection, first: u32) ?Coding {
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
    // Decision 101: the client decodes only a coding it offered.
    for (codings) |offered| {
        if (offered == coding) return coding;
    }
    return null;
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
    const storage = slot.decoders.?;
    assert(slot.decoding.active());
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
        const progress = h11.coding.decode(&slot.decoding, storage, octets[taken..], output) catch {
            // RFC 1950 §2.2, RFC 1951 §3.2 and RFC 1952 §2.3: content that breaks its coding's
            // format fails the response (decision 101).
            return error.CodingCorrupt;
        };
        if (room.len == 0 and progress.written > 0) return error.NoSpaceLeft;
        taken += progress.consumed;
        exchange.body_len += progress.written;
    }
    unreachable;
}

/// The response's content ended. Coded content must end with its stream (RFC 1950 §2.2, RFC 1952
/// §2.3), and the decoder goes back. A response with no content, such as one to HEAD, decoded
/// nothing, and names no coding removed.
pub fn end(slot: *Slot) Error!void {
    const storage = slot.decoders orelse return;
    if (!slot.decoding.active()) return;
    slot.decoders = null;
    if (slot.coded_len == 0) {
        h11.coding.release(&slot.decoding, storage);
        slot.exchange.coding = null;
        return;
    }
    // RFC 1950 §2.2 and RFC 1952 §2.3: a stream ends with its checksum, so content that ends
    // before it is corrupt.
    h11.coding.finish(&slot.decoding, storage) catch return error.CodingCorrupt;
}
