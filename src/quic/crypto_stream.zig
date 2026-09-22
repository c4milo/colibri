//! The CRYPTO streams of RFC 9000 §19.6: one ordered flow of handshake octets per encryption
//! level, reassembled from the frames that carried them.
//!
//! §19.6 makes each encryption level "a separate CRYPTO stream of data", each starting at offset
//! 0. A frame names an offset and its octets, frames arrive in any order and a lost one is
//! retransmitted, so the same octets may arrive twice. What the handshake needs is the opposite:
//! an in-order run it can read and then forget.
//!
//! **A CRYPTO stream is not a STREAM.** `src/quic/stream/` cannot serve here and the differences
//! are not cosmetic: a CRYPTO stream has no identifier, no FIN, no flow control and no final
//! size, so none of §3.2's receiving states or §4.5's final-size rules apply to it. What it has
//! instead is §7.5's buffer limit, which is the only thing bounding what a peer can make colibri
//! hold, because "there is no flow control of CRYPTO frames".
//!
//! **The window is anchored at what the handshake has taken.** `buffer[0]` is the octet at
//! `base`, every octet below `base` has been read and forgotten, and `contiguous` counts the
//! octets from `base` that are present with no gap. So `readable` is the run the handshake may
//! read now, and `consume` slides the window forward. Data past the window is more than §7.5
//! obliges colibri to buffer and is a connection error of CRYPTO_BUFFER_EXCEEDED.
const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("crypto");
const constants = @import("constants.zig");

/// Why a peer's CRYPTO data is refused.
pub const Error = error{
    /// RFC 9000 §7.5: more out-of-order data than colibri buffers. "If an endpoint does not
    /// expand its buffer, it MUST close the connection with a CRYPTO_BUFFER_EXCEEDED error code",
    /// and `error_code.crypto_buffer_exceeded` is what the connection sends.
    CryptoBufferExceeded,
};

/// One encryption level's flow of handshake octets (RFC 9000 §19.6).
pub const CryptoStream = struct {
    /// The stream offset of `buffer[0]`: every octet below it has been read and forgotten.
    base: u64,
    /// Octets from `base` that are present with no gap, which is what `readable` returns.
    contiguous: usize,
    /// The window of octets at and above `base` (RFC 9000 §7.5).
    buffer: [constants.crypto_buffer_len]u8,
    /// Which octets of `buffer` a frame has delivered. A bit rather than a byte each, because
    /// the byte would cost eight times the window per level and hold one answer.
    present: std.StaticBitSet(constants.crypto_buffer_len),
    /// Octets colibri has sent on this level, which is the Offset the next CRYPTO frame it writes
    /// carries (RFC 9000 §19.6). The two directions are separate flows at one level, so the
    /// sending side sits beside the receiving window rather than in a struct of its own.
    sent_len: u64,
    /// The stream offset of `send_buffer[0]`: octets below it were framed and then forgotten.
    send_base: u64,
    /// Octets the provider has produced at this level, as an offset in the same flow.
    produced_len: u64,
    /// What was produced and not yet forgotten. RFC 9000 §13.3 retransmits a lost frame's octets
    /// under a new packet number, and §17.2.5.3 has a client repeat its first flight after a
    /// Retry; both read this rather than asking the provider, which has given the octets up.
    send_buffer: [constants.crypto_send_buffer_len]u8,

    /// A stream with nothing received. RFC 9000 §19.6: each level starts at an offset of 0.
    pub fn init(stream: *CryptoStream) void {
        stream.base = 0;
        stream.contiguous = 0;
        stream.present = .initEmpty();
        stream.sent_len = 0;
        stream.send_base = 0;
        stream.produced_len = 0;
        assert(stream.readable().len == 0);
        assert(stream.unsent().len == 0);
    }

    /// Where the provider may write more of this level's flow. Empty when everything produced is
    /// still waiting to be framed, which is the window doing its job.
    pub fn send_room(stream: *CryptoStream) []u8 {
        stream.forget_framed();
        const held: usize = @intCast(stream.produced_len - stream.send_base);
        return stream.send_buffer[held..];
    }

    /// Records that the provider wrote `len` octets into `send_room`.
    pub fn produced(stream: *CryptoStream, len: usize) void {
        assert(stream.produced_len + len - stream.send_base <= stream.send_buffer.len);
        stream.produced_len += len;
        assert(stream.produced_len >= stream.sent_len);
    }

    /// The octets the next CRYPTO frame carries: produced at this level and not yet framed.
    pub fn unsent(stream: *const CryptoStream) []const u8 {
        const from: usize = @intCast(stream.sent_len - stream.send_base);
        const to: usize = @intCast(stream.produced_len - stream.send_base);
        return stream.send_buffer[from..to];
    }

    /// Records that `len` octets of `unsent` went into a CRYPTO frame, which advances the Offset
    /// the next one carries (RFC 9000 §19.6).
    pub fn framed(stream: *CryptoStream, len: usize) void {
        assert(len <= stream.unsent().len);
        stream.sent_len += len;
        assert(stream.sent_len <= stream.produced_len);
    }

    /// Whether this level's flow can be sent again from offset 0, which RFC 9000 §17.2.5.3 asks
    /// of a client after a Retry: "A client MUST use the same cryptographic handshake message it
    /// included in this packet." False when the window no longer reaches 0, which is a flight
    /// larger than it.
    pub fn can_rewind(stream: *const CryptoStream) bool {
        return stream.send_base == 0;
    }

    /// RFC 9000 §13.3: "Data sent in CRYPTO frames is retransmitted according to the rules in
    /// [QUIC-RECOVERY], until all data has been acknowledged." A packet that carried octets from
    /// `offset` was declared lost, so the flow is framed again from there.
    ///
    /// Answers false when the window no longer reaches that far, which is a flight longer than it
    /// whose early octets were forgotten. §13.3 has no answer for that and the caller ends the
    /// connection; a handshake that fits the window never meets it.
    pub fn on_lost(stream: *CryptoStream, offset: u64) bool {
        if (offset < stream.send_base) return false;
        // Octets already being sent again from a lower offset cover this one. §13.3 permits
        // sending more than was lost — "a receiver MUST accept packets containing an outdated
        // frame" — so the lowest rewind wins and nothing is tracked per packet.
        if (offset < stream.sent_len) stream.sent_len = offset;
        assert(stream.sent_len >= stream.send_base);
        assert(stream.sent_len <= stream.produced_len);
        return true;
    }

    /// Sends this level's flow again from the start (RFC 9000 §17.2.5.3). The octets are the ones
    /// already produced, so the provider is not asked for them twice.
    pub fn rewind(stream: *CryptoStream) void {
        assert(stream.can_rewind());
        stream.sent_len = 0;
        assert(stream.unsent().len == stream.produced_len);
    }

    /// Forgets the octets already framed, and only when the window has no room left. RFC 9000
    /// §13.3's retransmission and §17.2.5.3's repeat can reach only what the window still holds,
    /// so this runs as late as it can and a flight that fits is never forgotten.
    fn forget_framed(stream: *CryptoStream) void {
        if (stream.produced_len - stream.send_base < stream.send_buffer.len) return;
        const forget: usize = @intCast(stream.sent_len - stream.send_base);
        if (forget == 0) return;
        const kept: usize = @intCast(stream.produced_len - stream.sent_len);
        std.mem.copyForwards(u8, stream.send_buffer[0..kept], stream.send_buffer[forget..][0..kept]);
        stream.send_base = stream.sent_len;
        assert(stream.unsent().len == kept);
    }

    /// Takes one CRYPTO frame's octets. Data already read is dropped, data that overlaps what is
    /// buffered is written again with the same value, and a gap is held until it is filled.
    pub fn receive(stream: *CryptoStream, offset: u64, data: []const u8) Error!void {
        // RFC 9000 §19.6: the sum of the offset and the length cannot exceed 2^62-1, which the
        // frame reader has already refused, so this addition cannot wrap.
        assert(offset <= constants.stream_offset_max - data.len);
        if (data.len == 0) return;
        const end = offset + data.len;
        // Wholly below the window: every octet was read already, which a retransmission of an
        // acknowledged frame produces (RFC 9002 §6.2).
        if (end <= stream.base) return;
        // Past the window: §7.5 obliges colibri to buffer 4096 octets of out-of-order data and
        // this is more, so the connection ends rather than the buffer growing.
        if (end > stream.base + stream.buffer.len) return Error.CryptoBufferExceeded;
        stream.write_within(offset, data);
        stream.advance();
    }

    /// Copies the part of `data` at or above `base` into the window.
    fn write_within(stream: *CryptoStream, offset: u64, data: []const u8) void {
        const from = @max(offset, stream.base);
        const skipped: usize = @intCast(from - offset);
        const source = data[skipped..];
        const start: usize = @intCast(from - stream.base);
        assert(start + source.len <= stream.buffer.len);
        @memcpy(stream.buffer[start..][0..source.len], source);
        // Bounded by the window, which `receive` has already held the frame inside.
        for (start..start + source.len) |index| stream.present.set(index);
    }

    /// Extends the in-order run over every octet now present at its end.
    fn advance(stream: *CryptoStream) void {
        // Bounded by the window: every turn moves one octet and the window is fixed.
        while (stream.contiguous < stream.buffer.len and stream.present.isSet(stream.contiguous)) {
            stream.contiguous += 1;
        }
    }

    /// The octets the handshake may read now: every one from `base` with no gap before it.
    pub fn readable(stream: *const CryptoStream) []const u8 {
        return stream.buffer[0..stream.contiguous];
    }

    /// Forgets the first `len` octets of `readable`, sliding the window forward by that much.
    pub fn consume(stream: *CryptoStream, len: usize) void {
        assert(len <= stream.contiguous);
        if (len == 0) return;
        const kept = stream.buffer.len - len;
        std.mem.copyForwards(u8, stream.buffer[0..kept], stream.buffer[len..]);
        // Bounded by the window, twice: what moves down and what is cleared behind it.
        for (0..kept) |index| stream.present.setValue(index, stream.present.isSet(index + len));
        for (kept..stream.buffer.len) |index| stream.present.unset(index);
        stream.base += len;
        stream.contiguous -= len;
        assert(stream.readable().len == stream.contiguous);
    }

    /// How many octets the handshake has read out of the peer's flow at this level. It is the
    /// receiving side's mark and has nothing to do with the Offset colibri writes, which is
    /// `sent_len`: RFC 9000 §19.6 gives each direction of a level its own flow.
    pub fn consumed_len(stream: *const CryptoStream) u64 {
        return stream.base;
    }
};

/// The three streams of a connection, one per encryption level (RFC 9000 §19.6). 0-RTT is not one
/// of them: decision 20 refuses it, and RFC 9000 §19.6 forbids a CRYPTO frame in a 0-RTT packet.
pub const Levels = struct {
    streams: [constants.packet_number_spaces]CryptoStream,

    pub fn init(levels: *Levels) void {
        for (&levels.streams) |*stream| stream.init();
    }

    /// The stream a packet at `level` carries CRYPTO frames on.
    pub fn at(levels: *Levels, level: crypto.suite.Level) *CryptoStream {
        return &levels.streams[@intFromEnum(level)];
    }

    pub fn at_const(levels: *const Levels, level: crypto.suite.Level) *const CryptoStream {
        return &levels.streams[@intFromEnum(level)];
    }
};

comptime {
    // One stream per encryption level, and `Level` is what names them.
    assert(constants.packet_number_spaces == @typeInfo(crypto.suite.Level).@"enum".fields.len);
}

test {
    _ = @import("crypto_stream_test.zig");
}
