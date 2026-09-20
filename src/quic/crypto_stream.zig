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

    /// A stream with nothing received. RFC 9000 §19.6: each level starts at an offset of 0.
    pub fn init(stream: *CryptoStream) void {
        stream.base = 0;
        stream.contiguous = 0;
        stream.present = .initEmpty();
        assert(stream.readable().len == 0);
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

    /// How many octets the handshake has read from this level, which is where the next frame
    /// colibri sends on it begins.
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
