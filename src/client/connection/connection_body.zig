//! The pieces of a streamed response on a TCP connection (decision 153 ruling 7, design §8 step
//! 39f). h11 and h2 copy each run of the response's content into the caller's `Response.body`, and
//! the caller holds it until `release_body`. The connection reads no more of the response, nor of
//! any other, while the caller holds a piece: h11 reads its responses in order (RFC 9112 §9.2), and
//! h2 reads nothing more of the connection.
//!
//! A run longer than `Response.body` leaves a tail: the octets after the piece, which the protocol
//! read and the caller has not had. The connection does not count them as taken, so they wait at
//! the front of the next call's octets: the caller's input in cleartext, and the opened records
//! over TLS. Once the caller releases the piece, the next pieces come from the tail, and the
//! protocol reads on after it.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");
const slots_module = @import("../slots.zig");
const response_write = @import("../response_write.zig");
const connection_module = @import("connection.zig");
const connection_h2 = @import("connection_h2.zig");

const Connection = connection_module.Connection;
const Slot = slots_module.Slot;

/// The rest of a run of content that did not fit the caller's `Response.body`.
pub const Tail = struct {
    /// The exchange the octets are for.
    id: event.RequestId = 0,
    /// Octets of content left, at the front of the next call's octets.
    len: usize = 0,
    /// Octets the protocol read after the content, which carry none: h2's padding (RFC 9113
    /// §6.1).
    skip_len: usize = 0,
    /// The content ends with the tail: h2's DATA frame carried END_STREAM (RFC 9113 §8.1).
    ends: bool = false,

    /// Whether octets of the tail wait to be taken.
    pub fn pending(tail: *const Tail) bool {
        return tail.len > 0 or tail.skip_len > 0;
    }
};

/// Holds the first piece of `octets`, a run of `slot`'s streamed content that the protocol read,
/// and keeps what does not fit as the tail. Returns the octets of the tail: the caller does not
/// count them as taken.
pub fn hold(connection: *Connection, slot: *Slot, octets: []const u8) usize {
    assert(!connection.tail.pending());
    assert(octets.len > 0);
    const held = response_write.hold_piece(slot, octets);
    connection.tail = .{ .id = slot.id, .len = octets.len - held };
    return connection.tail.len;
}

/// Takes the tail from the front of `plaintext`: the next piece of its exchange, then the octets to
/// skip. Returns the octets taken. A call with no octets waits for the caller to pass them again.
pub fn read_tail(connection: *Connection, plaintext: []const u8) usize {
    const tail = &connection.tail;
    assert(tail.pending());
    if (plaintext.len == 0) return 0;
    const slot = connection.slots.of_id(tail.id);
    var taken: usize = 0;
    if (tail.len > 0) {
        taken = take_content(slot, plaintext[0..@min(tail.len, plaintext.len)]);
        tail.len -= taken;
    }
    if (tail.len == 0) {
        const skipped = @min(tail.skip_len, plaintext.len - taken);
        tail.skip_len -= skipped;
        taken += skipped;
        if (!tail.pending() and tail.ends) end_content(connection, slot);
    }
    connection.unread_len = plaintext.len - taken;
    assert(taken > 0);
    return taken;
}

/// Takes `octets` of the tail: the next piece of a streamed response, or, of an exchange the
/// caller cancelled, octets read and dropped. Returns the octets taken.
fn take_content(slot: ?*Slot, octets: []const u8) usize {
    const owner = slot orelse return octets.len;
    switch (owner.stage) {
        .sent => return response_write.hold_piece(owner, octets),
        // h11 reads the rest of a cancelled response and drops it (decision 146).
        .dropping => {
            owner.dropped_len += octets.len;
            return octets.len;
        },
        // The connection ends its exchanges only when it reads nothing more.
        .free, .queued, .ended => unreachable,
    }
}

/// The tail was the last of the content: h2's END_STREAM ends the response (RFC 9113 §8.1). An
/// exchange the caller cancelled reports nothing.
fn end_content(connection: *Connection, slot: ?*Slot) void {
    connection.tail = .{};
    const owner = slot orelse return;
    if (owner.stage != .sent) return;
    _ = connection_h2.finish(connection, owner);
}

/// The caller gave back the piece of exchange `id` its `Response.body` held. Over h2 the stream's
/// credit for it goes back (RFC 9113 §6.9), and the connection reads on.
pub fn release(connection: *Connection, id: event.RequestId) void {
    // The pool releases only a piece the connection reported.
    const slot = connection.slots.of_id(id).?;
    const len = response_write.release_piece(slot);
    // RFC 9113 §5.4.1: a connection that failed sends nothing more.
    if (connection.stopped or connection.session != .h2) return;
    // RFC 9113 §6.9.1: the piece's octets of the stream's window, which colibri gave back none of
    // at receipt (`hold_credit`).
    connection.session.h2.release_stream(@intCast(slot.stream_id), @intCast(len));
}
