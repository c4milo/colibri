//! The request content of the h11 half of a client connection (decision 100), split from
//! `connection_h11.zig` in design §8 step 39. Over TLS, the part of the content that fills the
//! record of the head goes into the connection's output. The rest goes from the caller's memory
//! into the caller's output, sealed over TLS, with no copy into the connection's output
//! (https://github.com/c4milo/colibri/issues/105, decision 139).
const std = @import("std");
const assert = std.debug.assert;
const tls_provider = @import("tls_provider");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");
const connection_tls = @import("connection_tls.zig");
const slots_module = @import("../slots.zig");

const Connection = connection_module.Connection;
const Slot = slots_module.Slot;

/// The written exchange whose content is still going out, or null. h11 writes the next head only
/// after it, so there is one at most (RFC 9112 §9.3.2).
pub fn writing(connection: *Connection) ?*Slot {
    for (&connection.slots.slots) |*slot| {
        if (slot.stage == .sent and !slot.content_done()) return slot;
    }
    return null;
}

/// Ends the body whose last octet went out. Returns whether the next head may follow.
pub fn end_content(connection: *Connection) bool {
    const session = &connection.session.h11;
    // RFC 9112 §6.2: a body of a declared length ends with its last octet, and the next head may
    // follow.
    if (session.writer.open()) connection.output_len += session.write_end(internal.room(connection), &.{}) catch return false;
    return true;
}

/// Writes into the output the part of `slot`'s content that fills the record of the head before
/// it, over TLS. `send_content` writes the rest from the caller's memory, with no copy into the
/// output (https://github.com/c4milo/colibri/issues/105).
pub fn write_content(connection: *Connection, slot: *Slot) void {
    const content = slot.request.body;
    const response = slot.response;
    const left = content.len - response.body_sent;
    const take = @min(left, internal.room(connection).len, internal.record_fill(connection));
    if (take == 0) return;
    const written = connection.session.h11.write_body(internal.room(connection), content[response.body_sent..][0..take]) catch {
        // RFC 9112 §9.6: the connection closed, and no more of the body goes out.
        slot.content_stopped = true;
        return;
    };
    connection.output_len += written;
    response.body_sent += take;
    assert(response.body_sent <= content.len);
}

/// Writes the content of the request going out from the caller's memory into `output`, sealed
/// over TLS, once the connection's own output is empty, and ends its body after its last octet.
/// Returns the octets written into `output` (https://github.com/c4milo/colibri/issues/105).
pub fn send_content(connection: *Connection, output: []u8, now_ns: u64) usize {
    assert(connection.output_len == 0);
    assert(connection.session == .h11);
    if (connection.stopped) return 0;
    const slot = writing(connection) orelse return 0;
    const response = slot.response;
    const content = slot.request.body[response.body_sent..];
    const sent: tls_provider.provider.Sealed = if (connection.config.tls == null)
        copy_content(content, output)
    else
        connection_tls.seal_content(connection, content, output, now_ns);
    // A record that failed ended the connection and every exchange it held.
    if (sent.consumed == 0) return sent.written;
    // The head declared the body's length, and the octets sent stay within it (decision 95).
    connection.session.h11.count_body(sent.consumed) catch unreachable;
    response.body_sent += sent.consumed;
    assert(response.body_sent <= slot.request.body.len);
    if (slot.content_done()) _ = end_content(connection);
    return sent.written;
}

/// Copies as much of `content` as `output` holds, in cleartext.
fn copy_content(content: []const u8, output: []u8) tls_provider.provider.Sealed {
    const take = @min(content.len, output.len);
    @memcpy(output[0..take], content[0..take]);
    return .{ .consumed = take, .written = take };
}
