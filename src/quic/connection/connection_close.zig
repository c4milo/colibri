//! The CONNECTION_CLOSE frame this endpoint sends (RFC 9000 §10.2, §10.2.3, §19.19).
//!
//! Reading the peer's belongs to `connection_frames.zig`. Writing colibri's own is here, and it
//! is the hole every other piece of step 9e left: each one names the connection error it found
//! and none of them could tell the peer.
//!
//! **Which packets carry it is the whole problem.** §10.2.3 states the goal — "the goal is to
//! ensure that the peer will process the frame" — and before the handshake is confirmed neither
//! side knows for certain which keys the other holds. So the frame goes in a packet at more than
//! one encryption level, §12.2 coalesces those into one datagram, and the caller pays for one
//! datagram rather than three.
//!
//! **A 0x1d frame cannot leave the application level.** §12.5 confines an application close to
//! the application packet number space, and §10.2.3 says what to send in its place: type 0x1c,
//! the Reason Phrase cleared and APPLICATION_ERROR as the code. `frame_for` is that conversion,
//! which is why a caller states the close once instead of once per level.
//!
//! **The Reason Phrase is the caller's octets and colibri copies none of them** (decision 35), so
//! a caller that gives one keeps it alive until the closing period ends. A close colibri raises
//! for itself carries none: §19.19 makes the field diagnostic and colibri has no text to put in
//! it that the code does not already say.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const frame_module = @import("../frame/frame.zig");
const frame_control = @import("../frame/frame_control.zig");
const connection_module = @import("connection.zig");
const keys_module = @import("connection_keys.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;

/// What this endpoint tells its peer (RFC 9000 §19.19). It is the frame's own struct, because
/// what colibri sends and what it reads are the same five fields.
pub const Close = frame_control.ConnectionClose;

/// The transport close colibri raises for a connection error it found itself (RFC 9000 §11.1).
/// `frame_type` is the frame that triggered it, or null when no frame did.
pub fn transport(code: u64, frame_type: ?u64) Close {
    return .{
        .layer = .transport,
        .error_code = code,
        // RFC 9000 §19.19: a 0x1c frame always carries the field, and "A value of 0 (equivalent
        // to the mention of the PADDING frame) is used when the frame type is unknown."
        .frame_type = frame_type orelse constants.frame_padding,
        // RFC 9000 §19.19: "This can be zero length if the sender chooses not to give details
        // beyond the Error Code value."
        .reason = "",
    };
}

/// Whether a packet at `level` carries the close (RFC 9000 §10.2.3).
pub fn carries(connection: *const Connection, level: Level) bool {
    if (connection.pending_close == null) return false;
    // RFC 9001 §4.9, invariant 21: a level colibri never installed keys for, or has discarded
    // them at, seals nothing — a close no more than anything else.
    if (!keys_module.can_seal(connection, level)) return false;
    // RFC 9000 §10.2.3: "After the handshake is confirmed (see Section 4.1.2 of [QUIC-TLS]), an
    // endpoint MUST send any CONNECTION_CLOSE frames in a 1-RTT packet."
    if (connection.handshake_confirmed) return level == .application;
    return switch (level) {
        .initial => carries_initial(connection),
        // RFC 9000 §10.2.3: "Prior to confirming the handshake, a peer might be unable to process
        // 1-RTT packets, so an endpoint SHOULD send a CONNECTION_CLOSE frame in both Handshake
        // and 1-RTT packets."
        .handshake, .application => true,
    };
}

/// Whether an Initial packet carries the close, before the handshake is confirmed (§10.2.3).
fn carries_initial(connection: *const Connection) bool {
    // RFC 9000 §10.2.3: "A server SHOULD also send a CONNECTION_CLOSE frame in an Initial
    // packet", because "it is possible that a server does not know whether the client has
    // Handshake keys", and one of the two will then be readable.
    if (connection.role == .server) return true;
    // A client is the other half of that sentence: it "will always know whether the server has
    // Handshake keys (see Section 17.2.2.1)", so it owes the server no second copy. It sends an
    // Initial only while that is the one packet it can send at all, which §10.2.3 admits —
    // "An endpoint can send a CONNECTION_CLOSE frame in an Initial packet."
    return !keys_module.can_seal(connection, .handshake);
}

/// The frame a packet at `level` carries, with RFC 9000 §10.2.3's replacement applied.
pub fn frame_for(pending: Close, level: Level) Close {
    // §12.5: an application close belongs to the application packet number space, and that is
    // the one level where what the caller asked for goes out unchanged.
    if (level == .application or pending.layer == .transport) return pending;
    // §10.2.3: "A CONNECTION_CLOSE of type 0x1d MUST be replaced by a CONNECTION_CLOSE of type
    // 0x1c when sending the frame in Initial or Handshake packets." And: "Endpoints MUST clear
    // the value of the Reason Phrase field and SHOULD use the APPLICATION_ERROR code when
    // converting to a CONNECTION_CLOSE of type 0x1c." Both are here and neither is optional to
    // colibri, because §10.2.3 gives the reason — "information about the application state might
    // be revealed".
    return .{
        .layer = .transport,
        .error_code = error_code.application_error,
        // §19.19: a transport close carries the Frame Type field and an application close does
        // not, so there is none to carry over. "A value of 0 (equivalent to the mention of the
        // PADDING frame) is used when the frame type is unknown."
        .frame_type = constants.frame_padding,
        .reason = "",
    };
}

/// Writes the close a packet at `level` carries into the front of `output`, and answers how many
/// octets it occupies. 0 means this packet carries none.
pub fn write(connection: *const Connection, level: Level, output: []u8) usize {
    const pending = connection.pending_close orelse return 0;
    if (!carries(connection, level)) return 0;
    const shaped = frame_for(pending, level);
    // Invariant 8: §12.5's rule is checked against the frame that is about to go out, not
    // against the one the caller stated, so the conversion above cannot be skipped silently.
    assert(frame_module.Frame.permitted_at(.{ .connection_close = shaped }, level));
    var writer = Writer.init(output);
    frame_module.write(&writer, .{ .connection_close = shaped }) catch
        return write_without_reason(shaped, output);
    return writer.written().len;
}

/// The frame again with its Reason Phrase dropped, for a packet that could not hold it.
///
/// RFC 9000 §19.19: "Because a CONNECTION_CLOSE frame cannot be split between packets, any limits
/// on packet size will also limit the space available for a reason phrase." The code is what the
/// peer acts on and the reason is diagnostic, so the reason gives way rather than the frame.
fn write_without_reason(shaped: Close, output: []u8) usize {
    if (shaped.reason.len == 0) return 0;
    var bare = shaped;
    bare.reason = "";
    var writer = Writer.init(output);
    frame_module.write(&writer, .{ .connection_close = bare }) catch return 0;
    return writer.written().len;
}

/// Records that this endpoint is closing the connection (RFC 9000 §10.2's immediate close). From
/// here every packet it sends carries the close and nothing else, until the closing period ends.
pub fn owe(connection: *Connection, what: Close) void {
    // RFC 9000 §10.2.2: "an endpoint in the draining state MUST NOT send any packets", so a
    // connection the peer already closed is not one to answer. §10.2.2's MAY — a single close
    // before entering draining — is declined: `on_close_received` enters draining at once.
    if (connection.termination.state != .active) return;
    // §10.2.1: a closing endpoint "retains only enough information to generate a packet
    // containing a CONNECTION_CLOSE frame", which is the first close and not the latest. A
    // second error found while closing changes nothing the peer will see.
    if (connection.pending_close != null) return;
    // §19.19: an application close carries no Frame Type field, so one must not be stated.
    assert(what.layer == .transport or what.frame_type == null);
    connection.pending_close = what;
}

/// Whether any packet this connection sends would carry a close (RFC 9000 §10.2.3). It writes
/// nothing, so the send path can ask before it decides how to fill a datagram.
pub fn owes(connection: *const Connection) bool {
    // Bounded by the levels, of which RFC 9001 §4.1.4 names three.
    for (0..core.levels_count) |index| {
        if (carries(connection, @enumFromInt(index))) return true;
    }
    return false;
}

test {
    _ = @import("connection_close_test.zig");
}
