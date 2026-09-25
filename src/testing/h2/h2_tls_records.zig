//! The record half of h2 over TLS, which design §9's h2 server (`h2_tls.zig`) and h2 client
//! (`h2_client_tls.zig`) share once their handshakes complete. Part of design §8 step 5.
//!
//! `step` does three things in order, each bounded by the buffers:
//!   1. opens whole records into h2's byte stream while there is room for one;
//!   2. steps the session over the byte stream, as the cleartext endpoint does;
//!   3. seals what the session wrote, as much as the socket's output holds, and once the session
//!      is done and every octet is sealed, the `close_notify` RFC 9846 §6.1 requires.
//!
//! Every octet crosses `connection_tls`'s `decrypt` and `encrypt`, so what the provider does with
//! a record is the provider's, and the endpoint around this file never sees plaintext.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const tls = @import("tls");
const constants = @import("../constants.zig");

const connection_tls = h2.connection_tls;

pub const Error = error{
    /// A record did not open or did not seal (RFC 9846 §6).
    TlsFailed,
};

/// What one step did to the socket's buffers.
pub const Step = struct {
    /// Octets of the socket's input taken.
    consumed: usize,
    /// Octets written into the socket's output, to be sent in order.
    written: usize,
    /// Whether the connection is finished and everything it owes is written.
    done: bool,
};

/// The record half of one connection. Its methods take the session as `anytype`: either of design
/// §9's h2 sessions, each of which has a `connection`, a `now_ns` and a `step` that answers the
/// octets it consumed and wrote and whether it is done.
pub const Records = struct {
    /// h2's byte stream, opened from records and not yet consumed by the session.
    plain_in: [constants.tls_plaintext_in_len]u8,
    plain_in_len: usize,
    /// What the session wrote that the seal has not taken yet.
    plain_out: [constants.write_buffer_len]u8,
    plain_out_len: usize,
    /// Whether the session said it is done, so it reads no more.
    session_done: bool,
    /// Whether the peer's `close_notify` ended its data (RFC 9846 §6.1).
    peer_closed: bool,
    /// Whether this side's `close_notify` has been sealed.
    close_sent: bool,

    /// Empties the buffers for a connection whose handshake has not started.
    pub fn reset(records: *Records) void {
        records.plain_in_len = 0;
        records.plain_out_len = 0;
        records.session_done = false;
        records.peer_closed = false;
        records.close_sent = false;
    }

    /// Runs the three parts of the header over what the socket read, writing into its output.
    /// The session's connection must hold the provider already (`attach_tls`).
    pub fn step(records: *Records, session: anytype, input: []const u8, output: []u8) Error!Step {
        const consumed = try records.open(session, input);
        records.step_session(session);
        const written = try records.seal(session, output);
        const done = records.finished() and records.plain_out_len == 0 and records.close_sent;
        return .{ .consumed = consumed, .written = written, .done = done };
    }

    /// Whether the connection has nothing more to read: the session is done, or the peer
    /// closed.
    fn finished(records: *const Records) bool {
        return records.session_done or records.peer_closed;
    }

    /// Opens whole records into the byte stream while one fits, and returns the octets taken.
    fn open(records: *Records, session: anytype, input: []const u8) Error!usize {
        var consumed: usize = 0;
        // Bounded: every pass takes a whole record, or stops.
        for (0..input.len + 1) |_| {
            if (records.finished()) return consumed;
            const opened = connection_tls.decrypt(
                &session.connection,
                input[consumed..],
                records.plain_in[records.plain_in_len..],
                session.now_ns,
            ) catch |failure| switch (failure) {
                // The byte stream has no room for another record until the session reads it.
                error.NoSpaceLeft => return consumed,
                // RFC 9113 §5.4.1: an h2 connection error. The session's next step reads the
                // failure from the connection and writes the GOAWAY it queued.
                error.ConnectionFailed => return consumed,
                error.TlsFailed, error.HandshakeIncomplete, error.NoProvider => return Error.TlsFailed,
            };
            // No whole record is left.
            if (opened.consumed == 0) return consumed;
            consumed += opened.consumed;
            records.plain_in_len += opened.plaintext_len;
            // RFC 9846 §6.1: the peer's close_notify ends its data.
            if (opened.end_of_data) records.peer_closed = true;
            // RFC 9846 §4.7.3: a KeyUpdate may leave a reply owed, which goes out before the
            // next record is opened, so at most one is owed at a time.
            if (opened.owes_handshake) return consumed;
        }
        unreachable; // Each record takes at least its header, so the input ends first.
    }

    /// Steps the session over the byte stream until it stops moving, as the cleartext
    /// endpoint does, appending what it writes to the plaintext output.
    fn step_session(records: *Records, session: anytype) void {
        for (0..constants.steps_per_read_max) |_| {
            const room = records.plain_out[records.plain_out_len..];
            if (room.len == 0) return;
            const stepped = session.step(records.plain_in[0..records.plain_in_len], room);
            records.plain_out_len += stepped.written;
            records.take_plain_in(stepped.consumed);
            if (stepped.done) {
                records.session_done = true;
                return;
            }
            if (stepped.consumed == 0 and stepped.written == 0) return;
        }
    }

    /// Seals as much of the plaintext output as the socket's output holds, then the
    /// `close_notify` once the connection is finished and nothing is left to seal.
    fn seal(records: *Records, session: anytype, output: []u8) Error!usize {
        // Called with no plaintext too: `encrypt` writes what the provider owes first, such as
        // the reply to a KeyUpdate (RFC 9846 §4.7.3), and that does not wait for h2 to write.
        const plaintext = records.plain_out[0..records.plain_out_len];
        const sealed = connection_tls.encrypt(&session.connection, plaintext, output, session.now_ns) catch |failure| switch (failure) {
            // The socket has not taken what it holds; the rest waits.
            error.NoSpaceLeft => return 0,
            else => return Error.TlsFailed,
        };
        records.take_plain_out(sealed.consumed);
        var written = sealed.written;
        if (!records.finished() or records.plain_out_len > 0 or records.close_sent) return written;
        if (output.len - written < close_notify_len_max) return written;
        // RFC 9846 §6.1: "Each party MUST send a "close_notify" alert before closing its write
        // side of the connection".
        written += connection_tls.close_notify(&session.connection, output[written..]) catch return written;
        records.close_sent = true;
        return written;
    }

    fn take_plain_in(records: *Records, consumed: usize) void {
        assert(consumed <= records.plain_in_len);
        std.mem.copyForwards(u8, &records.plain_in, records.plain_in[consumed..records.plain_in_len]);
        records.plain_in_len -= consumed;
    }

    fn take_plain_out(records: *Records, consumed: usize) void {
        assert(consumed <= records.plain_out_len);
        std.mem.copyForwards(u8, &records.plain_out, records.plain_out[consumed..records.plain_out_len]);
        records.plain_out_len -= consumed;
    }
};

/// The most octets a sealed `close_notify` takes: a record header (RFC 9846 §5.1), the alert's two
/// octets (§6), and the content type and AEAD expansion, which §5.2 bounds by what a ciphertext
/// may add to a plaintext.
const close_notify_len_max: usize = tls.constants.record_header_len + alert_len +
    (tls.constants.record_ciphertext_len_max - tls.constants.record_plaintext_len_max);

/// RFC 9846 §6: an alert is a level and a description, one octet each.
const alert_len: usize = 2;

const testing = std.testing;
const h2_session = @import("h2_session.zig");

/// A provider for this file's tests that seals at most `record_plaintext_len` octets a call, which
/// the vtable permits (`tls.provider`), and copies rather than protects. chapulin's adapter fills
/// the output it is given, so only a provider like this one shows the order `seal` keeps.
/// Test-only.
const OneRecordProvider = struct {
    const record_plaintext_len: usize = 16;
    /// RFC 9846 §5.1's content types, and §6's close_notify alert.
    const content_alert: u8 = 21;
    const content_application_data: u8 = 23;
    const close_notify = [_]u8{ 1, 0 };

    const vtable: tls.VTable = .{
        .handshake_read = handshake_read,
        .handshake_write = handshake_write,
        .encrypt_record = encrypt_record,
        .decrypt_record = decrypt_record,
        .negotiated_alpn = negotiated_alpn,
        .handshake_complete = handshake_complete,
        .negotiated_parameters = negotiated_parameters,
        .take_alert = take_alert,
        .send_close_notify = send_close_notify,
        .initiate_key_update = initiate_key_update,
        .export_keying_material = export_keying_material,
    };

    /// A record: a header naming the body's length, then the body (RFC 9846 §5.1).
    fn write_record(output: []u8, content_type: u8, body: []const u8) error{NoSpaceLeft}!usize {
        var writer = tls.core.Writer.init(output);
        writer.write_byte(content_type) catch return error.NoSpaceLeft;
        writer.write_int(u16, tls.constants.version_tls_1_2) catch return error.NoSpaceLeft;
        writer.write_int(u16, @intCast(body.len)) catch return error.NoSpaceLeft;
        writer.write_bytes(body) catch return error.NoSpaceLeft;
        return writer.written().len;
    }

    fn encrypt_record(_: *anyopaque, plaintext: []const u8, output: []u8) tls.provider.SealError!tls.provider.Sealed {
        const body_len = @min(plaintext.len, record_plaintext_len);
        const written = try write_record(output, content_application_data, plaintext[0..body_len]);
        return .{ .consumed = body_len, .written = written };
    }

    fn send_close_notify(_: *anyopaque, output: []u8) tls.provider.CloseError!usize {
        return write_record(output, content_alert, &close_notify);
    }

    fn decrypt_record(_: *anyopaque, _: []const u8, _: []u8) tls.provider.OpenError!tls.provider.Opened {
        return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
    }
    fn handshake_read(_: *anyopaque, _: []const u8, _: u64) tls.provider.HandshakeReadError!usize {
        return 0;
    }
    fn handshake_write(_: *anyopaque, _: []u8, _: u64) tls.provider.HandshakeWriteError!usize {
        return 0;
    }
    fn negotiated_alpn(_: *const anyopaque) ?[]const u8 {
        return "h2";
    }
    fn handshake_complete(_: *const anyopaque) bool {
        return true;
    }
    fn negotiated_parameters(_: *const anyopaque) ?tls.Negotiated {
        return .{ .version = tls.constants.version_tls_1_3, .cipher_suite = tls.constants.cipher_suite_chacha20_poly1305_sha256 };
    }
    fn take_alert(_: *anyopaque) ?tls.AlertReport {
        return null;
    }
    fn initiate_key_update(_: *anyopaque, _: tls.provider.KeyUpdateRequest, _: []u8) tls.provider.KeyUpdateError!usize {
        return error.Unsupported;
    }
    fn export_keying_material(_: *anyopaque, _: []const u8, _: ?[]const u8, _: []u8) tls.provider.ExportError!void {
        return error.Unsupported;
    }
};

/// The records half, the session and the output the test drives, outside any stack frame.
/// Test-only.
var test_records: Records = undefined;
var test_session: h2_session.Session = undefined;
var test_output: [constants.write_buffer_len]u8 = undefined;
var test_context: u8 = 0;
/// More steps than the session's frames take records. Test-only.
const test_steps_max: usize = 64;

test "RFC 9846 §6.1: the close_notify follows every record of what the session wrote" {
    test_session.init();
    try test_session.connection.attach_tls(.{ .context = &test_context, .vtable = &OneRecordProvider.vtable });
    test_records.reset();
    // Octets that are not the client preface fail the connection (RFC 9113 §3.4), so the session
    // writes its SETTINGS and a GOAWAY and is done in its first step: more than one record holds.
    const not_preface = "X" ** h2.constants.client_preface.len;
    @memcpy(test_records.plain_in[0..not_preface.len], not_preface);
    test_records.plain_in_len = not_preface.len;
    var written: usize = 0;
    var steps: usize = 0;
    // Bounded: each step seals one record.
    for (0..test_steps_max) |_| {
        const stepped = try test_records.step(&test_session, &.{}, test_output[written..]);
        written += stepped.written;
        steps += 1;
        // RFC 9846 §6.1: nothing follows a close_notify, so none goes out while plaintext waits.
        try testing.expect(!test_records.close_sent or test_records.plain_out_len == 0);
        if (stepped.done) break;
    }
    try testing.expect(test_records.close_sent and steps > 1);
    // The last record is the alert, and every one before it carries the session's frames.
    var reader = tls.core.Reader.init(test_output[0..written]);
    var last_content: u8 = 0;
    for (0..test_steps_max) |_| {
        if (reader.remaining_len() == 0) break;
        last_content = try reader.read_byte();
        _ = try reader.read_int(u16);
        _ = try reader.take(try reader.read_int(u16));
    }
    try testing.expectEqual(OneRecordProvider.content_alert, last_content);
}
