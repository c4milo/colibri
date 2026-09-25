//! Test-only: TLS 1.3 records sealed under the key a zeroed chapulin session holds, so a test can
//! hand the record adapter real records without a handshake. Part of design §8 step 5's TLS work.
//!
//! A chapulin direction that no handshake has keyed has a key and an IV of zeros, and sequence
//! number 0. A build with one suite runs ChaCha20-Poly1305 on it (chapulin's `record.h`). So a
//! session set to `CH_ST_CONNECTED` opens and seals records under that key, and `seal` below
//! writes the same records chapulin does. The first test proves it against `ch_write`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const tls = @import("tls");
const chapulin = @import("chapulin.zig");
const chapulin_record = @import("chapulin_record.zig");

const c = chapulin.c;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Held = chapulin_record.Held;

/// RFC 9846 §5.1's content types this file seals.
pub const content_alert: u8 = 21;
pub const content_handshake: u8 = 22;
pub const content_application_data: u8 = 23;
/// RFC 9846 §5.1: `legacy_record_version` is 0x0303 on every protected record.
const legacy_record_version: u16 = 0x0303;
/// RFC 9846 §6: the close_notify alert, whose level is warning.
pub const close_notify = [_]u8{ alert_level_warning, alert_close_notify };
const alert_level_warning: u8 = 1;
const alert_close_notify: u8 = 0;
/// The most content one test record carries.
const content_len_max: usize = 256;

/// Makes `session` a connected chapulin session over `held`, keyed with zeros in both directions,
/// and `held` its record phase. `receive` is chapulin's receive buffer.
pub fn connect(held: *Held, session: *c.ch_tls, receive: []u8) void {
    session.* = std.mem.zeroes(c.ch_tls);
    session.state = c.CH_ST_CONNECTED;
    // A connected session has its traffic keys installed, which `ch_close` reads.
    session.keys = 1;
    session.peer_limit = c.CH_TX_PT;
    session.cfg.send = chapulin_record.send;
    session.cfg.recv = chapulin_record.recv;
    session.cfg.io = @ptrCast(&held.io);
    session.cfg.buf = receive.ptr;
    session.cfg.buf_len = receive.len;
    // The protocols the role's `init` offered, which a finished handshake indexes.
    const alpn = held.alpn;
    held.* = .{
        .session = session,
        .io = .{ .records = .{} },
        .closed = false,
        .pending_alert = null,
        .suite = tls.constants.cipher_suite_chacha20_poly1305_sha256,
        .alpn = alpn,
    };
}

/// Seals `content` as one record of `content_type`, the `sequence`th the peer sent (RFC 9846
/// §5.2), into the front of `output`, and returns it.
pub fn seal(sequence: u64, content_type: u8, content: []const u8, output: []u8) ![]const u8 {
    assert(content.len <= content_len_max);
    // RFC 9846 §5.2: the inner plaintext is the content followed by its real type.
    var inner: [content_len_max + 1]u8 = undefined;
    @memcpy(inner[0..content.len], content);
    inner[content.len] = content_type;
    const inner_len = content.len + 1;
    var writer = core.Writer.init(output);
    try writer.write_byte(content_application_data);
    try writer.write_int(u16, legacy_record_version);
    try writer.write_int(u16, @intCast(inner_len + Aead.tag_length));
    const header_len = writer.written().len;
    // RFC 9846 §5.3: the nonce is the sequence number, big-endian and padded on the left, XORed
    // with the IV, which is zeros.
    var nonce: [Aead.nonce_length]u8 = @splat(0);
    std.mem.writeInt(u64, nonce[Aead.nonce_length - @sizeOf(u64) ..], sequence, .big);
    const key: [Aead.key_length]u8 = @splat(0);
    var sealed: [content_len_max + 1]u8 = undefined;
    var tag: [Aead.tag_length]u8 = undefined;
    // RFC 9846 §5.2: the additional data is the record header.
    Aead.encrypt(sealed[0..inner_len], &tag, inner[0..inner_len], output[0..header_len], nonce, key);
    try writer.write_bytes(sealed[0..inner_len]);
    try writer.write_bytes(&tag);
    return writer.written();
}

/// What `open` found in a record: its real content type and its content.
pub const Opened = struct {
    content_type: u8,
    content: []const u8,
};

/// Opens `record`, the `sequence`th this side sealed under the zero key, into `output`, or answers
/// null when it does not authenticate under that key (RFC 9846 §5.2).
pub fn open(sequence: u64, record: []const u8, output: []u8) ?Opened {
    var reader = core.Reader.init(record);
    const header = reader.take(tls.constants.record_header_len) catch return null;
    const sealed = reader.take_rest();
    if (sealed.len < Aead.tag_length + 1) return null;
    const inner_len = sealed.len - Aead.tag_length;
    if (inner_len > output.len) return null;
    var nonce: [Aead.nonce_length]u8 = @splat(0);
    std.mem.writeInt(u64, nonce[Aead.nonce_length - @sizeOf(u64) ..], sequence, .big);
    const key: [Aead.key_length]u8 = @splat(0);
    const tag = sealed[inner_len..][0..Aead.tag_length];
    Aead.decrypt(output[0..inner_len], sealed[0..inner_len], tag.*, header, nonce, key) catch return null;
    // RFC 9846 §5.2: the real type is the last octet that is not padding, and this side pads none.
    return .{ .content_type = output[inner_len - 1], .content = output[0 .. inner_len - 1] };
}

const testing = std.testing;

/// A connected session the test drives. Test-only.
var test_session: if (chapulin.available) c.ch_tls else void = undefined;
var test_held: Held = undefined;
var test_receive: [tls.constants.record_write_len_min]u8 = undefined;

test "a record sealed here is the record chapulin seals under the zero key" {
    if (!chapulin.available) return error.SkipZigTest;
    connect(&test_held, &test_session, &test_receive);
    var chapulin_output: [content_len_max]u8 = undefined;
    const provider: tls.Provider = .{ .context = @ptrCast(&test_held), .vtable = &chapulin_record.vtable };
    const sealed = try provider.vtable.encrypt_record(provider.context, "zero key", &chapulin_output);
    var ours: [content_len_max]u8 = undefined;
    const expected = try seal(0, content_application_data, "zero key", &ours);
    try testing.expectEqualSlices(u8, expected, chapulin_output[0..sealed.written]);
}
