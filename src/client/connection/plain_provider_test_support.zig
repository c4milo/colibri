//! A provider the client's record tests use (`connection_records_test.zig`) that protects
//! nothing: a record is RFC 9846 §5.1's header and its content in the clear, under the content's
//! own type. It stands in for a finished handshake's session, so the tests make what chapulin's
//! server never sends: a KeyUpdate. The server's tests have the same provider in
//! `src/server/plain_provider_test_support.zig`; a module's tests import no file of another
//! module. Test-only.
const std = @import("std");
const tls_provider = @import("tls_provider");

const core = tls_provider.core;
const provider_module = tls_provider.provider;
const header_len = tls_provider.constants.protocol.record_header_len;

/// RFC 9846 §5.1's content types, the legacy version every record carries, and §6's alerts.
pub const content_alert: u8 = 21;
pub const content_handshake: u8 = 22;
pub const content_application_data: u8 = 23;
const legacy_record_version: u16 = 0x0303;
pub const close_notify = [_]u8{ alert_level_warning, @intFromEnum(tls_provider.Alert.close_notify) };
const alert_level_warning: u8 = 1;

/// RFC 9846 §4.7.3: a KeyUpdate as a handshake message, type 24 with a body of one octet.
pub const handshake_key_update: u8 = 24;
pub const key_update_requested = [_]u8{ handshake_key_update, 0, 0, 1, 1 };
pub const key_update_not_requested = [_]u8{ handshake_key_update, 0, 0, 1, 0 };

/// RFC 9846 §6: the fatal alert the provider sends when a run of KeyUpdates passes its limit.
const alert_level_fatal: u8 = 2;
const unexpected_message = [_]u8{ alert_level_fatal, @intFromEnum(tls_provider.Alert.unexpected_message) };

/// Room for the alert of a failure, as a record.
const owed_len_max: usize = header_len + unexpected_message.len;

/// KeyUpdates in a row the provider reads, chapulin's `CH_KEY_UPDATE_RUN_MAX`. Only a record of
/// one octet of data or more ends a run.
pub const key_update_run_max: u32 = 16;

pub const PlainProvider = struct {
    /// The protocol the handshake selected (RFC 7301 §3.2).
    alpn: []const u8,
    /// The alert of a failure, which `handshake_write` writes (RFC 9846 §6).
    owed: [owed_len_max]u8 = undefined,
    owed_len: usize = 0,
    /// KeyUpdates read since the last record of data, as chapulin counts them.
    key_updates: u32 = 0,
    /// Whether a KeyUpdate asked for an answer that `encrypt_record` has not written yet (RFC 9846
    /// §4.7.3). One answer serves every request read before it, as chapulin's does.
    answer_owed: bool = false,
    /// The peer's close_notify, or the alert this side sent past a run of KeyUpdates, which
    /// `take_alert` reports once.
    pending_alert: ?tls_provider.AlertReport = null,
    /// Whether this side's close_notify went out.
    closed: bool = false,
    /// Whether `encrypt_record` refuses every record, as a provider does after a failure.
    refuse_seal: bool = false,
    /// The version the handshake reports (RFC 9846 Appendix B.1).
    version: u16 = tls_provider.constants.protocol.version_tls_1_3,

    const vtable: tls_provider.VTable = .{
        .handshake_read = handshake_read,
        .handshake_write = handshake_write,
        .encrypt_record = encrypt_record,
        .writable_len = writable_len,
        .encrypt_parts = encrypt_parts,
        .decrypt_record = decrypt_record,
        .negotiated_alpn = negotiated_alpn,
        .handshake_complete = handshake_complete,
        .negotiated_parameters = negotiated_parameters,
        .take_alert = take_alert,
        .send_close_notify = send_close_notify,
        .initiate_key_update = initiate_key_update,
        .export_keying_material = export_keying_material,
    };

    pub fn provider(plain: *PlainProvider) tls_provider.Provider {
        return .{ .context = @ptrCast(plain), .vtable = &vtable };
    }

    fn held(context: *anyopaque) *PlainProvider {
        return @ptrCast(@alignCast(context));
    }

    fn held_const(context: *const anyopaque) *const PlainProvider {
        return @ptrCast(@alignCast(context));
    }

    fn encrypt_record(context: *anyopaque, plaintext: []const u8, output: []u8) provider_module.SealError!provider_module.Sealed {
        const plain = held(context);
        // RFC 9846 §6: a provider that failed protects no more records.
        if (plain.refuse_seal) return error.TlsFailed;
        // RFC 9846 §4.7.3: the answer is owed before the next record of data, so empty plaintext
        // writes nothing.
        if (plaintext.len == 0) return .{ .consumed = 0, .written = 0 };
        const answer_len: usize = if (plain.answer_owed) header_len + key_update_not_requested.len else 0;
        // RFC 9846 §5.2: the output holds the answer and a record of one octet, or nothing moves.
        if (output.len <= answer_len + header_len) return error.NoSpaceLeft;
        // RFC 9846 §4.7.3: the provider writes the answer first, under the keys it replaces.
        if (plain.answer_owed) _ = seal(content_handshake, &key_update_not_requested, output) catch unreachable;
        plain.answer_owed = false;
        const taken = @min(plaintext.len, output.len - answer_len - header_len, tls_provider.constants.protocol.record_plaintext_len_max);
        const written = seal(content_application_data, plaintext[0..taken], output[answer_len..]) catch unreachable;
        return .{ .consumed = taken, .written = answer_len + written.len };
    }

    /// The plaintext of one record after the answer the provider owes: the parts go out in one.
    fn writable_len(context: *const anyopaque, output_len: usize) usize {
        const answer_len: usize = if (held_const(context).answer_owed) header_len + key_update_not_requested.len else 0;
        return @min(output_len -| (answer_len + header_len), tls_provider.constants.protocol.record_plaintext_len_max);
    }

    /// Writes `head` and then `data` in one record of data, after the answer the provider owes, as
    /// `encrypt_record` writes (decision 139). Whole or nothing.
    fn encrypt_parts(context: *anyopaque, head: []const u8, data: []const u8, output: []u8) provider_module.SealError!usize {
        const plain = held(context);
        // RFC 9846 §6: a provider that failed protects no more records.
        if (plain.refuse_seal) return error.TlsFailed;
        if (head.len + data.len > writable_len(context, output.len)) return error.NoSpaceLeft;
        const answer_len: usize = if (plain.answer_owed) header_len + key_update_not_requested.len else 0;
        // RFC 9846 §4.7.3: the provider writes the answer first, under the keys it replaces.
        if (plain.answer_owed) _ = seal(content_handshake, &key_update_not_requested, output) catch unreachable;
        plain.answer_owed = false;
        var writer = core.Writer.init(output[answer_len..]);
        writer.write_byte(content_application_data) catch unreachable;
        writer.write_int(u16, legacy_record_version) catch unreachable;
        writer.write_int(u16, @intCast(head.len + data.len)) catch unreachable;
        writer.write_bytes(head) catch unreachable;
        writer.write_bytes(data) catch unreachable;
        return answer_len + writer.written().len;
    }

    fn decrypt_record(context: *anyopaque, input: []const u8, plaintext: []u8) provider_module.OpenError!provider_module.Opened {
        const plain = held(context);
        const opened = open(input) orelse return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
        const consumed = header_len + opened.content.len;
        switch (opened.content_type) {
            content_application_data => {
                if (plaintext.len < opened.content.len) return error.NoSpaceLeft;
                @memcpy(plaintext[0..opened.content.len], opened.content);
                // A record that carries no data counts against the run h2 bounds, as chapulin's do.
                if (opened.content.len == 0) return .{ .consumed = consumed, .plaintext_len = 0, .content = .without_data };
                // A record of one octet of data or more ends a run of KeyUpdates, as in chapulin.
                plain.key_updates = 0;
                return .{ .consumed = consumed, .plaintext_len = opened.content.len, .content = .application_data };
            },
            content_alert => {
                // RFC 9846 §6.2: any alert but close_notify is an error alert, which ends the
                // connection.
                if (!std.mem.eql(u8, opened.content, &close_notify)) return error.TlsFailed;
                plain.pending_alert = .{ .description = .close_notify, .origin = .peer };
                return .{ .consumed = consumed, .plaintext_len = 0, .content = .alert };
            },
            content_handshake => return plain.read_key_update(opened.content, consumed),
            // RFC 9846 §5.1: a record of any other content type ends the connection.
            else => return error.TlsFailed,
        }
    }

    /// Reads a KeyUpdate. A request leaves the answer owed to `encrypt_record`.
    fn read_key_update(plain: *PlainProvider, content: []const u8, consumed: usize) provider_module.OpenError!provider_module.Opened {
        const requested = std.mem.eql(u8, content, &key_update_requested);
        // RFC 9846 §4.7.3: the one post-handshake message this provider reads is a KeyUpdate.
        if (!requested and !std.mem.eql(u8, content, &key_update_not_requested)) return error.TlsFailed;
        plain.key_updates += 1;
        // RFC 9846 §4.7.3 sets no limit on a run. chapulin refuses the KeyUpdate past a full run,
        // with unexpected_message, and so does this provider.
        if (plain.key_updates > key_update_run_max) {
            plain.owed_len = (seal(content_alert, &unexpected_message, &plain.owed) catch unreachable).len;
            // `take_alert` names the alert that this side sent, as chapulin's adapter does.
            plain.pending_alert = .{ .description = .unexpected_message, .origin = .local };
            // RFC 9846 §6.2: the error alert ends the connection, and the error names the limit.
            return error.KeyUpdates;
        }
        if (requested) plain.answer_owed = true;
        return .{ .consumed = consumed, .plaintext_len = 0, .content = .without_data };
    }

    fn handshake_write(context: *anyopaque, output: []u8, now_ns: u64) provider_module.HandshakeWriteError!usize {
        _ = now_ns;
        const plain = held(context);
        if (plain.owed_len > output.len) return error.NoSpaceLeft;
        const written = plain.owed_len;
        @memcpy(output[0..written], plain.owed[0..written]);
        plain.owed_len = 0;
        return written;
    }

    fn send_close_notify(context: *anyopaque, output: []u8) provider_module.CloseError!usize {
        const plain = held(context);
        if (plain.closed) return 0;
        const written = seal(content_alert, &close_notify, output) catch return error.NoSpaceLeft;
        plain.closed = true;
        return written.len;
    }

    fn take_alert(context: *anyopaque) ?tls_provider.AlertReport {
        const plain = held(context);
        defer plain.pending_alert = null;
        return plain.pending_alert;
    }

    fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
        return held_const(context).alpn;
    }

    fn handshake_complete(context: *const anyopaque) bool {
        _ = context;
        return true;
    }

    fn negotiated_parameters(context: *const anyopaque) ?tls_provider.Negotiated {
        return .{ .version = held_const(context).version, .cipher_suite = tls_provider.constants.protocol.cipher_suite_chacha20_poly1305_sha256, .group = tls_provider.constants.protocol.group_x25519 };
    }

    fn handshake_read(context: *anyopaque, input: []const u8, now_ns: u64) provider_module.HandshakeReadError!usize {
        _ = .{ context, input, now_ns };
        return 0;
    }

    fn initiate_key_update(context: *anyopaque, request: provider_module.KeyUpdateRequest, output: []u8) provider_module.KeyUpdateError!usize {
        _ = .{ context, request, output };
        // RFC 9846 §4.7.3: this provider only answers a peer's KeyUpdate, and starts none.
        return error.Unsupported;
    }

    fn export_keying_material(context: *anyopaque, label: []const u8, context_value: ?[]const u8, output: []u8) provider_module.ExportError!void {
        _ = .{ context, label, context_value, output };
        // RFC 9846 §7.5: this provider holds no secret to export from.
        return error.Unsupported;
    }
};

/// Writes one record of `content_type` holding `content` into the front of `output`.
pub fn seal(content_type: u8, content: []const u8, output: []u8) error{NoSpaceLeft}![]u8 {
    var writer = core.Writer.init(output);
    writer.write_byte(content_type) catch return error.NoSpaceLeft;
    writer.write_int(u16, legacy_record_version) catch return error.NoSpaceLeft;
    writer.write_int(u16, @intCast(content.len)) catch return error.NoSpaceLeft;
    writer.write_bytes(content) catch return error.NoSpaceLeft;
    return output[0..writer.written().len];
}

pub const Opened = struct { content_type: u8, content: []const u8 };

/// The record at the front of `input`, or null while it is not whole (RFC 9846 §5.1).
pub fn open(input: []const u8) ?Opened {
    var reader = core.Reader.init(input);
    const content_type = reader.read_byte() catch return null;
    _ = reader.read_int(u16) catch return null;
    const length = reader.read_int(u16) catch return null;
    const content = reader.take(length) catch return null;
    return .{ .content_type = content_type, .content = content };
}
