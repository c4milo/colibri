//! A provider the client's endpoint tests use (`client_tls.zig`) that protects nothing:
//! a record is RFC 9846 §5.1's header and its content in the clear, under the content's own type.
//! The record half (`records.zig`) and the protocols' `connection_tls` drive it as they drive a
//! session of colibri's `tls`, whose records `src/tls/` tests against chapulin. Test-only.
const std = @import("std");
const tls_provider = @import("tls_provider");

const core = tls_provider.core;
const provider_module = tls_provider.provider;
const header_len = tls_provider.constants.record_header_len;

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

/// Room for one owed reply, as a record.
const owed_len_max: usize = header_len + key_update_not_requested.len;

pub const PlainProvider = struct {
    /// The protocol the handshake selected (RFC 7301 §3.2).
    alpn: []const u8,
    /// The reply a KeyUpdate that asked for one left owed (RFC 9846 §4.7.3).
    owed: [owed_len_max]u8 = undefined,
    owed_len: usize = 0,
    /// The peer's close_notify, which `take_alert` reports once.
    pending_alert: ?tls_provider.AlertReport = null,
    /// Whether this side's close_notify went out.
    closed: bool = false,

    const vtable: tls_provider.VTable = .{
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
        _ = context;
        if (plaintext.len == 0) return .{ .consumed = 0, .written = 0 };
        if (output.len <= header_len) return error.NoSpaceLeft;
        const taken = @min(plaintext.len, output.len - header_len, tls_provider.constants.record_plaintext_len_max);
        const written = seal(content_application_data, plaintext[0..taken], output) catch return error.NoSpaceLeft;
        return .{ .consumed = taken, .written = written.len };
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
                const content: tls_provider.Content = if (opened.content.len == 0) .new_session_ticket else .application_data;
                return .{ .consumed = consumed, .plaintext_len = opened.content.len, .content = content };
            },
            content_alert => {
                if (!std.mem.eql(u8, opened.content, &close_notify)) return error.TlsFailed;
                plain.pending_alert = .{ .description = .close_notify, .origin = .peer };
                return .{ .consumed = consumed, .plaintext_len = 0, .content = .alert };
            },
            content_handshake => {
                if (!std.mem.eql(u8, opened.content, &key_update_requested)) return error.TlsFailed;
                plain.owed_len = (seal(content_handshake, &key_update_not_requested, &plain.owed) catch unreachable).len;
                return .{ .consumed = consumed, .plaintext_len = 0, .content = .key_update };
            },
            else => return error.TlsFailed,
        }
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
        _ = context;
        return .{ .version = tls_provider.constants.version_tls_1_3, .cipher_suite = tls_provider.constants.cipher_suite_chacha20_poly1305_sha256 };
    }

    fn handshake_read(context: *anyopaque, input: []const u8, now_ns: u64) provider_module.HandshakeReadError!usize {
        _ = .{ context, input, now_ns };
        return 0;
    }

    fn initiate_key_update(context: *anyopaque, request: provider_module.KeyUpdateRequest, output: []u8) provider_module.KeyUpdateError!usize {
        _ = .{ context, request, output };
        return error.Unsupported;
    }

    fn export_keying_material(context: *anyopaque, label: []const u8, context_value: ?[]const u8, output: []u8) provider_module.ExportError!void {
        _ = .{ context, label, context_value, output };
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
