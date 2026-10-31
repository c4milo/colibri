//! A record-mode chapulin session behind colibri's `tls_provider.Provider` (decision 94): the calls
//! h2 and h11 make on a connection's records, written once for both roles, because chapulin's
//! client and server sessions answer the same record calls (`read`, `write`, `close`).
//!
//! chapulin's `read` opens one whole record. A KeyUpdate that asks for an answer leaves the answer
//! owed in chapulin's session. chapulin's `write` sends it in front of the next record of data.
//! RFC 9846 §4.7.3 requires the keys that the answer replaces to protect it. One answer serves
//! every KeyUpdate that asked, read since the last answer (chapulin's decision 138). A NewSessionTicket and a KeyUpdate
//! produce no plaintext, and RFC 9113 §9.2.3 permits both after the handshake.
//!
//! Each vtable member is a one-line call into a function below that takes the role's session
//! as `anytype`: a `Client` or a `Server` of `record.zig`, each with `session` and `state`.
const std = @import("std");
const assert = std.debug.assert;
const tls_provider = @import("tls_provider");
const chapulin = @import("chapulin_tcp");

const c = chapulin.c;
const provider_module = tls_provider.provider;

/// Room for what a `read` sends: the alert a failed read raises (RFC 9846 §6). chapulin's `write`
/// sends the answer to a KeyUpdate, so a `read` sends nothing else.
pub const owed_len_max = chapulin.record.alert_record_len;

/// RFC 9846 §4.3.1: chapulin speaks TLS 1.3 and nothing else.
const tls_1_3 = tls_provider.constants.protocol.version_tls_1_3;

/// What the provider keeps beside chapulin's session.
pub const State = struct {
    /// The alert chapulin sent from inside a failed `read`, which `handshake_write` writes whole.
    owed: [owed_len_max]u8 = undefined,
    owed_len: usize = 0,
    /// The peer's close_notify, which `take_alert` reports once (RFC 9846 §6.1).
    pending_alert: ?tls_provider.AlertReport = null,
    /// Whether `take_alert` has reported the fatal alert the peer sent, and the one this side sent.
    received_taken: bool = false,
    sent_taken: bool = false,
    /// Whether this side's close_notify has gone out (RFC 9846 §6.1).
    closed: bool = false,
    /// Whether the handshake completed, which a closed session still did.
    completed: bool = false,
    /// The octets a failed `handshake` wrote at the front of its output (RFC 9846 §6.2).
    failure_written: usize = 0,
};

/// The vtable for a role's session type `Held`.
pub fn Provider(comptime Held: type) type {
    return struct {
        pub const vtable: tls_provider.VTable = .{
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

        fn held(context: *anyopaque) *Held {
            return @ptrCast(@alignCast(context));
        }

        fn held_const(context: *const anyopaque) *const Held {
            return @ptrCast(@alignCast(context));
        }

        fn handshake_write(context: *anyopaque, output: []u8, now_ns: u64) provider_module.HandshakeWriteError!usize {
            _ = now_ns;
            return hand_over(&held(context).state, output);
        }

        fn encrypt_record(context: *anyopaque, plaintext: []const u8, output: []u8) provider_module.SealError!provider_module.Sealed {
            return seal(held(context), plaintext, output);
        }

        fn writable_len(context: *const anyopaque, output_len: usize) usize {
            return held_const(context).session.writableLen(output_len);
        }

        fn encrypt_parts(context: *anyopaque, head: []const u8, data: []const u8, output: []u8) provider_module.SealError!usize {
            return seal_parts(held(context), head, data, output);
        }

        fn decrypt_record(context: *anyopaque, input: []const u8, plaintext: []u8) provider_module.OpenError!provider_module.Opened {
            return open(held(context), input, plaintext);
        }

        fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
            return selected_protocol(held_const(context));
        }

        fn handshake_complete(context: *const anyopaque) bool {
            return held_const(context).state.completed;
        }

        fn negotiated_parameters(context: *const anyopaque) ?tls_provider.Negotiated {
            return parameters(held_const(context));
        }

        fn take_alert(context: *anyopaque) ?tls_provider.AlertReport {
            return next_alert(held(context));
        }

        fn send_close_notify(context: *anyopaque, output: []u8) provider_module.CloseError!usize {
            return close_notify(held(context), output);
        }

        fn export_keying_material(context: *anyopaque, label: []const u8, context_value: ?[]const u8, output: []u8) provider_module.ExportError!void {
            return export_material(held(context), label, context_value, output);
        }
    };
}

/// RFC 9846 §4.7: after the handshake, tickets and KeyUpdates ride records, which `read` opens, so
/// colibri hands over no handshake octets.
fn handshake_read(context: *anyopaque, input: []const u8, now_ns: u64) provider_module.HandshakeReadError!usize {
    _ = .{ context, input, now_ns };
    return 0;
}

/// chapulin has no call that starts a record-mode KeyUpdate. Its `write` answers the peer's.
fn initiate_key_update(context: *anyopaque, request: provider_module.KeyUpdateRequest, output: []u8) provider_module.KeyUpdateError!usize {
    _ = .{ context, request, output };
    // RFC 9846 §4.7.3: a KeyUpdate this side starts, which chapulin's record mode sends none of.
    return error.Unsupported;
}

/// The alert chapulin sent from inside a failed `read`, whole, or nothing when `output` cannot
/// hold it.
fn hand_over(state: *State, output: []u8) provider_module.HandshakeWriteError!usize {
    if (state.owed_len > output.len) return error.NoSpaceLeft;
    const written = state.owed_len;
    @memcpy(output[0..written], state.owed[0..written]);
    state.owed_len = 0;
    return written;
}

/// Seals as much of `plaintext` as `output` holds (RFC 9846 §5.2). chapulin's `write` is all or
/// nothing, so this asks it for what fits. What fits leaves room for the KeyUpdate that chapulin
/// owes the peer, which `write` sends first (RFC 9846 §4.7.3). Empty plaintext writes nothing, and
/// the answer stays owed.
fn seal(role: anytype, plaintext: []const u8, output: []u8) provider_module.SealError!provider_module.Sealed {
    if (plaintext.len == 0) return .{ .consumed = 0, .written = 0 };
    const fits = @min(plaintext.len, role.session.writableLen(output.len));
    // RFC 9846 §5.2: a record carries at least one octet of application data here.
    if (fits == 0) return error.NoSpaceLeft;
    // RFC 9846 §6.1: a session that closed or failed seals nothing more.
    const written = role.session.write(plaintext[0..fits], output) catch return error.TlsFailed;
    return .{ .consumed = fits, .written = written };
}

/// Seals `head` and then `data` as one run of plaintext, whole or not at all, with chapulin's
/// `writeParts` (chapulin's decision 167, decision 139): `write`'s records for the two joined, and
/// no copy of them into one buffer.
fn seal_parts(role: anytype, head: []const u8, data: []const u8, output: []u8) provider_module.SealError!usize {
    assert(head.len > 0);
    // RFC 9846 §5.2: what does not fit `output` is sealed whole by a later call.
    if (head.len + data.len > role.session.writableLen(output.len)) return error.NoSpaceLeft;
    const parts = [_]c.ch_part{ chapulin.part(head), chapulin.part(data) };
    // RFC 9846 §6.1: a session that closed or failed seals nothing more.
    return role.session.writeParts(&parts, output) catch return error.TlsFailed;
}

/// Opens the record at the front of `input` and says what it held.
fn open(role: anytype, input: []const u8, plaintext: []u8) provider_module.OpenError!provider_module.Opened {
    const whole = c.ch_record_whole_len(input.ptr, input.len);
    // RFC 9846 §5.1: a record not yet whole is incomplete, and chapulin never reads it.
    if (whole == 0) return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
    // RFC 9846 §5.2: a record's plaintext is shorter than what follows its header, so a buffer
    // that long holds all of it and chapulin keeps none back.
    if (plaintext.len < whole - tls_provider.constants.protocol.record_header_len) return error.NoSpaceLeft;
    const state = &role.state;
    // A failed read ends the session, and h2 and h11 read no record after one, so nothing is owed.
    assert(state.owed_len == 0);
    const read = role.session.read(input, plaintext, &state.owed) catch |failure| {
        // The alert a failed read raised is owed to the peer (RFC 9846 §6).
        state.owed_len = role.session.replyLen();
        // RFC 9846 §4.7.3 sets no limit on a run of KeyUpdates. chapulin's decision 138 fails the
        // KeyUpdate past `CH_KEY_UPDATE_RUN_MAX` with unexpected_message, and this error names it.
        if (failure == error.KeyUpdateLimit) return error.KeyUpdates;
        // RFC 9846 §6.2: an error alert ends the connection.
        return error.TlsFailed;
    };
    // chapulin's `read` sends nothing into `reply` when it succeeds: the answer to a KeyUpdate
    // waits for `write`.
    assert(read.reply_len == 0);
    if (read.pt_len > 0) return .{ .consumed = read.consumed, .plaintext_len = read.pt_len, .content = .application_data };
    // RFC 9846 §6.1: chapulin answers 0 for the peer's close_notify.
    if (read.peer_closed) {
        state.pending_alert = .{ .description = .close_notify, .origin = .peer };
        return .{ .consumed = read.consumed, .plaintext_len = 0, .content = .alert };
    }
    // RFC 9846 §4.7.1 and §4.7.3: a NewSessionTicket or a KeyUpdate, or an empty record of
    // application data (§5.1).
    return .{ .consumed = read.consumed, .plaintext_len = 0, .content = .without_data };
}

/// RFC 7301 §3.1: what the handshake selected, from the list the configuration offered.
fn selected_protocol(role: anytype) ?[]const u8 {
    if (!role.state.completed) return null;
    return role.session.alpnSelected();
}

/// RFC 9846 §4.3.1 and Appendix B.4: the version and the suite the handshake selected. A client
/// of an object without AES-GCM offers ChaCha20 alone and records no suite (chapulin's
/// `ch_tls.suite`), so that is the suite it reports.
fn parameters(role: anytype) ?tls_provider.Negotiated {
    if (!role.state.completed) return null;
    const suite = role.session.suite() orelse if (aes_gcm) return null else chapulin.Suite.chacha20_poly1305_sha256;
    // RFC 9846 §4.3.8: the server's KeyShareEntry names the group, which chapulin holds once the
    // handshake completed.
    const group = role.session.group() orelse return null;
    return .{ .version = tls_1_3, .cipher_suite = @intFromEnum(suite), .group = @intFromEnum(group) };
}

/// Whether the object holds the AES-GCM suites beside ChaCha20: a server's suite order exists in
/// such a build alone (chapulin's `srv_cfg.h`).
pub const aes_gcm = @hasField(c.ch_srv_cfg, "cipher_suites");

/// The peer's close_notify, then what a failure left (RFC 9846 §6): the fatal alert the peer sent,
/// then the one this side sent, each once. chapulin sends its own alert from inside a read or a
/// write, and names both (`ch_alert_sent`, `ch_alert_received`).
fn next_alert(role: anytype) ?tls_provider.AlertReport {
    const state = &role.state;
    if (state.pending_alert) |report| {
        state.pending_alert = null;
        return report;
    }
    if (role.session.recordState() != .failed) return null;
    if (!state.received_taken) {
        state.received_taken = true;
        if (role.session.alertReceived()) |description| return .{ .description = @enumFromInt(description), .origin = .peer };
    }
    if (!state.sent_taken) {
        state.sent_taken = true;
        if (role.session.alertSent()) |description| return .{ .description = @enumFromInt(description), .origin = .local };
    }
    return null;
}

/// RFC 9846 §6.1's close_notify, once. chapulin's `close` wipes the keys whether or not the alert
/// fits, so an output too short for it is refused before chapulin is called.
fn close_notify(role: anytype, output: []u8) provider_module.CloseError!usize {
    if (role.state.closed) return 0;
    if (output.len < chapulin.record.alert_record_len) return error.NoSpaceLeft;
    const written = role.session.close(output) catch unreachable;
    role.state.closed = true;
    return written;
}

/// Why `fail` sent no alert.
pub const FailError = error{
    /// The alert is not one of RFC 9846 §6.2's error alerts: close_notify and user_canceled end a
    /// connection in order (§6.1), and no other value names an alert. The session is as it was.
    NotErrorAlert,
    /// The handshake has not completed, or the session already closed or failed, and chapulin
    /// sends an alert on a connected session alone. The session is as it was.
    NotConnected,
    /// `output` holds fewer than `alert_record_len` octets. The session is as it was.
    NoSpaceLeft,
    /// The write key seals no more records (RFC 9846 §5.5), so no alert went out. The session
    /// failed all the same.
    KeyExhausted,
};

/// RFC 9846 §6.2's fatal alert `description` names, for an error the caller found itself, and then the
/// session fails. chapulin wipes the keys once it is called, so an output too short for the alert
/// is refused before chapulin is called, as `close_notify` refuses one.
pub fn fail(role: anytype, description: tls_provider.Alert, output: []u8) FailError!usize {
    if (output.len < chapulin.record.alert_record_len) return error.NoSpaceLeft;
    const written = role.session.fail(@intFromEnum(description), output) catch |failure| return switch (failure) {
        // RFC 9846 §6.2: chapulin takes the error alerts alone, and the session stays as it was.
        error.Invalid => error.NotErrorAlert,
        // RFC 9846 §6: no alert is sent on a session that is not connected.
        error.Proto => error.NotConnected,
        // RFC 9846 §5.5: a key past its limit seals nothing more.
        error.Cap => error.KeyExhausted,
        // The output holds a whole alert record, which the check above made sure of.
        error.Io => unreachable,
    };
    assert(written > 0 and written <= chapulin.record.alert_record_len);
    return written;
}

/// RFC 9846 §7.5's exporter, which the TCP object offers (`EXPORTER=on`).
fn export_material(role: anytype, label: []const u8, context_value: ?[]const u8, output: []u8) provider_module.ExportError!void {
    // RFC 9846 §7.5: the exporter secret exists once the handshake completes.
    if (role.session.recordState() != .connected) return error.HandshakeIncomplete;
    // RFC 9846 §7.5: the exporter's output, which chapulin bounds at `CH_EXPORT_MAX` octets.
    if (output.len > c.CH_EXPORT_MAX) return error.OutputTooLong;
    if (output.len == 0) return;
    var storage: [c.CH_EXPORT_LABEL_MAX + 1]u8 = undefined;
    // RFC 9846 §7.5: a label chapulin cannot take as a C string has no exporter here.
    const terminated = label_string(label, &storage) orelse return error.Unsupported;
    // RFC 9846 §7.5: chapulin refuses what its exporter cannot derive.
    role.session.exportKeyingMaterial(terminated, context_value orelse &.{}, output) catch return error.Unsupported;
}

/// chapulin takes an exporter label as a C string of at most `CH_EXPORT_LABEL_MAX` octets. A longer
/// label, or one holding a zero octet, which C would end early, is one this provider has no
/// exporter for.
fn label_string(label: []const u8, storage: *[c.CH_EXPORT_LABEL_MAX + 1]u8) ?[:0]const u8 {
    if (label.len > c.CH_EXPORT_LABEL_MAX) return null;
    if (std.mem.indexOfScalar(u8, label, 0) != null) return null;
    @memcpy(storage[0..label.len], label);
    storage[label.len] = 0;
    return storage[0..label.len :0];
}
