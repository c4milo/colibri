//! A record-mode chapulin session behind colibri's `tls_provider.Provider` (decision 94): the calls
//! h2 and h11 make on a connection's records, written once for both roles, because chapulin's
//! client and server sessions answer the same record calls (`read`, `write`, `close`).
//!
//! chapulin's `read` opens one whole record and answers a KeyUpdate itself, into a reply this file
//! keeps until `handshake_write` hands it over: RFC 9846 §4.7.3's answer is protected under the
//! keys it replaces, so it goes out before any record sealed after it. A NewSessionTicket and a
//! KeyUpdate produce no plaintext, and RFC 9113 §9.2.3 permits both after the handshake.
//!
//! Each vtable member is a one-line call into a function below that takes the role's session
//! as `anytype`: a `Client` or a `Server` of `record.zig`, each with `session` and `state`.
const std = @import("std");
const tls_provider = @import("tls_provider");
const chapulin = @import("chapulin_tcp");
const constants = @import("../constants.zig");

const c = chapulin.c;
const provider_module = tls_provider.provider;

/// Room for what one `read` sends: `key_update_replies_max` KeyUpdate answers, and the alert a
/// failed read raises.
pub const owed_len_max = chapulin.record.key_update_record_len * constants.key_update_replies_max +
    chapulin.record.alert_record_len;

/// RFC 9846 §4.3.1: chapulin speaks TLS 1.3 and nothing else.
const tls_1_3 = tls_provider.constants.version_tls_1_3;

/// What the provider keeps beside chapulin's session.
pub const State = struct {
    /// What chapulin sent from inside `read`, which `handshake_write` hands over whole.
    owed: [owed_len_max]u8 = undefined,
    owed_len: usize = 0,
    /// The peer's close_notify, which `take_alert` reports once (RFC 9846 §6.1).
    pending_alert: ?tls_provider.AlertReport = null,
    /// Whether this side's close_notify has gone out (RFC 9846 §6.1).
    closed: bool = false,
    /// Whether the handshake completed, which a closed session still did.
    completed: bool = false,
};

/// The vtable for a role's session type `Held`.
pub fn Provider(comptime Held: type) type {
    return struct {
        pub const vtable: tls_provider.VTable = .{
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
            return peer_alert(&held(context).state);
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

/// chapulin has no call that starts a record-mode KeyUpdate, and answers the peer's itself.
fn initiate_key_update(context: *anyopaque, request: provider_module.KeyUpdateRequest, output: []u8) provider_module.KeyUpdateError!usize {
    _ = .{ context, request, output };
    // RFC 9846 §4.7.3: a KeyUpdate this side starts, which chapulin's record mode sends none of.
    return error.Unsupported;
}

/// What chapulin sent from inside `read`, whole, or nothing when `output` cannot hold it.
fn hand_over(state: *State, output: []u8) provider_module.HandshakeWriteError!usize {
    if (state.owed_len > output.len) return error.NoSpaceLeft;
    const written = state.owed_len;
    @memcpy(output[0..written], state.owed[0..written]);
    state.owed_len = 0;
    return written;
}

/// Seals as much of `plaintext` as `output` holds (RFC 9846 §5.2). chapulin's `write` is all or
/// nothing, so this asks it for what fits.
fn seal(role: anytype, plaintext: []const u8, output: []u8) provider_module.SealError!provider_module.Sealed {
    if (plaintext.len == 0) return .{ .consumed = 0, .written = 0 };
    const fits = @min(plaintext.len, role.session.writableLen(output.len));
    // RFC 9846 §5.2: a record carries at least one octet of application data here.
    if (fits == 0) return error.NoSpaceLeft;
    // RFC 9846 §6.1: a session that closed or failed seals nothing more.
    const written = role.session.write(plaintext[0..fits], output) catch return error.TlsFailed;
    return .{ .consumed = fits, .written = written };
}

/// Opens the record at the front of `input` and says what it held.
fn open(role: anytype, input: []const u8, plaintext: []u8) provider_module.OpenError!provider_module.Opened {
    const whole = c.ch_record_whole_len(input.ptr, input.len);
    // RFC 9846 §5.1: a record not yet whole is incomplete, and chapulin never reads it.
    if (whole == 0) return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
    // RFC 9846 §5.2: a record's plaintext is shorter than what follows its header, so a buffer
    // that long holds all of it and chapulin keeps none back.
    if (plaintext.len < whole - tls_provider.constants.record_header_len) return error.NoSpaceLeft;
    const state = &role.state;
    const read = role.session.read(input, plaintext, state.owed[state.owed_len..]) catch {
        // The alert a failed read raised is owed to the peer (RFC 9846 §6).
        state.owed_len += role.session.replyLen();
        // RFC 9846 §6.2: an error alert ends the connection.
        return error.TlsFailed;
    };
    state.owed_len += read.reply_len;
    if (read.pt_len > 0) return .{ .consumed = read.consumed, .plaintext_len = read.pt_len, .content = .application_data };
    // RFC 9846 §6.1: chapulin answers 0 for the peer's close_notify.
    if (read.peer_closed) {
        state.pending_alert = .{ .description = .close_notify, .origin = .peer };
        return .{ .consumed = read.consumed, .plaintext_len = 0, .content = .alert };
    }
    // RFC 9846 §4.7.3: a record that made chapulin answer held a KeyUpdate that asked.
    const content: tls_provider.Content = if (read.reply_len > 0) .key_update else .new_session_ticket;
    return .{ .consumed = read.consumed, .plaintext_len = 0, .content = content };
}

/// RFC 7301 §3.1: what the handshake selected, from the list the configuration offered.
fn selected_protocol(role: anytype) ?[]const u8 {
    if (!role.state.completed) return null;
    return role.session.alpnSelected();
}

/// RFC 9846 §4.3.1 and Appendix B.4: the version and the suite the handshake selected.
fn parameters(role: anytype) ?tls_provider.Negotiated {
    if (!role.state.completed) return null;
    const suite = role.session.suite() orelse return null;
    return .{ .version = tls_1_3, .cipher_suite = @intFromEnum(suite) };
}

/// The peer's close_notify, once. A read that fails sent its own alert from inside chapulin, which
/// keeps no description of it or of a fatal alert it received, so neither is reported (reported to
/// chapulin on 2026-09-26). A failed handshake's alert is the session's `alert`.
fn peer_alert(state: *State) ?tls_provider.AlertReport {
    defer state.pending_alert = null;
    return state.pending_alert;
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
