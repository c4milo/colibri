//! The record phase of a chapulin session behind colibri's `tls.Provider`, shared by both roles
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 5's TLS work.
//!
//! **Two phases, because the two sides meet the socket at different places.** colibri's vtable is
//! buffer in and buffer out: it never reads a descriptor, and `attach_tls` refuses a handshake
//! that has not already completed. chapulin's `ch_connect` and `ch_srv_accept` are the opposite —
//! each drives a whole handshake itself through the `send` and `recv` callbacks of its config.
//! This file changes what those two callbacks read and write:
//!
//!   1. **Handshake.** The callbacks read and write the socket, and chapulin runs to completion.
//!      colibri is not involved and owns nothing yet.
//!   2. **Records.** The callbacks serve slices colibri passed in, so `ch_write` seals into
//!      colibri's output and `ch_read` opens from colibri's input. No descriptor is touched.
//!
//! Phase 2 is what lets a socket-owning TLS stack fill a vtable that owns no I/O. It works
//! because colibri hands over whole records: `decrypt_record` is called with a complete record,
//! so the `recv` callback never runs dry, which matters because chapulin's `io.c` turns any
//! `recv` of zero or less into `CH_EIO` and no callback of its can say "nothing yet"
//! ([decision 46](../../../docs/decisions.md)).
//!
//! Nothing in phase 2 is a role: `ch_read`, `ch_write` and `ch_close` are the three calls both a
//! `ROLE=client` and a `ROLE=server` object export, and they read the same `ch_tls`. So one
//! vtable serves both, written once here. A role holds a `Held` and hands its address over as
//! the provider's context, which is why no member below knows which side it is on.
const std = @import("std");
const tls = @import("tls");
const chapulin = @import("chapulin.zig");

const c = chapulin.c;
const posix = std.posix;

/// Everything the record phase touches. `Client` and `Server` each hold one and pass its address
/// as the provider's context, so every member of the vtable below reads this and nothing else.
pub const Held = struct {
    /// chapulin's session, which its three record calls read and write.
    session: c.ch_tls,
    /// Where the callbacks read and write, which is the phase.
    io: Io,
    /// Whether `close_notify` has gone out, so a second call writes nothing (RFC 9846 §6.1).
    closed: bool,
    /// The alert colibri has not collected yet, and null when there is none. chapulin keeps no
    /// alert on a record-mode session a caller can read, so the one description this file can
    /// report is the clean peer close `ch_read` answers 0 for.
    pending_alert: ?tls.AlertReport,
    /// The suite the handshake selected, which a role fills when its handshake completes. A
    /// server reads `session.suite`; a client has no such field and reports the one its build
    /// offers. `negotiated_parameters` reads it here either way.
    suite: u16,
};

/// Where chapulin's callbacks read and write. The phase moves once, when the handshake ends, and
/// never moves back.
pub const Io = union(enum) {
    /// Phase 1: the socket the caller connected or accepted.
    socket: posix.socket_t,
    /// Phase 2: the slices colibri passed into `encrypt_record` or `decrypt_record`.
    records: Records,
};

pub const Records = struct {
    /// What colibri gave to open, and how much of it chapulin has taken.
    input: []const u8 = &.{},
    taken: usize = 0,
    /// Where colibri wants the sealed octets, and how many are there.
    output: []u8 = &.{},
    written: usize = 0,
    /// Whether chapulin asked for octets after taking everything colibri gave. `decrypt_record`
    /// reads it to tell a post-handshake message from a failure; see the comment there.
    ran_dry: bool = false,
};

/// RFC 9113 §3.1's identifier, which is the two octets 0x68 0x32.
pub const alpn_h2 = "h2";

/// RFC 9846 Appendix B.1: the TLS 1.3 codepoint. chapulin speaks 1.3 and nothing else, so a
/// completed handshake negotiated it.
pub const tls_1_3 = tls.constants.version_tls_1_3;

/// chapulin answers 0 for success and a negative `CH_E*` for everything else. The `send`
/// callback shares the convention; `recv` does not, and returns a count.
pub const ok: c_int = 0;
const failed: c_int = -1;

/// Names the code chapulin last answered, for a run to print.
pub fn reason(code: c_int) []const u8 {
    return switch (code) {
        ok => "ok",
        c.CH_EIO => "CH_EIO: the transport failed or closed",
        c.CH_EPROTO => "CH_EPROTO: the peer broke the protocol",
        c.CH_EAUTH => "CH_EAUTH: authentication failed",
        c.CH_ECAP => "CH_ECAP: the buffer is too small for the peer's message",
        c.CH_ECLOSED => "CH_ECLOSED: the peer sent close_notify",
        c.CH_EINVAL => "CH_EINVAL: the configuration or the call is invalid",
        else => "unknown",
    };
}

/// chapulin's `send`: in phase 1 the socket, in phase 2 colibri's output buffer.
///
/// It moves every octet and answers 0. chapulin's `cfg.h` is explicit that anything else,
/// "including a positive byte count, is failure", so this must not report what it wrote.
pub fn send(io: ?*anyopaque, octets: [*c]const u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    switch (state.*) {
        .socket => |descriptor| return send_socket(descriptor, octets, len),
        .records => |*records| {
            const room = records.output.len - records.written;
            // A short output is colibri's to widen, and chapulin cannot be told to wait, so this
            // fails the call rather than writing part of a record.
            if (len > room) return failed;
            @memcpy(records.output[records.written..][0..len], octets[0..len]);
            records.written += len;
            return ok;
        },
    }
}

/// Phase 1's half of `send`. Blocking, with no MSG_DONTWAIT: chapulin's callbacks cannot report
/// "nothing yet", so the handshake waits here rather than answering short (decision 46). A
/// blocking send may still move fewer octets than asked, so this loops until all are gone.
fn send_socket(descriptor: posix.socket_t, octets: [*c]const u8, len: usize) c_int {
    var sent: usize = 0;
    // Bounded by `len`, and every pass moves at least one octet or returns.
    while (sent < len) {
        const wrote = std.c.send(descriptor, octets + sent, len - sent, 0);
        if (wrote <= 0) return failed;
        sent += @intCast(wrote);
    }
    return ok;
}

/// chapulin's `recv`: in phase 1 the socket, in phase 2 the record colibri passed in.
pub fn recv(io: ?*anyopaque, out: [*c]u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    switch (state.*) {
        .socket => |descriptor| {
            // `recv` is the other convention: 1 to n octets, or a negative for failure.
            const read = std.c.recv(descriptor, out, len, 0);
            if (read <= 0) return failed;
            return @intCast(read);
        },
        .records => |*records| {
            const left = records.input.len - records.taken;
            // colibri passes a whole record, so chapulin never asks past the end of one. Running
            // dry would reach chapulin as CH_EIO, which is why the caller must not call with a
            // partial record (decision 46).
            const take = @min(len, left);
            if (take == 0) {
                records.ran_dry = true;
                return failed;
            }
            @memcpy(out[0..take], records.input[records.taken..][0..take]);
            records.taken += take;
            return @intCast(take);
        },
    }
}

/// Casts the context colibri passes back to what a role handed over.
fn held(context: *anyopaque) *Held {
    return @ptrCast(@alignCast(context));
}

fn held_const(context: *const anyopaque) *const Held {
    return @ptrCast(@alignCast(context));
}

/// Opens one record into `plaintext` (RFC 9846 §5.2), and says what it held.
///
/// chapulin's `ch_read` handles NewSessionTicket and KeyUpdate itself and returns only
/// application data, so a record holding one of those produces no plaintext and `ch_read` reads
/// on for more. In phase 2 there is no more: colibri passes one record, the `recv` callback runs
/// dry, and `ch_read` answers with an error. That is not a failure, and treating it as one would
/// close a healthy connection the first time a peer sent a ticket, which servers do routinely.
///
/// So a call that took the whole record, produced no plaintext and then ran dry is reported as a
/// post-handshake message. colibri cannot tell a ticket from a key update here and does not need
/// to: RFC 9113 §9.2.3 permits both and h2 does nothing with either. What colibri would need to
/// tell apart is a CertificateRequest, which §9.2.3 makes a connection error; chapulin refuses
/// that itself and answers an error with nothing consumed, which reaches colibri as `TlsFailed`
/// and closes the connection for the same reason under a different name.
fn decrypt_record(
    context: *anyopaque,
    input: []const u8,
    plaintext: []u8,
) tls.provider.OpenError!tls.provider.Opened {
    const role = held(context);
    role.io = .{ .records = .{ .input = input } };
    const read = c.ch_read(&role.session, plaintext.ptr, plaintext.len);
    const records = role.io.records;
    if (read > 0) return .{
        .consumed = records.taken,
        .plaintext_len = @intCast(read),
        .content = .application_data,
    };
    if (read == 0) return closed_by_peer(role, records.taken);
    if (records.ran_dry and records.taken == input.len and input.len > 0) {
        return .{ .consumed = records.taken, .plaintext_len = 0, .content = .new_session_ticket };
    }
    // Nothing was taken, so no whole record was there and the caller reads more.
    if (records.taken == 0) return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
    return tls.provider.OpenError.TlsFailed;
}

/// RFC 9846 §6.1: chapulin answers 0 for a clean peer close, which is a `close_notify`. colibri's
/// `on_alert` calls `take_alert` for the description and treats a provider that reports none as
/// having broken its contract, so the report is recorded here for it.
fn closed_by_peer(role: *Held, consumed: usize) tls.provider.Opened {
    role.pending_alert = .{ .description = .close_notify, .origin = .peer };
    return .{ .consumed = consumed, .plaintext_len = 0, .content = .alert };
}

/// Protects `plaintext` as one or more records (RFC 9846 §5.2).
fn encrypt_record(
    context: *anyopaque,
    plaintext: []const u8,
    output: []u8,
) tls.provider.SealError!tls.provider.Sealed {
    const role = held(context);
    role.io = .{ .records = .{ .output = output } };
    // chapulin seals and hands the octets to `send`, which writes them into colibri's output.
    // A short output reaches it as a failed send, so nothing is half-written.
    if (c.ch_write(&role.session, plaintext.ptr, plaintext.len) != ok) {
        if (role.io.records.written == 0) return tls.provider.SealError.NoSpaceLeft;
        return tls.provider.SealError.TlsFailed;
    }
    return .{ .consumed = plaintext.len, .written = role.io.records.written };
}

/// RFC 9846 §4.3.1 and Appendix B.4: the version and the suite the handshake selected. The role
/// filled `suite` when its handshake completed.
fn negotiated_parameters(context: *const anyopaque) ?tls.Negotiated {
    const role = held_const(context);
    if (!handshake_complete(context)) return null;
    return .{ .version = tls_1_3, .cipher_suite = role.suite };
}

/// RFC 9846 Appendix E.5: an application must be able to tell. chapulin reaches its established
/// state only when its handshake call returned success, which is when a role leaves phase 1.
fn handshake_complete(context: *const anyopaque) bool {
    return held_const(context).io == .records;
}

/// RFC 7301: what the handshake selected, or null when it selected nothing.
fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
    const role = held_const(context);
    // A session that has not handshaked is all zeros, and chapulin's CH_ALPN_NONE is 255, so a
    // zeroed `alpn_selected` reads as index 0 — the protocol colibri offered. Asking the phase
    // first is what keeps an untouched session from reporting a selection.
    if (role.io != .records) return null;
    if (role.session.alpn_selected == c.CH_ALPN_NONE) return null;
    return alpn_h2;
}

/// RFC 9846 §4.7.3 and §4.7.1: after the handshake, a peer's KeyUpdate and NewSessionTicket ride
/// records, and chapulin answers both inside `ch_read`. So colibri owes no handshake octets here
/// and consumes none: both members answer 0 for the life of the connection.
fn handshake_read(context: *anyopaque, input: []const u8, now_ns: u64) tls.provider.HandshakeReadError!usize {
    _ = .{ context, input, now_ns };
    return 0;
}

fn handshake_write(context: *anyopaque, output: []u8, now_ns: u64) tls.provider.HandshakeWriteError!usize {
    _ = .{ context, output, now_ns };
    return 0;
}

/// The alert colibri has not collected, which the call clears. chapulin's record mode keeps no
/// alert on the session a caller can read — `session.h` declares the field on `ch_quic` for QUIC
/// mode and nowhere for records — so a failed session reaches colibri as an error with no
/// description, and the one report this answers is the clean peer close `decrypt_record`
/// recorded.
fn take_alert(context: *anyopaque) ?tls.AlertReport {
    const role = held(context);
    const report = role.pending_alert;
    role.pending_alert = null;
    return report;
}

/// RFC 9846 §6.1's `close_notify`. `ch_close` sends it through the same `send` callback, which in
/// phase 2 writes into colibri's output, and then wipes the key material.
fn send_close_notify(context: *anyopaque, output: []u8) tls.provider.CloseError!usize {
    const role = held(context);
    if (role.closed) return 0;
    role.io = .{ .records = .{ .output = output } };
    c.ch_close(&role.session);
    role.closed = true;
    return role.io.records.written;
}

/// chapulin answers a peer's KeyUpdate itself and offers no way to start one, so colibri cannot
/// ask for it. Every member of the vtable is mandatory, which is why this exists and refuses.
fn initiate_key_update(
    context: *anyopaque,
    request: tls.provider.KeyUpdateRequest,
    output: []u8,
) tls.provider.KeyUpdateError!usize {
    _ = .{ context, request, output };
    return tls.provider.KeyUpdateError.Unsupported;
}

/// RFC 9846 §7.5 standardises the exporter without obliging a stack to offer it, and chapulin's
/// four public record-mode calls do not. h2 needs none of it.
fn export_keying_material(
    context: *anyopaque,
    label: []const u8,
    context_value: ?[]const u8,
    output: []u8,
) tls.provider.ExportError!void {
    _ = .{ context, label, context_value, output };
    return tls.provider.ExportError.Unsupported;
}

/// The calls colibri makes on a chapulin session, whichever side it is. Every member is mandatory
/// (decision 8), so the two chapulin does not offer answer `Unsupported` rather than being absent.
pub const vtable: tls.VTable = .{
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
