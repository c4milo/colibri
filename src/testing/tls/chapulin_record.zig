//! The record phase of a chapulin session behind colibri's `tls.Provider`, shared by both roles
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 5's TLS work.
//!
//! **Two phases.** colibri's vtable is buffer in and buffer out: it never reads a descriptor, and
//! `attach_tls` refuses a handshake that has not already completed. Both roles are
//! `TRANSPORT=tcp-nonblocking` builds (decisions 46 and 82), so neither touches a descriptor:
//!
//!   1. **Handshake.** The caller passes the octets it read. The client's driver answers through
//!      `ch_record_out`, which the caller pulls from. The server's hands its flight to
//!      `flight_out`, which writes into the caller's output.
//!   2. **Records.** The callbacks serve slices colibri passed in, so `ch_write` seals into
//!      colibri's output and `ch_read` opens from colibri's input.
//!
//! chapulin reads a record whole or fails the session, so `decrypt_record` hands it one whole
//! record at a time and reports a partial one as incomplete. Past that record the `recv` callback
//! answers 0, which record mode reads as no record yet (`rec.h`), and the session stays live.
//!
//! Nothing in phase 2 is a role: `ch_read`, `ch_write` and `ch_close` are the three calls both a
//! `ROLE=client` and a `ROLE=server` object export, and they read the same `ch_tls`. So one
//! vtable serves both, written once here. A role holds a `Held` and hands its address over as
//! the provider's context, which is why no member below knows which side it is on.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const tls = @import("tls");
const chapulin = @import("chapulin.zig");

const c = chapulin.c;

/// Everything the record phase touches. `Client` and `Server` each hold one and pass its address
/// as the provider's context, so every member of the vtable below reads this and nothing else.
pub const Held = struct {
    /// chapulin's session, which its three record calls read and write. Each role's lives inside
    /// chapulin's `ch_record`, which cannot be copied, so this points at it.
    session: *c.ch_tls,
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
    /// What chapulin sent from inside `ch_read`, which `handshake_write` hands over: the reply to
    /// a KeyUpdate that asked for one (RFC 9846 §4.7.3), or the alert a failed read raised.
    owed: [owed_len_max]u8 = undefined,
    owed_len: usize = 0,
};

/// Room for what one `ch_read` sends: a KeyUpdate reply is a record of 27 octets and an alert one
/// of 24, each a header of 5, the message, an inner content type and a tag of 16 (RFC 9846 §5.2).
/// h2 seals before it opens another record after a KeyUpdate, so one reply is owed at a time.
pub const owed_len_max: usize = 64;

/// Where chapulin's callbacks read and write. The phase moves once, when the handshake ends, and
/// never moves back.
pub const Io = union(enum) {
    /// Phase 1: where the server's `flight_out` writes its flight. The client's driver writes
    /// through `ch_record_out` and leaves this empty.
    handshake: Flight,
    /// Phase 2: the slices colibri passed into `encrypt_record` or `decrypt_record`.
    records: Records,
};

/// The output a record-mode server's handshake call writes its flight into.
pub const Flight = struct {
    output: []u8 = &.{},
    written: usize = 0,
    /// Whether a record did not fit. chapulin's sink takes a whole record or fails the handshake
    /// (`srv_cfg.h`), so this names the one failure that is the caller's to fix.
    short: bool = false,
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
pub const failed: c_int = -1;

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

/// chapulin's `send`: in phase 2, colibri's output buffer.
///
/// It moves every octet and answers 0. chapulin's `cfg.h` is explicit that anything else,
/// "including a positive byte count, is failure", so this must not report what it wrote.
pub fn send(io: ?*anyopaque, octets: [*c]const u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    switch (state.*) {
        // chapulin's INV-28: a record-mode handshake calls neither `send` nor `recv`.
        .handshake => return failed,
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

/// chapulin's `recv`: in phase 2, the record colibri passed in.
pub fn recv(io: ?*anyopaque, out: [*c]u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    switch (state.*) {
        .handshake => return failed,
        .records => |*records| {
            const left = records.input.len - records.taken;
            // `decrypt_record` passes whole records, so chapulin runs dry only after one, where a 0
            // answers `CH_RECORD_AGAIN` and the session stays live (`rec.h`).
            const take = @min(len, left);
            if (take == 0) {
                records.ran_dry = true;
                return 0;
            }
            @memcpy(out[0..take], records.input[records.taken..][0..take]);
            records.taken += take;
            return @intCast(take);
        },
    }
}

/// chapulin's `on_record_out`: one whole record of a record-mode server's flight, written into
/// the output the handshake call was given. chapulin cannot be told to wait, so a record that does
/// not fit fails the handshake; the caller gives the call room for a whole flight.
pub fn flight_out(io: ?*anyopaque, octets: [*c]const u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    return switch (state.*) {
        .handshake => |*flight| append_flight(flight, octets, len),
        // chapulin sends the flight only during the handshake call, which sets this phase.
        .records => failed,
    };
}

/// Writes one whole record into the flight, or fails the call when it does not fit.
fn append_flight(flight: *Flight, octets: [*c]const u8, len: usize) c_int {
    const room = flight.output.len - flight.written;
    if (len > room) {
        flight.short = true;
        return failed;
    }
    @memcpy(flight.output[flight.written..][0..len], octets[0..len]);
    flight.written += len;
    return ok;
}

/// The length of the record at the front of `input`, its header included, or null when the input
/// does not hold all of it. RFC 9846 §5.1: a record is a five-octet header whose last two octets
/// are the length of what follows.
pub fn whole_record_len(input: []const u8) ?usize {
    var reader = core.Reader.init(input);
    _ = reader.take(record_length_offset) catch return null;
    const length = reader.read_int(u16) catch return null;
    const total = tls.constants.record_header_len + @as(usize, length);
    if (input.len < total) return null;
    return total;
}

/// Where the length sits in a record's header: after the content type and the legacy version
/// (RFC 9846 §5.1).
const record_length_offset: usize = 3;

/// How many of `plaintext_len` octets fit `output_len` octets once sealed as records of at most
/// `limit` octets of plaintext, each of which the seal makes `overhead` octets longer.
pub fn sealable_len(plaintext_len: usize, output_len: usize, limit: usize, overhead: usize) usize {
    assert(limit > 0);
    const sealed_record_len = limit + overhead;
    const whole = output_len / sealed_record_len;
    const rest = output_len % sealed_record_len;
    const partial = if (rest > overhead) rest - overhead else 0;
    return @min(plaintext_len, whole * limit + partial);
}

/// Casts the context colibri passes back to what a role handed over.
fn held(context: *anyopaque) *Held {
    return @ptrCast(@alignCast(context));
}

fn held_const(context: *const anyopaque) *const Held {
    return @ptrCast(@alignCast(context));
}

/// Opens the record at the front of `input` into `plaintext` (RFC 9846 §5.2), and says what it
/// held.
///
/// chapulin's `ch_read` handles NewSessionTicket and KeyUpdate itself and returns only
/// application data, so a record holding one of those produces no plaintext and `ch_read` reads
/// on for more. It is given one record, so there is no more, and `ch_read` answers
/// `CH_RECORD_AGAIN` (`rec.h`). That is not a failure, and
/// treating it as one would close a healthy connection the first time a peer sent a ticket, which
/// servers do routinely. So a call that took the whole record and produced no plaintext is
/// reported as a post-handshake message.
///
/// colibri cannot tell a ticket from a key update here and does not need to: RFC 9113 §9.2.3
/// permits both and h2 does nothing with either. What colibri would need to tell apart is a
/// CertificateRequest, which §9.2.3 makes a connection error; chapulin refuses that itself, which
/// reaches colibri as `TlsFailed` and closes the connection for the same reason under another name.
fn decrypt_record(
    context: *anyopaque,
    input: []const u8,
    plaintext: []u8,
) tls.provider.OpenError!tls.provider.Opened {
    const role = held(context);
    // RFC 9846 §5.1: chapulin reads a record whole or fails the session, so a partial one is
    // reported as incomplete before chapulin sees it, and the caller reads more.
    const record_len = whole_record_len(input) orelse
        return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
    // A record's plaintext is shorter than what follows its header, so a buffer that long holds
    // it, and chapulin never keeps plaintext back for a call that brings no record.
    if (plaintext.len < record_len - tls.constants.record_header_len) return tls.provider.OpenError.NoSpaceLeft;
    // chapulin may send from inside `ch_read`, and what it sends waits in `owed`.
    role.io = .{ .records = .{ .input = input[0..record_len], .output = role.owed[role.owed_len..] } };
    const read = c.ch_read(role.session, plaintext.ptr, plaintext.len);
    const records = role.io.records;
    role.owed_len += records.written;
    if (read > 0) return .{
        .consumed = records.taken,
        .plaintext_len = @intCast(read),
        .content = .application_data,
    };
    if (read == 0) return closed_by_peer(role, records.taken);
    if (records.ran_dry and records.taken == record_len and read == c.CH_RECORD_AGAIN) {
        // A record that made chapulin send was a KeyUpdate asking for one back.
        const content: tls.Content = if (records.written > 0) .key_update else .new_session_ticket;
        return .{ .consumed = records.taken, .plaintext_len = 0, .content = content };
    }
    return tls.provider.OpenError.TlsFailed;
}

/// RFC 9846 §6.1: chapulin answers 0 for a clean peer close, which is a `close_notify`. colibri's
/// `on_alert` calls `take_alert` for the description and treats a provider that reports none as
/// having broken its contract, so the report is recorded here for it.
fn closed_by_peer(role: *Held, consumed: usize) tls.provider.Opened {
    role.pending_alert = .{ .description = .close_notify, .origin = .peer };
    return .{ .consumed = consumed, .plaintext_len = 0, .content = .alert };
}

/// Protects as much of `plaintext` as `output` holds once sealed, as one or more records (RFC 9846
/// §5.2). chapulin fails the session when its `send` cannot take a whole record, so this asks it
/// to seal only what fits: records of at most `min(peer_limit, CH_TX_PT)` octets of plaintext, as
/// its `ch_write` cuts them, each `REC_OVERHEAD` octets longer once sealed.
fn encrypt_record(
    context: *anyopaque,
    plaintext: []const u8,
    output: []u8,
) tls.provider.SealError!tls.provider.Sealed {
    const role = held(context);
    if (plaintext.len == 0) return .{ .consumed = 0, .written = 0 };
    const limit: usize = @min(role.session.peer_limit, c.CH_TX_PT);
    const fits = sealable_len(plaintext.len, output.len, limit, c.REC_OVERHEAD);
    // RFC 9846 §5.2: a record carries at least one octet of application data here, so an output
    // that cannot hold one record of one octet takes nothing.
    if (fits == 0) return tls.provider.SealError.NoSpaceLeft;
    role.io = .{ .records = .{ .output = output } };
    if (c.ch_write(role.session, plaintext.ptr, fits) != ok) return tls.provider.SealError.TlsFailed;
    return .{ .consumed = fits, .written = role.io.records.written };
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
/// records, and chapulin reads both inside `ch_read`. So colibri hands over no handshake octets
/// here, and this answers 0 for the life of the connection.
fn handshake_read(context: *anyopaque, input: []const u8, now_ns: u64) tls.provider.HandshakeReadError!usize {
    _ = .{ context, input, now_ns };
    return 0;
}

/// What chapulin sent from inside `ch_read` (`owed`), whole: RFC 9846 §4.7.3's KeyUpdate reply is
/// protected under the keys it replaces, so none of it may follow a record sealed after it. An
/// output that cannot hold all of it takes none.
fn handshake_write(context: *anyopaque, output: []u8, now_ns: u64) tls.provider.HandshakeWriteError!usize {
    _ = now_ns;
    const role = held(context);
    if (role.owed_len > output.len) return tls.provider.HandshakeWriteError.NoSpaceLeft;
    const written = role.owed_len;
    @memcpy(output[0..written], role.owed[0..written]);
    role.owed_len = 0;
    return written;
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
    c.ch_close(role.session);
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

/// RFC 9846 §7.5's exporter, which chapulin's `EXPORTER=on` build offers as `ch_export`. h2 needs
/// none of it; the check endpoints compare it with their peer's, which is how they tell that both
/// ends derived one set of secrets.
///
/// chapulin answers only while its session is connected. A session that closed or failed has
/// wiped the secret, and this adapter reports that as the secret not existing, as before the
/// handshake completed. §7.5 computes one value for no context and for an empty one, so both go
/// to chapulin as a null pointer and a zero length.
fn export_keying_material(
    context: *anyopaque,
    label: []const u8,
    context_value: ?[]const u8,
    output: []u8,
) tls.provider.ExportError!void {
    const role = held(context);
    if (role.session.state != c.CH_ST_CONNECTED) return tls.provider.ExportError.HandshakeIncomplete;
    // chapulin's bound is 255 octets, lower than the 255 hash lengths of RFC 5869 §2.3 that the
    // error names, and a provider enforces its own.
    if (output.len > c.CH_EXPORT_MAX) return tls.provider.ExportError.OutputTooLong;
    // chapulin refuses a zero length, and there is nothing to write.
    if (output.len == 0) return;
    var label_storage: [c.CH_EXPORT_LABEL_MAX + 1]u8 = undefined;
    const label_terminated = label_string(label, &label_storage) orelse
        return tls.provider.ExportError.Unsupported;
    const value = context_value orelse &.{};
    const value_pointer: ?[*]const u8 = if (value.len == 0) null else value.ptr;
    const code = c.ch_export(role.session, label_terminated, value_pointer, value.len, output.ptr, output.len);
    // Every argument rule chapulin's `tls.h` names is checked above, so a refusal here is a
    // defect in this adapter or in chapulin, not a condition colibri could handle.
    std.debug.assert(code == ok);
}

/// chapulin takes an exporter label as a C string of 1 to `CH_EXPORT_LABEL_MAX` octets. A label
/// outside that bound, or one holding a zero octet a C string would end at, answers null: it is a
/// label this provider has no exporter for.
fn label_string(label: []const u8, storage: *[c.CH_EXPORT_LABEL_MAX + 1]u8) ?[*:0]const u8 {
    if (label.len == 0 or label.len > c.CH_EXPORT_LABEL_MAX) return null;
    if (std.mem.indexOfScalar(u8, label, 0) != null) return null;
    @memcpy(storage[0..label.len], label);
    storage[label.len] = 0;
    return storage[0..label.len :0].ptr;
}

/// The calls colibri makes on a chapulin session, whichever side it is. Every member is mandatory
/// (decision 8), so the one chapulin does not offer answers `Unsupported` rather than being absent.
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

test {
    _ = @import("chapulin_record_test.zig");
}
