//! chapulin's TLS 1.3 client behind colibri's `tls.Provider`, for `src/testing/` alone
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 5's TLS half.
//!
//! **Two phases, because the two sides meet the socket at different places.** colibri's vtable is
//! buffer in and buffer out: it never reads a descriptor, and `attach_tls` refuses a handshake
//! that has not already completed. chapulin's `ch_connect` is the opposite — it drives the whole
//! handshake itself through the `send` and `recv` callbacks of its config. The seam is those two
//! callbacks, and this file moves them:
//!
//!   1. **Handshake.** The callbacks read and write the socket, and `ch_connect` runs to
//!      completion. colibri is not involved and owns nothing yet.
//!   2. **Records.** The callbacks serve slices colibri passed in, so `ch_write` seals into
//!      colibri's output and `ch_read` opens from colibri's input. No descriptor is touched.
//!
//! Phase 2 is what lets a socket-owning TLS stack fill a vtable that owns no I/O. It works
//! because colibri hands over whole records: `decrypt_record` is called with a complete record,
//! so the `recv` callback never runs dry, which matters because chapulin's `io.c` turns any
//! `recv` of zero or less into `CH_EIO` and no callback of its can say "nothing yet"
//! ([decision 46](../../../docs/decisions.md)).
//!
//! The handshake blocks, so an endpoint using this drives **one connection at a time**. The
//! 64-connection poll loop stays cleartext until chapulin's callbacks can report "nothing yet".
const std = @import("std");
const tls = @import("tls");
const constants = @import("../constants.zig");
const chapulin = @import("chapulin.zig");

const c = chapulin.c;
const posix = std.posix;

pub const Error = error{
    /// chapulin refused the configuration before sending anything, which is a defect in how
    /// colibri built it rather than anything the peer did.
    ConfigRefused,
    /// The handshake did not complete (RFC 9846 §6). chapulin has raised its own alert.
    HandshakeFailed,
};

/// What the caller provides. The octets are the caller's and must outlive the session, which is
/// chapulin's rule for both lists and colibri's rule for every buffer (decision 35).
pub const Options = struct {
    /// The trust anchors, each an SPKI, as chapulin's `ch_trust_anchor` carries them.
    anchors: []const c.ch_trust_anchor,
    /// The name the certificate must carry (RFC 9110 §4.3.4).
    hostname: []const u8,
    /// The connected socket. It stays the caller's: this file never opens or closes one.
    socket: posix.socket_t,
    /// chapulin's receive buffer. Its size less record overhead is advertised to the peer as
    /// `record_size_limit`, so the peer can never overflow it. The caller owns it, like every
    /// buffer colibri touches (decision 35), and `tools/tls_handshake.sh` varies it to measure
    /// the smallest a real server's flight fits in.
    receive: []u8,
    /// The instant, in seconds since 1970-01-01T00:00:00Z. A webpki chain is valid only at a
    /// time, and chapulin compares every certificate against this one with no skew. It is a
    /// parameter because no file under `src/` may read a clock (non-negotiable 3), this one
    /// included: the caller reads it and passes it in.
    now_seconds: u64,
};

/// Where chapulin's callbacks read and write. The phase moves once, when the handshake ends, and
/// never moves back.
pub const Io = union(enum) {
    /// Phase 1: the socket the caller connected.
    socket: posix.socket_t,
    /// Phase 2: the slices colibri passed into `encrypt_record` or `decrypt_record`.
    records: Records,
};

const Records = struct {
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

pub const Client = struct {
    session: c.ch_tls,
    config: c.ch_cfg,
    /// The one protocol colibri offers. RFC 9113 §3.1: "h2" identifies HTTP/2 over TLS.
    alpn: [1]c.ch_alpn_protocol,
    io: Io,
    /// Whether `close_notify` has gone out, so a second call writes nothing (RFC 9846 §6.1).
    closed: bool,
    /// What chapulin last answered. It is one of its `CH_E*` codes, which `reason` names.
    code: c_int,

    /// Builds the configuration and checks it, without sending anything.
    pub fn init(client: *Client, options: Options) Error!void {
        // The two chapulin structs are zeroed field by field, because a union has no zero and
        // chapulin reads every field it declares.
        client.session = std.mem.zeroes(c.ch_tls);
        client.config = std.mem.zeroes(c.ch_cfg);
        client.io = .{ .socket = options.socket };
        client.closed = false;
        client.code = ok;
        // RFC 9113 §3.1: h2 over TLS is selected by ALPN, and colibri offers that and nothing
        // else, so a server that will not speak h2 fails the handshake rather than the request.
        client.alpn[0] = .{ .name = alpn_h2.ptr, .name_len = alpn_h2.len };
        client.config = .{
            .buf = options.receive.ptr,
            .buf_len = options.receive.len,
            .send = send,
            .recv = recv,
            .io = @ptrCast(&client.io),
            .anchors = options.anchors.ptr,
            .anchor_count = options.anchors.len,
            .hostname = options.hostname.ptr,
            .hostname_len = options.hostname.len,
            .alpn_protocols = &client.alpn,
            .alpn_count = client.alpn.len,
            .now_seconds = options.now_seconds,
        };
    }

    /// Runs the handshake to completion (phase 1). It blocks, so one connection at a time.
    pub fn handshake(client: *Client) Error!void {
        client.code = c.ch_connect(&client.session, &client.config);
        if (client.code != ok) return Error.HandshakeFailed;
        // Phase 2 from here: nothing below this line touches the descriptor again.
        client.io = .{ .records = .{} };
    }

    /// RFC 7301 §3.1: what the server selected, or null when it selected nothing. In TLS 1.3 the
    /// selection arrives in EncryptedExtensions, so null before that is an answer and not an error.
    /// The session colibri drives, and the calls it makes on it.
    pub fn provider(client: *Client) tls.Provider {
        return .{ .context = @ptrCast(client), .vtable = &vtable };
    }

    pub fn negotiated_alpn(client: *const Client) ?[]const u8 {
        // A session that has not handshaked is all zeros, and chapulin's CH_ALPN_NONE is 255,
        // so a zeroed `alpn_selected` reads as index 0 — the protocol colibri offered. Asking
        // the phase first is what keeps an untouched session from reporting a selection.
        if (client.io != .records) return null;
        if (client.session.alpn_selected == c.CH_ALPN_NONE) return null;
        return alpn_h2;
    }
};

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

/// RFC 9113 §3.1's identifier, which is the two octets 0x68 0x32.
pub const alpn_h2 = "h2";

/// chapulin answers 0 for success and a negative `CH_E*` for everything else. The `send`
/// callback shares the convention; `recv` does not, and returns a count.
const ok: c_int = 0;
const failed: c_int = -1;

/// chapulin's `send`: in phase 1 the socket, in phase 2 colibri's output buffer.
///
/// It moves every octet and answers 0. chapulin's `cfg.h` is explicit that anything else, "including
/// a positive byte count, is failure", so this must not report what it wrote.
pub fn send(io: ?*anyopaque, octets: [*c]const u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    switch (state.*) {
        .socket => |descriptor| {
            // Blocking, with no MSG_DONTWAIT: chapulin's callbacks cannot report "nothing yet",
            // so the handshake waits here rather than answering short (decision 46). A blocking
            // send may still move fewer octets than asked, so this loops until all are gone.
            var sent: usize = 0;
            // Bounded by `len`, and every pass moves at least one octet or returns.
            while (sent < len) {
                const wrote = std.c.send(descriptor, octets + sent, len - sent, 0);
                if (wrote <= 0) return failed;
                sent += @intCast(wrote);
            }
            return ok;
        },
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

/// Opens one record into `plaintext` (RFC 9846 §5.2), and says what it held.
///
/// chapulin's `ch_read` handles NewSessionTicket and KeyUpdate itself and returns only
/// application data, so a record holding one of those produces no plaintext and `ch_read` reads
/// on for more. In phase 2 there is no more: colibri passes one record, the `recv` callback runs
/// dry, and `ch_read` answers with an error. That is not a failure, and treating it as one would
/// close a healthy connection the first time a server sent a ticket, which servers do routinely.
///
/// So a call that took the whole record, produced no plaintext and then ran dry is reported as a
/// post-handshake message. colibri cannot tell a ticket from a key update here and does not need
/// to: RFC 9113 §9.2.3 permits both and h2 does nothing with either. What colibri would need to
/// tell apart is a CertificateRequest, which §9.2.3 makes a connection error; chapulin refuses
/// that itself and answers an error with nothing consumed, which reaches colibri as `TlsFailed`
/// and closes the connection for the same reason under a different name.
fn decrypt_record(context: *anyopaque, input: []const u8, plaintext: []u8) tls.provider.OpenError!tls.provider.Opened {
    const client: *Client = @ptrCast(@alignCast(context));
    client.io = .{ .records = .{ .input = input } };
    const read = c.ch_read(&client.session, plaintext.ptr, plaintext.len);
    const records = client.io.records;
    if (read > 0) return .{
        .consumed = records.taken,
        .plaintext_len = @intCast(read),
        .content = .application_data,
    };
    // RFC 9846 §6.1: chapulin answers 0 for a clean peer close, which is a `close_notify`.
    if (read == 0) return .{ .consumed = records.taken, .plaintext_len = 0, .content = .alert };
    if (records.ran_dry and records.taken == input.len and input.len > 0) {
        return .{ .consumed = records.taken, .plaintext_len = 0, .content = .new_session_ticket };
    }
    // Nothing was taken, so no whole record was there and the caller reads more.
    if (records.taken == 0) return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
    return tls.provider.OpenError.TlsFailed;
}

/// Protects `plaintext` as one or more records (RFC 9846 §5.2).
fn encrypt_record(context: *anyopaque, plaintext: []const u8, output: []u8) tls.provider.SealError!tls.provider.Sealed {
    const client: *Client = @ptrCast(@alignCast(context));
    client.io = .{ .records = .{ .output = output } };
    // chapulin seals and hands the octets to `send`, which writes them into colibri's output.
    // A short output reaches it as a failed send, so nothing is half-written.
    if (c.ch_write(&client.session, plaintext.ptr, plaintext.len) != ok) {
        if (client.io.records.written == 0) return tls.provider.SealError.NoSpaceLeft;
        return tls.provider.SealError.TlsFailed;
    }
    return .{ .consumed = plaintext.len, .written = client.io.records.written };
}

/// RFC 9846 §4.3.1 and Appendix B.4: the version and the suite the handshake selected.
///
/// **colibri derives the suite rather than reading it, and that is a gap worth naming.** A
/// chapulin client keeps no `suite` field: its `session.h` declares one only under
/// `CH_ROLE_SERVER`, because a client "offers exactly one of everything". So colibri reports the
/// one suite the linked build offers, which `handshake_message.c` writes as the single entry of
/// its ClientHello.
///
/// Today that is TLS_CHACHA20_POLY1305_SHA256. It will not always be: RFC 9846 §9.1 makes
/// TLS_AES_128_GCM_SHA256 mandatory to implement, chapulin does not offer it yet, and its
/// `docs/aes_suite.md` scopes the work. When that lands, a client build may offer two suites and
/// this function will report the wrong one until chapulin exposes what was selected. The run in
/// `tools/tls_handshake.sh` prints the suite, so a change shows there first.
fn negotiated_parameters(context: *const anyopaque) ?tls.Negotiated {
    const client: *const Client = @ptrCast(@alignCast(context));
    if (!handshake_complete(context)) return null;
    _ = client;
    return .{
        .version = tls_1_3,
        .cipher_suite = tls.constants.cipher_suite_chacha20_poly1305_sha256,
    };
}

/// RFC 9846 Appendix E.5: an application must be able to tell. chapulin reaches its established
/// state only when `ch_connect` returned success, which is when this file leaves phase 1.
fn handshake_complete(context: *const anyopaque) bool {
    const client: *const Client = @ptrCast(@alignCast(context));
    return client.io == .records;
}

/// RFC 9846 Appendix B.1: the TLS 1.3 codepoint. chapulin speaks 1.3 and nothing else, so a
/// completed handshake negotiated it.
pub const tls_1_3: u16 = 0x0304;

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

/// chapulin's TLS mode keeps no alert on the session a caller can read: `session.h` declares the
/// field on `ch_quic` for QUIC mode and nowhere for records. So colibri learns that a session
/// failed and not which description said so, and closes without naming one.
fn take_alert(context: *anyopaque) ?tls.AlertReport {
    _ = context;
    return null;
}

/// RFC 9846 §6.1's `close_notify`. `ch_close` sends it through the same `send` callback, which
/// in phase 2 writes into colibri's output, and then wipes the key material.
fn send_close_notify(context: *anyopaque, output: []u8) tls.provider.CloseError!usize {
    const client: *Client = @ptrCast(@alignCast(context));
    if (client.closed) return 0;
    client.io = .{ .records = .{ .output = output } };
    c.ch_close(&client.session);
    client.closed = true;
    return client.io.records.written;
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

/// RFC 7301 §3.1, read through the vtable.
fn vtable_negotiated_alpn(context: *const anyopaque) ?[]const u8 {
    const client: *const Client = @ptrCast(@alignCast(context));
    return client.negotiated_alpn();
}

/// The calls colibri makes on this session. Every member is mandatory (decision 8), so the two
/// chapulin does not offer answer `Unsupported` rather than being absent.
pub const vtable: tls.VTable = .{
    .handshake_read = handshake_read,
    .handshake_write = handshake_write,
    .encrypt_record = encrypt_record,
    .decrypt_record = decrypt_record,
    .negotiated_alpn = vtable_negotiated_alpn,
    .handshake_complete = handshake_complete,
    .negotiated_parameters = negotiated_parameters,
    .take_alert = take_alert,
    .send_close_notify = send_close_notify,
    .initiate_key_update = initiate_key_update,
    .export_keying_material = export_keying_material,
};

test {
    _ = @import("chapulin_client_test.zig");
}
