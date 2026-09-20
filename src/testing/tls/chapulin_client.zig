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
    /// The handshake did not complete (RFC 8446 §6). chapulin has raised its own alert.
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
};

/// Where chapulin's callbacks read and write. The phase moves once, when the handshake ends, and
/// never moves back.
const Io = union(enum) {
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
    /// chapulin's receive buffer, whose size less record overhead it advertises as the peer's
    /// `record_size_limit`, so the peer can never overflow it.
    receive: [constants.tls_receive_len]u8,
    io: Io,
    /// Whether `close_notify` has gone out, so a second call writes nothing (RFC 8446 §6.1).
    closed: bool,

    /// Builds the configuration and checks it, without sending anything.
    pub fn init(client: *Client, options: Options) Error!void {
        // The two chapulin structs are zeroed field by field, because a union has no zero and
        // chapulin reads every field it declares.
        client.session = std.mem.zeroes(c.ch_tls);
        client.config = std.mem.zeroes(c.ch_cfg);
        client.receive = @splat(0);
        client.io = .{ .socket = options.socket };
        client.closed = false;
        // RFC 9113 §3.1: h2 over TLS is selected by ALPN, and colibri offers that and nothing
        // else, so a server that will not speak h2 fails the handshake rather than the request.
        client.alpn[0] = .{ .name = alpn_h2.ptr, .name_len = alpn_h2.len };
        client.config = .{
            .buf = &client.receive,
            .buf_len = client.receive.len,
            .send = send,
            .recv = recv,
            .io = @ptrCast(&client.io),
            .anchors = options.anchors.ptr,
            .anchor_count = options.anchors.len,
            .hostname = options.hostname.ptr,
            .hostname_len = options.hostname.len,
            .alpn_protocols = &client.alpn,
            .alpn_count = client.alpn.len,
        };
    }

    /// Runs the handshake to completion (phase 1). It blocks, so one connection at a time.
    pub fn handshake(client: *Client) Error!void {
        if (c.ch_connect(&client.session, &client.config) != ok) return Error.HandshakeFailed;
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

/// RFC 9113 §3.1's identifier, which is the two octets 0x68 0x32.
const alpn_h2 = "h2";

/// chapulin answers 0 for success and a negative `CH_E*` for everything else.
const ok: c_int = 0;

/// chapulin's `send`: in phase 1 the socket, in phase 2 colibri's output buffer.
fn send(io: ?*anyopaque, octets: [*c]const u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    switch (state.*) {
        .socket => |descriptor| {
            // Blocking, with no MSG_DONTWAIT: chapulin's callbacks cannot report "nothing yet",
            // so the handshake waits here rather than answering short (decision 46).
            const wrote = std.c.send(descriptor, octets, len, 0);
            if (wrote <= 0) return -1;
            return @intCast(wrote);
        },
        .records => |*records| {
            const room = records.output.len - records.written;
            // A short output is colibri's to widen, and chapulin cannot be told to wait, so this
            // fails the call rather than writing part of a record.
            if (len > room) return -1;
            @memcpy(records.output[records.written..][0..len], octets[0..len]);
            records.written += len;
            return @intCast(len);
        },
    }
}

/// chapulin's `recv`: in phase 1 the socket, in phase 2 the record colibri passed in.
fn recv(io: ?*anyopaque, out: [*c]u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    switch (state.*) {
        .socket => |descriptor| {
            const read = std.c.recv(descriptor, out, len, 0);
            if (read <= 0) return -1;
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
                return -1;
            }
            @memcpy(out[0..take], records.input[records.taken..][0..take]);
            records.taken += take;
            return @intCast(take);
        },
    }
}

const testing = std.testing;

/// The client the tests drive, placed outside any stack frame: it carries chapulin's session and
/// its receive buffer, which are larger than a stack frame should hold. Test-only.
var test_client: Client = undefined;
const test_hostname = "localhost";

test "the configuration colibri builds is the one chapulin is given" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{ .anchors = &anchors, .hostname = test_hostname, .socket = 0 });
    // RFC 9113 §3.1: one protocol is offered, and it is "h2".
    try testing.expectEqual(1, test_client.config.alpn_count);
    try testing.expectEqual(alpn_h2.len, test_client.config.alpn_protocols[0].name_len);
    try testing.expectEqualSlices(u8, "h2", test_client.config.alpn_protocols[0].name[0..2]);
    // The receive buffer is colibri's storage, and chapulin advertises its size to the peer.
    try testing.expectEqual(constants.tls_receive_len, test_client.config.buf_len);
    try testing.expectEqual(@intFromPtr(&test_client.receive), @intFromPtr(test_client.config.buf));
    // The hostname is the one the certificate must carry.
    try testing.expectEqual(test_hostname.len, test_client.config.hostname_len);
    // The callbacks point at this file, and their state at the phase.
    try testing.expect(test_client.config.send != null);
    try testing.expect(test_client.config.recv != null);
    try testing.expectEqual(Io.socket, std.meta.activeTag(test_client.io));
}

test "the record phase serves colibri's buffers and never the socket" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{ .anchors = &anchors, .hostname = test_hostname, .socket = 0 });
    // Moving to phase 2 is what `handshake` does on success; the descriptor is never used again.
    var input = [_]u8{ 1, 2, 3, 4 };
    var output: [8]u8 = @splat(0);
    test_client.io = .{ .records = .{ .input = &input, .output = &output } };
    // `recv` hands chapulin the octets colibri passed, in order, and stops at the end of them.
    var taken: [4]u8 = @splat(0);
    try testing.expectEqual(2, recv(@ptrCast(&test_client.io), &taken, 2));
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, taken[0..2]);
    try testing.expectEqual(2, recv(@ptrCast(&test_client.io), &taken, 4));
    try testing.expectEqualSlices(u8, &.{ 3, 4 }, taken[0..2]);
    // Past the end it fails rather than blocking, because no callback of chapulin's can say
    // "nothing yet" and colibri only ever passes a whole record.
    try testing.expectEqual(-1, recv(@ptrCast(&test_client.io), &taken, 1));
    // `send` fills colibri's output and refuses to write part of a record into a short one.
    const sealed = [_]u8{ 9, 9, 9 };
    try testing.expectEqual(3, send(@ptrCast(&test_client.io), &sealed, 3));
    try testing.expectEqualSlices(u8, &.{ 9, 9, 9 }, output[0..3]);
    try testing.expectEqual(3, test_client.io.records.written);
    try testing.expectEqual(-1, send(@ptrCast(&test_client.io), &sealed, 6));
    try testing.expectEqual(3, test_client.io.records.written);
}

/// Opens one record into `plaintext` (RFC 8446 §5.2), and says what it held.
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
    // RFC 8446 §6.1: chapulin answers 0 for a clean peer close, which is a `close_notify`.
    if (read == 0) return .{ .consumed = records.taken, .plaintext_len = 0, .content = .alert };
    if (records.ran_dry and records.taken == input.len and input.len > 0) {
        return .{ .consumed = records.taken, .plaintext_len = 0, .content = .new_session_ticket };
    }
    // Nothing was taken, so no whole record was there and the caller reads more.
    if (records.taken == 0) return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
    return tls.provider.OpenError.TlsFailed;
}

/// Protects `plaintext` as one or more records (RFC 8446 §5.2).
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

/// RFC 8446 §4.2.1 and Appendix B.4. A chapulin client offers exactly one suite, so its session
/// carries no `suite` field to read: its own `session.h` says a client "offers exactly one of
/// everything". So colibri names what the build it linked offers. An `AES=soft` build compiles
/// the ChaCha20-Poly1305 code, and chapulin's `CH_SUITE_AES_GCM` needs `AES=hw`, so the suite is
/// TLS_CHACHA20_POLY1305_SHA256. colibri admits it (decision 45) and names it from its own
/// constants rather than reaching into a chapulin header the public API does not carry.
fn negotiated_parameters(context: *const anyopaque) ?tls.Negotiated {
    const client: *const Client = @ptrCast(@alignCast(context));
    if (!handshake_complete(context)) return null;
    _ = client;
    return .{
        .version = tls_1_3,
        .cipher_suite = tls.constants.cipher_suite_chacha20_poly1305_sha256,
    };
}

/// RFC 8446 Appendix E.5: an application must be able to tell. chapulin reaches its established
/// state only when `ch_connect` returned success, which is when this file leaves phase 1.
fn handshake_complete(context: *const anyopaque) bool {
    const client: *const Client = @ptrCast(@alignCast(context));
    return client.io == .records;
}

/// RFC 8446 Appendix B.1: the TLS 1.3 codepoint. chapulin speaks 1.3 and nothing else, so a
/// completed handshake negotiated it.
const tls_1_3: u16 = 0x0304;

/// RFC 8446 §4.6.3 and §4.6.1: after the handshake, a peer's KeyUpdate and NewSessionTicket ride
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

/// RFC 8446 §6.1's `close_notify`. `ch_close` sends it through the same `send` callback, which
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

/// RFC 8446 §7.5 standardises the exporter without obliging a stack to offer it, and chapulin's
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

test "the vtable colibri gets answers every member" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{ .anchors = &anchors, .hostname = test_hostname, .socket = 0 });
    const held = test_client.provider();
    var room: [64]u8 = @splat(0);

    // Before the handshake nothing is negotiated. RFC 7301 §3.1's selection arrives in
    // EncryptedExtensions, and chapulin's CH_ALPN_NONE is 255, so a zeroed session must not
    // read as having chosen the protocol at index 0.
    try testing.expect(!held.vtable.handshake_complete(held.context));
    try testing.expectEqual(null, held.vtable.negotiated_alpn(held.context));
    try testing.expectEqual(null, held.vtable.negotiated_parameters(held.context));

    // RFC 8446 §4.6.3 and §4.6.1: chapulin answers a peer's KeyUpdate and NewSessionTicket
    // inside `ch_read`, so colibri owes no handshake octets and consumes none.
    try testing.expectEqual(0, try held.vtable.handshake_write(held.context, &room, 0));
    try testing.expectEqual(0, try held.vtable.handshake_read(held.context, &room, 0));

    // A session that has not failed has no alert to report.
    try testing.expectEqual(null, held.vtable.take_alert(held.context));

    // Every member is mandatory (decision 8), so the two chapulin does not offer refuse rather
    // than being absent.
    const update = held.vtable.initiate_key_update(held.context, .update_not_requested, &room);
    try testing.expectError(error.Unsupported, update);
    const exported = held.vtable.export_keying_material(held.context, "colibri", null, &room);
    try testing.expectError(error.Unsupported, exported);
}

test "once the handshake is done the session reports what it chose" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{ .anchors = &anchors, .hostname = test_hostname, .socket = 0 });
    // What `handshake` does on success. The live handshake is a separate check; this pins what
    // colibri reads afterwards.
    test_client.io = .{ .records = .{} };
    test_client.session.alpn_selected = 0;
    const held = test_client.provider();
    try testing.expect(held.vtable.handshake_complete(held.context));
    try testing.expectEqualStrings("h2", held.vtable.negotiated_alpn(held.context).?);
    // RFC 9113 §9.2: colibri needs both codepoints, and admits this suite (decision 45).
    const negotiated = held.vtable.negotiated_parameters(held.context).?;
    try testing.expectEqual(tls_1_3, negotiated.version);
    try testing.expectEqual(tls.constants.cipher_suite_chacha20_poly1305_sha256, negotiated.cipher_suite);
    // A server that selected nothing leaves colibri with no protocol, which `attach_tls` refuses.
    test_client.session.alpn_selected = c.CH_ALPN_NONE;
    try testing.expectEqual(null, held.vtable.negotiated_alpn(held.context));
}
