//! chapulin's TLS 1.3 client behind colibri's `tls.Provider`, for `src/testing/` alone
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 5's TLS half.
//!
//! This file is phase 1 — building the configuration and running `ch_connect` over the socket.
//! Phase 2, the record phase colibri drives through the vtable, is `chapulin_record.zig` and is
//! shared with the server, because nothing about `ch_read`, `ch_write` and `ch_close` is a role.
//!
//! The handshake blocks, so an endpoint using this drives **one connection at a time**. The h2
//! client's loop stays cleartext until it links chapulin's record-mode client, as the server links
//! the record-mode server ([decision 46](../../../docs/decisions.md), decision 82).
const std = @import("std");
const tls = @import("tls");
const chapulin = @import("chapulin.zig");
const chapulin_record = @import("chapulin_record.zig");

const c = chapulin.c;
const posix = std.posix;

/// The record phase is the same on both sides, so its names are re-exported here rather than
/// duplicated. One name per thing: these are aliases, not copies.
pub const Held = chapulin_record.Held;
pub const Io = chapulin_record.Io;
pub const Records = chapulin_record.Records;
pub const send = chapulin_record.send;
pub const recv = chapulin_record.recv;
pub const reason = chapulin_record.reason;
pub const alpn_h2 = chapulin_record.alpn_h2;
pub const tls_1_3 = chapulin_record.tls_1_3;

const ok = chapulin_record.ok;

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

/// **colibri reports the suite rather than reading it, and that is a gap worth naming.** A
/// chapulin client keeps no `suite` field: its `session.h` declares one only under
/// `CH_ROLE_SERVER`, because a client "offers exactly one of everything". So colibri reports the
/// one suite the linked build offers, which `handshake_message.c` writes as the single entry of
/// its ClientHello. A server has the field and reads it, which is why `Held.suite` exists.
///
/// Today that is TLS_CHACHA20_POLY1305_SHA256. It will not always be: RFC 9846 §9.1 makes
/// TLS_AES_128_GCM_SHA256 mandatory to implement, chapulin does not offer it yet, and its
/// `docs/aes_suite.md` scopes the work. When that lands, a client build may offer two suites and
/// this constant will report the wrong one until chapulin exposes what was selected. The run in
/// `tools/tls_handshake.sh` prints the suite, so a change shows there first.
pub const client_suite = tls.constants.cipher_suite_chacha20_poly1305_sha256;

pub const Client = struct {
    /// chapulin's session, which `held` points at.
    session: c.ch_tls,
    /// Everything the record phase touches, whose address is the provider's context.
    held: Held,
    config: c.ch_cfg,
    /// The one protocol colibri offers. RFC 9113 §3.1: "h2" identifies HTTP/2 over TLS.
    alpn: [1]c.ch_alpn_protocol,
    /// What chapulin last answered. It is one of its `CH_E*` codes, which `reason` names.
    code: c_int,

    /// Builds the configuration and checks it, without sending anything.
    pub fn init(client: *Client, options: Options) Error!void {
        // The two chapulin structs are zeroed field by field, because a union has no zero and
        // chapulin reads every field it declares.
        client.session = std.mem.zeroes(c.ch_tls);
        client.held.session = &client.session;
        client.config = std.mem.zeroes(c.ch_cfg);
        client.held.io = .{ .socket = options.socket };
        client.held.closed = false;
        client.held.pending_alert = null;
        client.held.suite = 0;
        client.code = ok;
        // RFC 9113 §3.1: h2 over TLS is selected by ALPN, and colibri offers that and nothing
        // else, so a server that will not speak h2 fails the handshake rather than the request.
        client.alpn[0] = .{ .name = alpn_h2.ptr, .name_len = alpn_h2.len };
        client.config = .{
            .buf = options.receive.ptr,
            .buf_len = options.receive.len,
            .send = send,
            .recv = recv,
            .io = @ptrCast(&client.held.io),
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
        client.held.suite = client_suite;
        client.held.io = .{ .records = .{} };
    }

    /// The session colibri drives, and the calls it makes on it.
    pub fn provider(client: *Client) tls.Provider {
        return .{ .context = @ptrCast(&client.held), .vtable = &vtable };
    }

    /// RFC 7301 §3.1: what the server selected, or null when it selected nothing. In TLS 1.3 the
    /// selection arrives in EncryptedExtensions, so null before that is an answer and not an
    /// error.
    pub fn negotiated_alpn(client: *Client) ?[]const u8 {
        const held = client.provider();
        return held.vtable.negotiated_alpn(held.context);
    }
};

/// The calls colibri makes on this session, which the record phase writes once for both roles.
pub const vtable = chapulin_record.vtable;

test {
    _ = @import("chapulin_client_test.zig");
}
