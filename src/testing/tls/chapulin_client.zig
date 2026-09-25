//! chapulin's TLS 1.3 client behind colibri's `tls.Provider`, for `src/testing/` alone
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 5's TLS half.
//!
//! This file is phase 1: building the configuration and driving chapulin's
//! `TRANSPORT=tcp-nonblocking` client handshake. `start` stages the ClientHello, and each call to
//! `handshake` passes what the caller read to `ch_record_in` and collects what chapulin owes the
//! server from `ch_record_out` into the caller's output. No call here touches a descriptor or waits
//! (decision 46). Phase 2, the record phase colibri drives through the vtable, is
//! `chapulin_record.zig` and is shared with the server.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const chapulin = @import("chapulin.zig");
const chapulin_record = @import("chapulin_record.zig");
const constants = @import("../constants.zig");

const c = chapulin.c;

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
    /// The handshake did not complete (RFC 9846 §6). `alert` names what chapulin chose.
    HandshakeFailed,
};

/// What the caller provides. The octets are the caller's and must outlive the session, which is
/// chapulin's rule for both lists and colibri's rule for every buffer (decision 35).
pub const Options = struct {
    /// The trust anchors, each an SPKI, as chapulin's `ch_trust_anchor` carries them.
    anchors: []const c.ch_trust_anchor,
    /// The name the certificate must carry (RFC 9110 §4.3.4).
    hostname: []const u8,
    /// chapulin's receive buffer. Its size less record overhead is advertised to the peer as
    /// `record_size_limit`, so the peer can never overflow it. `tools/tls_handshake.sh` varies it
    /// to measure the smallest a real server's flight fits in.
    receive: []u8,
    /// The instant, in seconds since 1970-01-01T00:00:00Z. A webpki chain is valid only at a
    /// time, and chapulin compares every certificate against this one with no skew. It is a
    /// parameter because no file under `src/` may read a clock (non-negotiable 3), this one
    /// included: the caller reads it and passes it in.
    now_seconds: u64,
    /// The protocols to offer through ALPN, most preferred first (RFC 7301 §3.1).
    protocols: []const []const u8 = &.{alpn_h2},
};

/// What one call to `handshake` did.
pub const Progress = struct {
    /// Octets of the input chapulin took: whole records only (`rec.h`).
    consumed: usize,
    /// Octets written into the output, to be sent in order.
    written: usize,
    /// Whether the handshake completed, so the provider is ready for `attach_tls`.
    complete: bool,
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
    /// chapulin's record-mode handshake, whose `t` is the session. It is not copyable, because
    /// chapulin keeps a pointer into it (`rec.h`).
    record: c.ch_record,
    /// Everything the record phase touches, whose address is the provider's context.
    held: Held,
    config: c.ch_cfg,
    /// The protocols colibri offers (`Options.protocols`).
    alpn: [constants.alpn_offered_max]c.ch_alpn_protocol,
    /// What chapulin last answered. It is one of its `CH_E*` codes, which `reason` names.
    code: c_int,

    /// Builds the configuration, without sending anything.
    pub fn init(client: *Client, options: Options) void {
        // The chapulin structs are zeroed field by field, because a union has no zero and
        // chapulin reads every field it declares.
        client.record = std.mem.zeroes(c.ch_record);
        client.held.session = &client.record.t;
        client.held.io = .{ .handshake = .{} };
        client.held.closed = false;
        client.held.pending_alert = null;
        client.held.suite = 0;
        client.held.owed_len = 0;
        client.code = ok;
        // RFC 9113 §3.1: h2 over TLS is selected by ALPN, and so is http/1.1 (RFC 7301 §6),
        // offered in decision 88's order.
        assert(options.protocols.len > 0 and options.protocols.len <= client.alpn.len);
        for (options.protocols, 0..) |name, index| client.alpn[index] = .{ .name = name.ptr, .name_len = name.len };
        client.held.alpn = client.alpn[0..options.protocols.len];
        client.config = std.mem.zeroes(c.ch_cfg);
        client.config.buf = options.receive.ptr;
        client.config.buf_len = options.receive.len;
        // chapulin requires both, though its record-mode handshake calls neither: `ch_read` and
        // `ch_write` call them once the session is connected (`rec.h`).
        client.config.send = send;
        client.config.recv = recv;
        client.config.io = @ptrCast(&client.held.io);
        client.config.anchors = options.anchors.ptr;
        client.config.anchor_count = options.anchors.len;
        client.config.hostname = options.hostname.ptr;
        client.config.hostname_len = options.hostname.len;
        client.config.alpn_protocols = &client.alpn;
        client.config.alpn_count = options.protocols.len;
        client.config.now_seconds = options.now_seconds;
    }

    /// Stages the ClientHello, which the next `handshake` call writes out (`rec.h`).
    pub fn start(client: *Client) Error!void {
        client.code = c.ch_record_init(&client.record, &client.config);
        if (client.code != ok) return Error.ConfigRefused;
        // `ch_record_init` placed a new session at the same address.
        assert(client.held.session == &client.record.t);
    }

    /// Passes what the caller read to chapulin and writes what it owes the server into `output`.
    /// chapulin takes whole records and leaves a trailing partial one for the caller to pass again
    /// with what follows it; the input is mutable because chapulin unprotects a record in place.
    pub fn handshake(client: *Client, input: []u8, output: []u8) Error!Progress {
        assert(client.held.io == .handshake);
        var consumed: usize = 0;
        if (input.len > 0) {
            client.code = c.ch_record_in(&client.record, input.ptr, input.len, &consumed);
            if (client.code != ok) return Error.HandshakeFailed;
        }
        const written = try client.collect(output);
        const complete = c.ch_record_state(&client.record) == c.CH_ST_CONNECTED;
        if (complete) {
            // Phase 2 from here.
            client.held.suite = client_suite;
            client.held.io = .{ .records = .{} };
        }
        return .{ .consumed = consumed, .written = written, .complete = complete };
    }

    /// Collects what chapulin has staged for the server, as much as `output` holds. chapulin
    /// stages into one buffer, so one call drains it or fills `output`; what does not fit stays
    /// staged for the next call (`rec.h`).
    fn collect(client: *Client, output: []u8) Error!usize {
        // `ch_record_out` refuses a capacity of 0 and would fail the handshake.
        if (output.len == 0) return 0;
        var collected: usize = 0;
        client.code = c.ch_record_out(&client.record, output.ptr, output.len, &collected);
        if (client.code != ok) return Error.HandshakeFailed;
        assert(collected <= output.len);
        return collected;
    }

    /// Wipes every secret the session still holds and marks it dead (`rec.h`). The caller calls
    /// it once the connection is over, after its `close_notify` or after a failure.
    pub fn close(client: *Client) void {
        c.ch_record_close(&client.record);
        assert(c.ch_record_state(&client.record) != c.CH_ST_CONNECTED);
    }

    /// The alert a failed handshake chose, for the caller to send before it closes (`rec.h`), or
    /// 0 when nothing failed.
    pub fn alert(client: *const Client) u8 {
        return c.ch_record_alert(&client.record);
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
