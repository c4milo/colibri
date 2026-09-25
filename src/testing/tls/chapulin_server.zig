//! chapulin's TLS 1.3 server behind colibri's `tls.Provider`, for `src/testing/` alone
//! ([decision 10](../../../docs/decisions.md)). The other half of design §8 step 5's TLS work.
//!
//! This file is phase 1: building the configuration and driving chapulin's `TRANSPORT=record`
//! handshake. The caller reads octets from its socket and passes them to `handshake`, which runs
//! `ch_srv_record_in` over them and returns the server's flight in the caller's output. No call
//! here touches a descriptor or waits, so the h2 endpoint drives a handshake from its loop's
//! events ([decision 46](../../../docs/decisions.md),
//! https://github.com/c4milo/colibri/issues/20). Phase 2, the record phase colibri drives through
//! the vtable, is `chapulin_record.zig` and is shared with the client.
//!
//! What differs from the client is the configuration. A server proves an identity instead of
//! judging one, so it carries a certificate chain and a signing key rather than trust anchors and
//! a hostname, and `ch_srv_check` tests at boot that the build can sign with each provisioned
//! key. A server also needs RFC 9846 §4.3.2's cookie key, which chapulin requires on every
//! handshake and not only when it sends a HelloRetryRequest.
//!
//! One thing the server reads that the client cannot: `session.suite`. chapulin declares the
//! field under `CH_ROLE_SERVER` alone, so this side reports the suite it selected rather than the
//! one its build offers.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const chapulin = @import("chapulin.zig");
const chapulin_record = @import("chapulin_record.zig");

const c = chapulin.c;

/// The record phase is the same on both sides, so its names are re-exported rather than
/// duplicated. One name per thing: these are aliases, not copies.
pub const Held = chapulin_record.Held;
pub const Io = chapulin_record.Io;
pub const reason = chapulin_record.reason;
pub const alpn_h2 = chapulin_record.alpn_h2;
pub const tls_1_3 = chapulin_record.tls_1_3;

const ok = chapulin_record.ok;

pub const Error = error{
    /// `ch_srv_check` refused the identities at boot: none provisioned, or a key whose signature
    /// its own verifier rejected. Nothing was served.
    IdentityRefused,
    /// `ch_srv_record_init` refused the configuration before reading a byte.
    ConfigRefused,
    /// The handshake did not complete (RFC 9846 §6). `alert` names what chapulin chose.
    HandshakeFailed,
    /// The output could not hold a record of the flight. chapulin's sink takes a whole record or
    /// fails the handshake, so the session is dead; the caller's output was too small.
    FlightTooLong,
};

/// How many certificates this server presents: the end-entity and the one root above it.
const chain_len: usize = 2;

/// RFC 9846 §4.3.2's cookie key, which `srv_cookie.h` fixes at 32 octets.
pub const cookie_key_len: usize = 32;

/// What `srv_cfg.h` fixes for the ecdsa_secp256r1_sha256 slot: a big-endian private scalar and
/// an uncompressed public point X||Y, each without any tag or prefix.
pub const private_scalar_len: usize = 32;
pub const public_point_len: usize = 64;

/// The signing identity a server provisions. `srv_cfg.h` fixes both lengths for the
/// ecdsa_secp256r1_sha256 slot: a 32-octet big-endian private scalar, and a 64-octet
/// uncompressed public point X||Y.
pub const Identity = struct {
    /// The end-entity certificate first, then the root that signed it (RFC 9846 §4.5.1).
    leaf: []const u8,
    issuer: []const u8,
    private_scalar: []const u8,
    public_point: []const u8,
};

pub const Options = struct {
    identity: Identity,
    /// RFC 9846 §4.3.2: one key per deployment, so a second ClientHello that lands on another
    /// session still verifies. chapulin refuses a configuration without it.
    cookie_key: []const u8,
    /// chapulin's receive buffer. In record mode the handshake reads records in place, and this
    /// holds the records `ch_read` opens afterwards; chapulin advertises its size, less record
    /// overhead, as `record_size_limit`.
    receive: []u8,
};

/// What one call to `handshake` did.
pub const Progress = struct {
    /// Octets of the input chapulin took: whole records only (`srv_rec.h`).
    consumed: usize,
    /// Octets of the flight written into the output, to be sent in order.
    written: usize,
    /// Whether the handshake completed, so the provider is ready for `attach_tls`.
    complete: bool,
};

pub const Server = struct {
    /// chapulin's record-mode handshake, whose `t` is the session. It is not copyable, because
    /// chapulin keeps a pointer into it (`rec.h`).
    record: c.ch_record,
    /// Everything the record phase touches, whose address is the provider's context.
    held: Held,
    config: c.ch_cfg,
    /// The chain, end-entity first then the root that signed it (RFC 9846 §4.5.1).
    chain: [chain_len]c.ch_cert,
    /// The one protocol this server offers (RFC 9113 §3.1).
    alpn: [1]c.ch_alpn_protocol,
    /// What chapulin last answered, which `reason` names.
    code: c_int,

    pub fn init(server: *Server, options: Options) void {
        server.record = std.mem.zeroes(c.ch_record);
        server.held.session = &server.record.t;
        server.config = std.mem.zeroes(c.ch_cfg);
        server.held.io = .{ .handshake = .{} };
        server.held.closed = false;
        server.held.pending_alert = null;
        server.held.suite = 0;
        server.code = ok;
        server.chain[0] = .{ .der = options.identity.leaf.ptr, .len = options.identity.leaf.len };
        server.chain[1] = .{ .der = options.identity.issuer.ptr, .len = options.identity.issuer.len };
        server.alpn[0] = .{ .name = alpn_h2.ptr, .name_len = alpn_h2.len };
        server.config.buf = options.receive.ptr;
        server.config.buf_len = options.receive.len;
        // chapulin requires both, though a record-mode handshake calls neither: `ch_read` and
        // `ch_write` call them once the session is connected (`rec.h`).
        server.config.send = chapulin_record.send;
        server.config.recv = chapulin_record.recv;
        server.config.io = @ptrCast(&server.held.io);
        server.config.alpn_protocols = &server.alpn;
        server.config.alpn_count = server.alpn.len;
        server.config.srv.ecdsa_p256 = .{
            .chain = &server.chain,
            .chain_count = server.chain.len,
            .priv = options.identity.private_scalar.ptr,
            .priv_len = options.identity.private_scalar.len,
            .@"pub" = options.identity.public_point.ptr,
            .pub_len = options.identity.public_point.len,
        };
        server.config.srv.cookie_key = options.cookie_key.ptr;
        server.config.srv.on_record_out = chapulin_record.flight_out;
    }

    /// `ch_srv_check`'s boot-time self-test: every provisioned key signs, and the signature
    /// verifies under the public key in the same slot. It runs no I/O and touches no session, so
    /// a caller runs it once rather than per connection. It draws entropy, so the caller seeds
    /// chapulin's generator first.
    pub fn check(server: *const Server) Error!void {
        if (c.ch_srv_check(&server.config) != ok) return Error.IdentityRefused;
    }

    /// Prepares the session to read a ClientHello. A server speaks second, so nothing is written.
    pub fn start(server: *Server) Error!void {
        server.code = c.ch_srv_record_init(&server.record, &server.config);
        if (server.code != ok) return Error.ConfigRefused;
        // `ch_srv_record_init` placed a new session at the same address.
        assert(server.held.session == &server.record.t);
    }

    /// Runs the handshake over the octets the caller read, and writes the server's flight into
    /// `output`. chapulin takes whole records and runs the handshake as far as they carry it; a
    /// trailing partial record stays for the caller to pass again with what follows it
    /// (`srv_rec.h`). The input is mutable because chapulin unprotects a record in place; the
    /// octets up to `consumed` are rewritten.
    pub fn handshake(server: *Server, input: []u8, output: []u8) Error!Progress {
        assert(server.held.io == .handshake);
        server.held.io = .{ .handshake = .{ .output = output } };
        var consumed: usize = 0;
        server.code = c.ch_srv_record_in(&server.record, input.ptr, input.len, &consumed);
        const written = server.held.io.handshake.written;
        if (server.held.io.handshake.short) return Error.FlightTooLong;
        if (server.code != ok) return Error.HandshakeFailed;
        assert(consumed <= input.len and written <= output.len);
        const complete = c.ch_record_state(&server.record) == c.CH_ST_CONNECTED;
        if (complete) {
            // Phase 2 from here. chapulin declares `suite` under `CH_ROLE_SERVER`, so this side
            // reports what it selected.
            server.held.suite = server.record.t.suite;
            server.held.io = .{ .records = .{} };
        }
        return .{ .consumed = consumed, .written = written, .complete = complete };
    }

    /// The alert a failed handshake chose, for the caller to send before it closes (`rec.h`), or
    /// 0 when nothing failed.
    pub fn alert(server: *const Server) u8 {
        return c.ch_record_alert(&server.record);
    }

    /// The session colibri drives, and the calls it makes on it.
    pub fn provider(server: *Server) tls.Provider {
        return .{ .context = @ptrCast(&server.held), .vtable = &vtable };
    }

    /// RFC 7301 §3.2: what this server selected, or null when it selected nothing.
    pub fn negotiated_alpn(server: *Server) ?[]const u8 {
        const held = server.provider();
        return held.vtable.negotiated_alpn(held.context);
    }
};

/// The calls colibri makes on this session, which the record phase writes once for both roles.
pub const vtable = chapulin_record.vtable;

const testing = std.testing;

/// A server the test drives, and an identity of the right lengths that nothing signs with. The
/// handshake fails before chapulin reads a key. Test-only.
var test_server: if (chapulin.available) Server else void = undefined;
var test_receive: [tls.constants.record_write_len_min]u8 = undefined;
var test_output: [tls.constants.record_write_len_min]u8 = undefined;
/// Each certificate is an empty DER SEQUENCE. Test-only.
const test_der = [_]u8{ der_sequence_tag, 0 };
const der_sequence_tag: u8 = 0x30;
const test_scalar: [private_scalar_len]u8 = @splat(1);
const test_point: [public_point_len]u8 = @splat(1);
const test_cookie: [cookie_key_len]u8 = @splat(1);

test "RFC 9846 §6: a ClientHello chapulin refuses fails the handshake, and nothing completes" {
    if (!chapulin.available) return error.SkipZigTest;
    test_server.init(.{
        .identity = .{ .leaf = &test_der, .issuer = &test_der, .private_scalar = &test_scalar, .public_point = &test_point },
        .cookie_key = &test_cookie,
        .receive = &test_receive,
    });
    try test_server.start();
    // A handshake record holding a ClientHello whose body is empty (RFC 9846 §4.1.2).
    var hello = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00 };
    try testing.expectError(Error.HandshakeFailed, test_server.handshake(&hello, &test_output));
    try testing.expect(test_server.alert() != 0);
    try testing.expect(!test_server.provider().is_complete());
}
