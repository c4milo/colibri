//! chapulin's TLS 1.3 server behind colibri's `tls.Provider`, for `src/testing/` alone
//! ([decision 10](../../../docs/decisions.md)). The other half of design §8 step 5's TLS work.
//!
//! This file is phase 1 — building the configuration and running `ch_srv_accept` over the
//! accepted socket. Phase 2, the record phase colibri drives through the vtable, is
//! `chapulin_record.zig` and is shared with the client: `ch_read`, `ch_write` and `ch_close` are
//! the three calls both roles export and they read the same `ch_tls`.
//!
//! What differs from the client is the configuration. A server proves an identity instead of
//! judging one, so it carries a certificate chain and a signing key rather than trust anchors and
//! a hostname, and `ch_srv_check` tests at boot that the build can sign with each provisioned
//! key. A server also needs RFC 9846 §4.3.2's cookie key, which chapulin requires on every
//! `ch_srv_accept` and not only when it mints a HelloRetryRequest.
//!
//! One thing the server reads that the client cannot: `session.suite`. chapulin declares the
//! field under `CH_ROLE_SERVER` alone, so this side reports the suite it selected rather than the
//! one its build offers.
const std = @import("std");
const tls = @import("tls");
const chapulin = @import("chapulin.zig");
const chapulin_record = @import("chapulin_record.zig");

const c = chapulin.c;
const posix = std.posix;

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
    /// `ch_srv_accept` refused the configuration before reading a byte.
    ConfigRefused,
    /// The handshake did not complete (RFC 9846 §6).
    HandshakeFailed,
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
    /// chapulin's receive buffer, which bounds the ClientHello it will accept. A Go client offers
    /// a post-quantum key share by default, whose ClientHello runs past a kilobyte, so this is
    /// sized well above chapulin's own floor.
    receive: []u8,
    /// The accepted socket. It stays the caller's.
    socket: posix.socket_t,
};

pub const Server = struct {
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
        server.held.session = std.mem.zeroes(c.ch_tls);
        server.config = std.mem.zeroes(c.ch_cfg);
        server.held.io = .{ .socket = options.socket };
        server.held.closed = false;
        server.held.pending_alert = null;
        server.held.suite = 0;
        server.code = ok;
        server.chain[0] = .{ .der = options.identity.leaf.ptr, .len = options.identity.leaf.len };
        server.chain[1] = .{ .der = options.identity.issuer.ptr, .len = options.identity.issuer.len };
        server.alpn[0] = .{ .name = alpn_h2.ptr, .name_len = alpn_h2.len };
        server.config.buf = options.receive.ptr;
        server.config.buf_len = options.receive.len;
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
    }

    /// `ch_srv_check`'s boot-time self-test: every provisioned key signs, and the signature
    /// verifies under the public key in the same slot. It runs no I/O and touches no session, so
    /// a caller runs it once rather than per connection. It draws entropy, so the caller seeds
    /// chapulin's generator first.
    pub fn check(server: *const Server) Error!void {
        if (c.ch_srv_check(&server.config) != ok) return Error.IdentityRefused;
    }

    /// Runs one handshake to completion. It blocks, so one connection at a time.
    pub fn accept(server: *Server) Error!void {
        server.code = c.ch_srv_accept(&server.held.session, &server.config);
        if (server.code != ok) return Error.HandshakeFailed;
        // Phase 2 from here: nothing below this line touches the descriptor again.
        // chapulin declares `suite` under `CH_ROLE_SERVER`, so this side reports what it selected.
        server.held.suite = server.held.session.suite;
        server.held.io = .{ .records = .{} };
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
