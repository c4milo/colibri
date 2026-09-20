//! chapulin's TLS 1.3 server behind colibri's `tls.Provider`, for `src/testing/` alone
//! ([decision 10](../../../docs/decisions.md)). The other half of design §8 step 5's TLS work.
//!
//! It is the mirror of `chapulin_client.zig` and shares its two phases: during the handshake
//! chapulin's `send` and `recv` callbacks drive the socket, and afterwards they serve the buffers
//! colibri passes to `encrypt_record` and `decrypt_record`. The `Io` union and both callbacks are
//! the client's, because nothing about them is a role.
//!
//! What differs is the configuration. A server proves an identity instead of judging one, so it
//! carries a certificate chain and a signing key rather than trust anchors and a hostname, and
//! `ch_srv_check` tests at boot that the build can sign with each provisioned key. A server also
//! needs RFC 9846 §4.3.2's cookie key, without which it cannot mint a HelloRetryRequest.
const std = @import("std");
const tls = @import("tls");
const chapulin = @import("chapulin.zig");
const chapulin_client = @import("chapulin_client.zig");

const c = chapulin.c;
const Io = chapulin_client.Io;
const posix = std.posix;

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
    /// chapulin's receive buffer, which bounds the ClientHello it will accept.
    receive: []u8,
    /// The accepted socket. It stays the caller's.
    socket: posix.socket_t,
};

pub const Server = struct {
    session: c.ch_tls,
    config: c.ch_cfg,
    /// The chain, end-entity first then the root that signed it (RFC 9846 §4.5.1).
    chain: [chain_len]c.ch_cert,
    /// The one protocol this server offers (RFC 9113 §3.1).
    alpn: [1]c.ch_alpn_protocol,
    io: Io,
    /// What chapulin last answered, which `chapulin_client.reason` names.
    code: c_int,

    pub fn init(server: *Server, options: Options) void {
        server.session = std.mem.zeroes(c.ch_tls);
        server.config = std.mem.zeroes(c.ch_cfg);
        server.io = .{ .socket = options.socket };
        server.code = 0;
        server.chain[0] = .{ .der = options.identity.leaf.ptr, .len = options.identity.leaf.len };
        server.chain[1] = .{ .der = options.identity.issuer.ptr, .len = options.identity.issuer.len };
        server.alpn[0] = .{
            .name = chapulin_client.alpn_h2.ptr,
            .name_len = chapulin_client.alpn_h2.len,
        };
        server.config.buf = options.receive.ptr;
        server.config.buf_len = options.receive.len;
        server.config.send = chapulin_client.send;
        server.config.recv = chapulin_client.recv;
        server.config.io = @ptrCast(&server.io);
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
    /// a caller runs it once rather than per connection.
    pub fn check(server: *const Server) Error!void {
        if (c.ch_srv_check(&server.config) != 0) return Error.IdentityRefused;
    }

    /// Runs one handshake to completion. It blocks, so one connection at a time.
    pub fn accept(server: *Server) Error!void {
        server.code = c.ch_srv_accept(&server.session, &server.config);
        if (server.code != 0) return Error.HandshakeFailed;
        // Phase 2 from here: nothing below this line touches the descriptor again.
        server.io = .{ .records = .{} };
    }

    /// RFC 7301 §3.2: what this server selected, or null when it selected nothing.
    pub fn negotiated_alpn(server: *const Server) ?[]const u8 {
        if (server.io != .records) return null;
        if (server.session.alpn_selected == c.CH_ALPN_NONE) return null;
        return chapulin_client.alpn_h2;
    }
};
