//! chapulin's QUIC mode behind colibri's `tls.QuicProvider` and `crypto.Suite`, for `src/testing/`
//! alone ([decision 10](../../../docs/decisions.md)). Part of design §8 step 9e, piece 11.
//!
//! One `ch_quic` is both halves. RFC 9001 §4.1.4 has TLS produce the secrets that packet
//! protection uses, and decision 48 keeps them inside the object that derived them, so the one
//! session answers the provider's calls here and the suite's in `chapulin_quic_suite.zig`.
//!
//! **The two roles hand out handshake octets differently, and colibri takes them one way.** A
//! chapulin client stages one message and the caller pulls it with `ch_quic_crypto_out`. A
//! chapulin server pushes its flight through `on_crypto_out` as it writes it, because one
//! Certificate message is larger than its staging buffer. Both land in `outgoing`, one buffer per
//! level, and `write_handshake` hands colibri what is waiting there. The client's message is
//! pulled the moment chapulin stages it, because `ch_quic_crypto_in` refuses another delivery
//! while one is staged.
//!
//! **colibri learns which levels are ready from the suite (decision 62).** chapulin sets a level's
//! bits in `levels_ready` inside the call that fed it, and `keys_available` reads those bits, so
//! colibri sees a level the moment chapulin has it. chapulin also reports each level through
//! `on_level_ready`, which it requires, and which this session has no use for.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../constants.zig");
const chapulin_quic_c = @import("chapulin_quic_c.zig");
const chapulin_quic_suite = @import("chapulin_quic_suite.zig");

const c = chapulin_quic_c.c;
const tls = quic.tls;
const Level = quic.core.Level;
const Role = quic.crypto.suite.Role;
const Keylog = chapulin_quic_c.Keylog;

pub const ok: c_int = 0;

/// The signing identity a server provisions in chapulin's ecdsa_secp256r1_sha256 slot: a 32-octet
/// big-endian private scalar and a 64-octet uncompressed point X||Y (`srv_cfg.h`).
pub const Identity = struct {
    /// The DER certificates the server presents, the end-entity first and each one after it
    /// certifying the one before (RFC 9846 §4.4.2): at least one, at most `quic_chain_len_max`.
    chain: []const []const u8,
    private_scalar: []const u8,
    public_point: []const u8,
    /// RFC 9846 §4.3.2's cookie key, which chapulin requires of every server.
    cookie_key: []const u8,
    /// The key chapulin seals its tickets under and opens them with (`srv_cfg.h`), or null to
    /// issue none and accept none.
    ticket_key: ?[]const u8 = null,
    /// The caller's Unix seconds at the start of this connection, which chapulin writes into the
    /// ticket it issues and judges an offered one against. 0 issues no ticket and accepts none.
    now_seconds: u64 = 0,
};

/// The octets of a resumption PSK: chapulin's one suite, TLS_CHACHA20_POLY1305_SHA256, hashes
/// with SHA-256 (RFC 9846 §4.6.1).
const psk_len = std.crypto.hash.sha2.Sha256.digest_length;

/// A NewSessionTicket a client kept (RFC 9846 §4.6.1), which its next connection presents to
/// resume (RFC 9846 §2.2). chapulin hands a ticket over during `on_ticket` alone, so it is copied.
pub const Ticket = struct {
    identity: [constants.quic_ticket_identity_len_max]u8 = undefined,
    identity_len: usize = 0,
    psk: [psk_len]u8 = undefined,
    age_add: u32 = 0,
    /// A Web PKI build binds the ticket to the host name and the anchors (`webpki_ticket.h`).
    binding: [psk_len]u8 = undefined,
    /// Whether a ticket arrived.
    held: bool = false,
    /// Whether a ticket arrived whose identity is longer than `identity` holds.
    too_long: bool = false,
};

/// A ticket a client presents. RFC 9846 §4.2.11: the obfuscated age is the ticket's age in
/// milliseconds plus its `ticket_age_add`, modulo 2^32.
pub const Resumption = struct {
    ticket: *const Ticket,
    obfuscated_age: u32,
};

/// Whether the linked object judges a server by the Web PKI (`TRUST=webpki`), or by a pinned
/// P-256 key (`TRUST=raw-ecdsa`). chapulin declares the anchor fields in a Web PKI build alone.
pub const webpki = chapulin_quic_c.available and @hasField(c.ch_cfg, "anchors");
pub const Anchor = if (webpki) c.ch_trust_anchor else void;

/// What a client judges the server by, which is the one mode the linked object was built with.
pub const Trust = union(enum) {
    /// The chain must reach one of `anchors` and carry `hostname`. `now_seconds` counts seconds
    /// since 1970-01-01T00:00:00Z, which the caller read: no file under `src/` reads a clock
    /// (non-negotiable 3).
    webpki: struct {
        anchors: []const Anchor,
        hostname: []const u8,
        now_seconds: u64,
    },
    /// The server must prove it holds the key whose P-256 point X||Y this is. chapulin reads no
    /// certificate in this mode, so no chain, name or date is judged.
    pinned: struct {
        public_point: []const u8,
    },
};

pub const Options = struct {
    role: Role,
    /// The one protocol offered or accepted (RFC 9001 §8.1 makes ALPN mandatory in QUIC).
    alpn: []const u8,
    /// chapulin's receive buffer, which bounds the largest handshake message it takes.
    receive: []u8,
    /// A client's trust, or null for a server.
    trust: ?Trust = null,
    /// A server's identity, or null for a client.
    identity: ?Identity = null,
    /// Where the traffic secrets go, or null to drop them.
    keylog: ?*Keylog = null,
    /// Where a client keeps the ticket its server issues, or null to keep none.
    ticket_store: ?*Ticket = null,
    /// A ticket a client presents to resume, or null for a full handshake.
    resumption: ?Resumption = null,
};

/// The handshake octets waiting at one level for colibri to frame them.
const Outgoing = struct {
    octets: [constants.quic_crypto_out_len]u8,
    /// Octets held, and how many of them colibri has taken.
    len: usize,
    taken: usize,
};

pub const Session = struct {
    quic: c.ch_quic,
    config: c.ch_cfg,
    role: Role,
    alpn: [1]c.ch_alpn_protocol,
    chain: [constants.quic_chain_len_max]c.ch_cert,
    /// This endpoint's transport parameters. chapulin copies the pointer, not the octets.
    local_parameters: [c.CH_TRANSPORT_PARAMS_MAX]u8,
    /// The peer's transport parameters, which chapulin hands over during a callback alone.
    peer_parameters: [constants.quic_peer_params_len_max]u8,
    peer_parameters_len: ?usize,
    outgoing: [quic.core.levels_count]Outgoing,
    /// Whether `ch_quic_init` or `ch_srv_quic_init` ran, which they do once the parameters are
    /// set (RFC 9001 §8.2).
    started: bool,
    /// Whether colibri has been told of the alert that ended the session.
    alert_taken: bool,
    /// Whether an outgoing buffer was too short, which fails the handshake.
    outgoing_overflowed: bool,
    keylog: ?*Keylog,
    ticket_store: ?*Ticket,
    /// What chapulin last answered.
    code: c_int,

    pub fn init(session: *Session, options: Options) void {
        assert((options.role == .client) == (options.trust != null));
        assert((options.role == .server) == (options.identity != null));
        assert(options.role == .client or (options.ticket_store == null and options.resumption == null));
        session.quic = std.mem.zeroes(c.ch_quic);
        session.config = std.mem.zeroes(c.ch_cfg);
        session.role = options.role;
        session.peer_parameters_len = null;
        for (&session.outgoing) |*outgoing| {
            outgoing.len = 0;
            outgoing.taken = 0;
        }
        session.started = false;
        session.alert_taken = false;
        session.outgoing_overflowed = false;
        session.keylog = options.keylog;
        session.ticket_store = options.ticket_store;
        session.code = ok;
        session.alpn[0] = .{ .name = options.alpn.ptr, .name_len = options.alpn.len };
        session.config.buf = options.receive.ptr;
        session.config.buf_len = options.receive.len;
        session.config.io = @ptrCast(session);
        session.config.alpn_protocols = &session.alpn;
        session.config.alpn_count = session.alpn.len;
        session.config.on_level_ready = on_level_ready;
        session.config.on_transport_params = on_transport_params;
        if (options.ticket_store != null) session.config.on_ticket = on_ticket;
        if (options.trust) |trust| session.configure_client(trust, options.resumption);
        if (options.identity) |identity| session.configure_server(identity);
    }

    fn configure_client(session: *Session, trust: Trust, resumption: ?Resumption) void {
        switch (trust) {
            .webpki => |judged| {
                // The object's trust mode is fixed when it is built, and a caller that asks for
                // the other one is colibri's defect.
                if (!webpki) unreachable;
                session.config.anchors = judged.anchors.ptr;
                session.config.anchor_count = judged.anchors.len;
                session.config.hostname = judged.hostname.ptr;
                session.config.hostname_len = judged.hostname.len;
                session.config.now_seconds = judged.now_seconds;
                if (resumption) |presented| session.config.ticket_binding = &presented.ticket.binding;
            },
            .pinned => |pin| {
                if (webpki) unreachable;
                // chapulin's `docs/quic_server.md`: a raw-mode client that resumes leaves both pin
                // slots unset, because the PSK authenticates the server.
                if (resumption == null) {
                    session.config.server_pubkey = pin.public_point.ptr;
                    session.config.server_pubkey_len = pin.public_point.len;
                }
            },
        }
        const presented = resumption orelse return;
        assert(presented.ticket.held);
        session.config.psk = &presented.ticket.psk;
        session.config.psk_len = presented.ticket.psk.len;
        session.config.psk_id = &presented.ticket.identity;
        session.config.psk_id_len = presented.ticket.identity_len;
        session.config.resumption = 1;
        session.config.obfuscated_age = presented.obfuscated_age;
    }

    fn configure_server(session: *Session, identity: Identity) void {
        assert(identity.chain.len > 0 and identity.chain.len <= session.chain.len);
        for (identity.chain, session.chain[0..identity.chain.len]) |der, *certificate| {
            certificate.* = .{ .der = der.ptr, .len = der.len };
        }
        session.config.srv.ecdsa_p256 = .{
            .chain = &session.chain,
            .chain_count = @intCast(identity.chain.len),
            .priv = identity.private_scalar.ptr,
            .priv_len = identity.private_scalar.len,
            .@"pub" = identity.public_point.ptr,
            .pub_len = identity.public_point.len,
        };
        session.config.srv.cookie_key = identity.cookie_key.ptr;
        session.config.srv.on_crypto_out = on_crypto_out;
        const ticket_key = identity.ticket_key orelse return;
        assert(ticket_key.len == c.SRV_TICKET_KEY_LEN);
        session.config.srv.ticket_key = ticket_key.ptr;
        session.config.srv.now_seconds = identity.now_seconds;
    }

    /// Whether a ticket this server issued authenticated the handshake, which then carried no
    /// Certificate (RFC 9846 §2.2).
    pub fn resumed(session: *const Session) bool {
        assert(session.role == .server);
        return session.quic.t.psk_selected != 0;
    }

    /// `ch_srv_check`'s test that the server's key signs and verifies. It draws entropy, so the
    /// caller seeds chapulin first.
    pub fn check_identity(session: *const Session) bool {
        assert(session.role == .server);
        return c.ch_srv_check(&session.config) == ok;
    }

    pub fn provider(session: *Session) tls.QuicProvider {
        return .{ .context = @ptrCast(session), .vtable = &vtable };
    }

    pub fn suite(session: *Session) quic.crypto.Suite {
        return .{ .context = @ptrCast(session), .vtable = &chapulin_quic_suite.vtable };
    }

    /// Whether the session failed, which `ch_quic_state` reports.
    pub fn failed(session: *const Session) bool {
        return c.ch_quic_state(&session.quic) == c.CH_ST_FAILED;
    }

    /// Pulls the message a client staged, at whichever level it is owed.
    fn pull_staged(session: *Session) void {
        if (session.role != .client) return;
        // Bounded by the levels, of which RFC 9001 §4.1.4 names three.
        for (&session.outgoing, 0..) |*outgoing, level| {
            const room = outgoing.octets[outgoing.len..];
            var written: usize = 0;
            const code = c.ch_quic_crypto_out(&session.quic, @intCast(level), room.ptr, room.len, &written);
            if (code == c.CH_ECAP) session.outgoing_overflowed = true;
            if (code != ok) continue;
            assert(written <= room.len);
            outgoing.len += written;
        }
    }
};

/// The bit of one level in one direction in chapulin's `levels_ready`, laid out as its
/// `CH_QUIC_LEVEL_BIT` lays it out.
pub fn ready_bit(level: usize, direction: usize) u8 {
    const directions: usize = quic.crypto.suite.directions_count;
    return @as(u8, 1) << @intCast(level * directions + direction);
}

fn session_of(io: ?*anyopaque) *Session {
    return @ptrCast(@alignCast(io.?));
}

/// chapulin requires the callback. colibri reads the same fact from `levels_ready` through
/// `keys_available` (decision 62), so there is nothing to do here.
fn on_level_ready(io: ?*anyopaque, level: u8, direction: u8) callconv(.c) void {
    _ = io;
    _ = level;
    _ = direction;
}

/// The peer's parameters, which point into chapulin's buffer for the length of the call alone.
fn on_transport_params(io: ?*anyopaque, body: [*c]const u8, len: usize) callconv(.c) void {
    const session = session_of(io);
    // A body this session cannot keep is reported as none, which colibri refuses (RFC 9001 §8.2).
    if (len > session.peer_parameters.len) return;
    @memcpy(session.peer_parameters[0..len], body[0..len]);
    session.peer_parameters_len = len;
}

/// A NewSessionTicket the server sent (RFC 9846 §4.6.1), which chapulin hands over for the length
/// of the call alone. A later ticket replaces an earlier one.
fn on_ticket(io: ?*anyopaque, issued: [*c]const c.ch_ticket) callconv(.c) void {
    const session = session_of(io);
    const store = session.ticket_store.?;
    const ticket = &issued[0];
    if (ticket.identity_len > store.identity.len) {
        store.too_long = true;
        return;
    }
    @memcpy(store.identity[0..ticket.identity_len], ticket.identity[0..ticket.identity_len]);
    store.identity_len = ticket.identity_len;
    store.psk = ticket.psk;
    store.age_add = ticket.age_add;
    if (webpki) store.binding = ticket.binding;
    store.held = true;
}

/// A server's handshake octets at one level, as chapulin writes them.
fn on_crypto_out(io: ?*anyopaque, level: u8, octets: [*c]const u8, len: usize) callconv(.c) c_int {
    const session = session_of(io);
    const outgoing = &session.outgoing[level];
    if (outgoing.len + len > outgoing.octets.len) {
        session.outgoing_overflowed = true;
        return c.CH_ECAP;
    }
    @memcpy(outgoing.octets[outgoing.len..][0..len], octets[0..len]);
    outgoing.len += len;
    return ok;
}

/// chapulin's `keylog.h` hook: one traffic secret as it was derived. `io` is the session.
fn keylog_hook(
    io: ?*anyopaque,
    label: [*c]const u8,
    client_random: [*c]const u8,
    secret: [*c]const u8,
) callconv(.c) void {
    const session = session_of(io);
    const keylog = session.keylog orelse return;
    keylog.append(std.mem.span(label), client_random[0..c.CH_KEYLOG_RANDOM_LEN], secret[0..c.SHA256_LEN]);
}

comptime {
    if (chapulin_quic_c.available) @export(&keylog_hook, .{ .name = "ch_keylog", .linkage = .strong });
}

pub const vtable: tls.quic_provider.VTable = .{
    .set_transport_params = set_transport_params,
    .peer_transport_params = peer_transport_params,
    .provide_handshake = provide_handshake,
    .write_handshake = write_handshake,
    .negotiated_alpn = negotiated_alpn,
    .handshake_complete = handshake_complete,
    .take_alert = take_alert,
    .export_keying_material = export_keying_material,
};

fn held(context: *anyopaque) *Session {
    return @ptrCast(@alignCast(context));
}

fn held_const(context: *const anyopaque) *const Session {
    return @ptrCast(@alignCast(context));
}

/// RFC 9001 §8.2: the parameters travel in the first message each side writes, so chapulin reads
/// them at initialization, and the session starts here.
fn set_transport_params(context: *anyopaque, body: []const u8) tls.quic_provider.TransportParamsError!void {
    const session = held(context);
    if (session.started) return error.HandshakeStarted;
    if (body.len > session.local_parameters.len) return error.TlsFailed;
    @memcpy(session.local_parameters[0..body.len], body);
    session.config.transport_params = &session.local_parameters;
    session.config.transport_params_len = body.len;
    session.code = switch (session.role) {
        .client => c.ch_quic_init(&session.quic, &session.config),
        .server => c.ch_srv_quic_init(&session.quic, &session.config),
    };
    session.started = true;
    if (session.code != ok) return error.TlsFailed;
    // A client's ClientHello is staged now (RFC 9001 §4.1.3).
    session.pull_staged();
}

fn peer_transport_params(context: *const anyopaque) ?[]const u8 {
    const session = held_const(context);
    const len = session.peer_parameters_len orelse return null;
    return session.peer_parameters[0..len];
}

fn provide_handshake(context: *anyopaque, level: Level, data: []const u8) tls.quic_provider.ProvideError!void {
    const session = held(context);
    if (!session.started) return error.WrongLevel;
    const at: u8 = @intFromEnum(level);
    session.code = switch (session.role) {
        .client => c.ch_quic_crypto_in(&session.quic, at, data.ptr, data.len),
        .server => c.ch_srv_quic_crypto_in(&session.quic, at, data.ptr, data.len),
    };
    session.pull_staged();
    if (session.outgoing_overflowed) return error.NoSpaceLeft;
    if (session.code == ok) return;
    // chapulin answers CH_EINVAL and changes nothing for octets at a level it is not reading yet
    // (RFC 9001 §4.1.3), and kills the session for every other refusal.
    if (session.code == c.CH_EINVAL and !session.failed()) return error.WrongLevel;
    if (session.code == c.CH_ECAP) return error.NoSpaceLeft;
    return error.TlsFailed;
}

/// Hands colibri what is waiting at `level`, as much as fits.
fn write_handshake(context: *anyopaque, level: Level, output: []u8) tls.quic_provider.WriteError!usize {
    const session = held(context);
    if (session.outgoing_overflowed) return error.NoSpaceLeft;
    const outgoing = &session.outgoing[@intFromEnum(level)];
    const waiting = outgoing.octets[outgoing.taken..outgoing.len];
    const len = @min(waiting.len, output.len);
    @memcpy(output[0..len], waiting[0..len]);
    outgoing.taken += len;
    if (outgoing.taken == outgoing.len) {
        outgoing.len = 0;
        outgoing.taken = 0;
    }
    return len;
}

fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
    const session = held_const(context);
    const selected = session.quic.t.alpn_selected;
    if (selected == c.CH_ALPN_NONE) return null;
    const protocol = session.alpn[selected];
    return protocol.name[0..protocol.name_len];
}

/// RFC 9001 §4.1.1: chapulin reports CONNECTED once it has sent its Finished and verified the
/// peer's.
fn handshake_complete(context: *const anyopaque) bool {
    const session = held_const(context);
    return c.ch_quic_state(&session.quic) == c.CH_ST_CONNECTED;
}

/// RFC 9001 §4.8: the alert behind a failed session, once.
fn take_alert(context: *anyopaque) ?tls.Alert {
    const session = held(context);
    if (session.alert_taken or !session.failed()) return null;
    const description = c.ch_quic_alert(&session.quic);
    if (description == 0) return null;
    session.alert_taken = true;
    return @enumFromInt(description);
}

/// chapulin's exporter is a record-layer call and its Makefile refuses `EXPORTER=on` with
/// `TRANSPORT=quic`.
fn export_keying_material(
    context: *anyopaque,
    label: []const u8,
    context_value: ?[]const u8,
    output: []u8,
) tls.quic_provider.ExportError!void {
    _ = context;
    _ = label;
    _ = context_value;
    _ = output;
    return error.Unsupported;
}
