//! The packet protection half of a QUIC session (`quic_provider.zig`): chapulin's packet calls
//! behind colibri's `crypto.Suite` (decisions 48 and 94). Every member is one chapulin call, and
//! what is left here is naming: chapulin answers errors of its own, and each maps onto the errors
//! `crypto/suite.zig` defines.
//!
//! A server's Retry comes before any session exists (RFC 9000 §8.1.2), so a session's suite mints
//! and checks no token. `Retry` is the suite a server writes its Retry and reads the returned token
//! with: chapulin's stateless token calls (`quic_token.h`) under a key the caller draws once for
//! the deployment (decision 55), and the Retry Integrity Tag, which RFC 9001 §5.8 fixes for every
//! connection.
const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("crypto");
const chapulin = @import("chapulin_quic");
const constants = @import("../constants.zig");
const quic_provider = @import("quic_provider.zig");

const c = chapulin.c;
const suite_module = crypto.suite;
const Level = crypto.Level;
const level_of = quic_provider.level_of;

comptime {
    // colibri's directions and key sets are chapulin's, value for value.
    for ([_]suite_module.Direction{ .read, .write }) |direction| {
        assert(@intFromEnum(direction) == @intFromEnum(@field(chapulin.quic.Direction, @tagName(direction))));
    }
    assert(crypto.constants.retry_integrity_tag_len == c.GCM_TAG);
    // colibri's versions are chapulin's, value for value (RFC 9000 §15, RFC 9369 §3.1).
    for (std.enums.values(suite_module.Version)) |named| {
        assert(@intFromEnum(named) == @intFromEnum(@field(chapulin.quic.Version, @tagName(named))));
    }
}

/// The bits of byte 0 that hold the Packet Number Length less one, once header protection is
/// removed (RFC 9000 §17.2, §17.3.1).
const packet_number_len_mask: u8 = 0x03;

/// chapulin's name for `named`, which the comptime block above holds to the same value. Each
/// packet call names its own version, which chapulin derives the keys, salt and Retry key of
/// (RFC 9001 §5.2, §5.8; RFC 9369 §3.3).
fn chapulin_version(named: suite_module.Version) chapulin.quic.Version {
    return @enumFromInt(@intFromEnum(named));
}

/// The vtable for a role's session type `Held`.
pub fn Suite(comptime Held: type) type {
    return struct {
        pub const vtable: suite_module.VTable = .{
            .install_initial_keys = install_initial_keys,
            .switch_version = switch_version,
            .keys_available = keys_available,
            .seal = seal,
            .open = open,
            .retry_tag_valid = retry_tag_valid,
            .retry_tag_write = retry_tag_write,
            .retry_token_write = session_token_write,
            .retry_token_check = session_token_check,
            .update_keys = update_keys,
            .key_phase = key_phase,
            .discard_previous_keys = discard_previous_keys,
            .discard_keys = discard_keys,
        };

        fn held(context: *anyopaque) *Held {
            return @ptrCast(@alignCast(context));
        }

        fn held_const(context: *const anyopaque) *const Held {
            return @ptrCast(@alignCast(context));
        }

        fn install_initial_keys(context: *anyopaque, role: suite_module.Role, dcid: []const u8) suite_module.InstallError!void {
            return install(held(context), role, dcid);
        }

        fn switch_version(context: *anyopaque, named: suite_module.Version) suite_module.SwitchError!void {
            return switch_role(held(context), named);
        }

        fn keys_available(context: *const anyopaque, level: Level, direction: suite_module.Direction) bool {
            const role = held_const(context);
            return role.state.started and role.session.keysReady(level_of(level), @enumFromInt(@intFromEnum(direction)));
        }

        fn seal(context: *anyopaque, sealing: suite_module.Sealing, output: []u8) suite_module.SealError!usize {
            return protect(held(context), sealing, output);
        }

        fn open(context: *anyopaque, opening: suite_module.Opening) suite_module.OpenError!suite_module.Opened {
            return unprotect(held(context), opening);
        }

        /// RFC 9001 §5.8, which chapulin computes and compares in constant time, under the Retry
        /// key and nonce of `named` (RFC 9369 §3.3.3).
        fn retry_tag_valid(context: *const anyopaque, named: suite_module.Version, pseudo_packet: []const u8, tag: *const [crypto.constants.retry_integrity_tag_len]u8) bool {
            const role = held_const(context);
            return role.state.started and role.session.retryOk(chapulin_version(named), pseudo_packet, tag);
        }

        fn update_keys(context: *anyopaque) suite_module.UpdateError!void {
            const role = held(context);
            // RFC 9001 §6.1: no update before the handshake completes.
            if (!role.state.started) return error.KeysUnavailable;
            // RFC 9001 §6.1: which chapulin refuses too, until then.
            role.session.keyUpdate() catch return error.KeysUnavailable;
        }

        fn key_phase(context: *const anyopaque) bool {
            const role = held_const(context);
            return role.state.started and role.session.keyPhase() != 0;
        }

        /// RFC 9001 §6.5.
        fn discard_previous_keys(context: *anyopaque) void {
            const role = held(context);
            if (role.state.started) role.session.dropPreviousKeys();
        }

        /// RFC 9001 §4.9. chapulin refuses only a level above the application's, which `Level`
        /// cannot name.
        fn discard_keys(context: *anyopaque, level: Level) void {
            const role = held(context);
            if (role.state.started) role.session.discard(level_of(level)) catch unreachable;
        }
    };
}

/// RFC 9001 §5.2: the Initial keys derive from the Destination Connection ID. chapulin fixes a
/// session's role when it starts, and the caller installs before the first packet, so the session
/// must have started by then.
fn install(role: anytype, asked: suite_module.Role, dcid: []const u8) suite_module.InstallError!void {
    const own: suite_module.Role = if (@TypeOf(role.*).is_client) .client else .server;
    // RFC 9001 §5.2: a session derives the keys of its own role, once it has started.
    if (asked != own or !role.state.started) return error.Unsupported;
    // RFC 9001 §5.2: chapulin refuses a connection ID it cannot derive from.
    role.session.initialKeys(dcid) catch return error.Unsupported;
}

/// RFC 9369 §4.1, which chapulin refuses twice, after the server's first CRYPTO octet, or to the
/// version it already negotiated.
fn switch_role(role: anytype, named: suite_module.Version) suite_module.SwitchError!void {
    if (comptime !@TypeOf(role.*).is_client) {
        // RFC 9369 §4.1 gives the switch to a client, and chapulin has no server call for it.
        return error.Refused;
    } else {
        // RFC 9369 §4.1: a session chapulin has not started has no original version to leave.
        if (!role.state.started) return error.Refused;
        // RFC 9369 §4.1: chapulin refuses a second switch, one after the server's first CRYPTO
        // octet, and one to the version already negotiated.
        role.session.switchVersion(chapulin_version(named)) catch return error.Refused;
        assert(role.session.negotiatedVersion() == chapulin_version(named));
    }
}

fn protect(role: anytype, sealing: suite_module.Sealing, output: []u8) suite_module.SealError!usize {
    // RFC 9001 §5.2: no packet is protected before the session holds its Initial keys.
    if (!role.state.started) return error.KeysUnavailable;
    const level = level_of(sealing.level);
    // RFC 9001 §4.8: a handshake that failed still owes the peer a CONNECTION_CLOSE. chapulin
    // seals one close per level after a failure, through its own call, and then drops that
    // level's write keys, which `keys_available` reports and decision 84's `take_lost` reads.
    const failed = role.session.state() == .failed;
    const named = chapulin_version(sealing.version);
    // RFC 9369 §4.1: colibri seals every packet in the session's negotiated version.
    assert(role.session.negotiatedVersion() == named);
    const sealed = if (failed)
        role.session.sealClose(level, named, sealing.packet_number, sealing.packet_number_len, sealing.header, sealing.payload, output)
    else
        role.session.seal(level, named, sealing.packet_number, sealing.packet_number_len, sealing.header, sealing.payload, output);
    return sealed catch |failure| switch (failure) {
        error.Cap => error.NoSpaceLeft,
        // RFC 9001 §4.8: after a failure, a close chapulin does not seal at this level.
        error.Invalid => if (failed or !role.session.keysReady(level, .write))
            error.KeysUnavailable
        else
            // RFC 9001 §6.6: the one other refusal is the packet past the confidentiality limit,
            // which an AES-GCM key set meets at 2^23 packets.
            error.ConfidentialityLimitReached,
    };
}

fn unprotect(role: anytype, opening: suite_module.Opening) suite_module.OpenError!suite_module.Opened {
    // RFC 9001 §5.2: no packet is opened before the session holds its Initial keys.
    if (!role.state.started) return error.KeysUnavailable;
    const opened = role.session.open(
        level_of(opening.level),
        chapulin_version(opening.version),
        opening.packet,
        opening.packet_number_offset,
        // RFC 9000 Appendix A.3, and chapulin's "or 0 before the first".
        opening.largest_packet_number orelse 0,
        // RFC 9001 §6.5: with nothing processed in the current phase, no packet is past it, so a
        // packet of the other phase is one of the phase before.
        opening.current_phase_lowest orelse std.math.maxInt(u64),
    ) catch |failure| return switch (failure) {
        // RFC 9001 §5.5: a packet that fails is dropped and the connection goes on.
        error.Discard => error.Discarded,
        // RFC 9001 §6.6: past the integrity limit.
        error.AeadLimit => error.IntegrityLimitReached,
        // RFC 9001 §5.7: keys not held, discarded, or 1-RTT before the handshake completes; and
        // RFC 9369 §4.1: keys never derived for the packet's version.
        error.Invalid => error.KeysUnavailable,
    };
    return .{
        .packet_number = opened.pn,
        .packet_number_len = (opening.packet[0] & packet_number_len_mask) + 1,
        .payload_len = opened.pt_len,
        .key_set = switch (opened.key_set) {
            .previous => .previous,
            .current => .current,
            .next => .next,
        },
    };
}

/// RFC 9001 §5.8: the tag is the same for every connection of a version, so any suite writes it.
fn retry_tag_write(context: *const anyopaque, named: suite_module.Version, pseudo_packet: []const u8, tag: *[crypto.constants.retry_integrity_tag_len]u8) suite_module.RetryTagError!void {
    _ = context;
    // RFC 9369 §3.3.3: chapulin refuses only a version it derives no Retry key for, and a server
    // over it then sends no Retry.
    chapulin.quic.retryTag(chapulin_version(named), pseudo_packet, tag) catch return error.Unsupported;
}

/// A session mints no token: a server writes its Retry with `Retry`, before the session exists.
fn session_token_write(context: *anyopaque, named: suite_module.Version, address: []const u8, ids: *const suite_module.RetryConnectionIds, now_ns: u64, output: []u8) suite_module.TokenError!usize {
    _ = .{ context, named, address, ids, now_ns, output };
    // RFC 9000 §8.1.2: a Retry comes before the session, whose suite has no token key.
    return error.Unsupported;
}

fn session_token_check(context: *const anyopaque, named: suite_module.Version, address: []const u8, token: []const u8, now_ns: u64) suite_module.TokenCheck {
    _ = .{ context, named, address, token, now_ns };
    return .not_retry;
}

/// The suite a server writes a Retry and reads the token it returns with, before any session
/// exists (RFC 9000 §8.1.2). The key is the deployment's (decision 55): the caller draws it once,
/// colibri passes chapulin a pointer and never reads it, and every token this server mints uses it.
pub const Retry = struct {
    key: *const [c.CH_QUIC_TOKEN_KEY_LEN]u8,
    /// How long a token is accepted after it was minted (RFC 9000 §8.1.4).
    lifetime_seconds: u64,

    pub fn suite(retry: *const Retry) crypto.Suite {
        return .{ .context = @constCast(retry), .vtable = &retry_vtable };
    }
};

pub const token_key_len = c.CH_QUIC_TOKEN_KEY_LEN;

const retry_vtable: suite_module.VTable = .{
    .install_initial_keys = no_session_install,
    .switch_version = no_session_switch,
    .keys_available = no_session_available,
    .seal = no_session_seal,
    .open = no_session_open,
    .retry_tag_valid = no_session_tag_valid,
    .retry_tag_write = retry_tag_write,
    .retry_token_write = retry_token_write,
    .retry_token_check = retry_token_check,
    .update_keys = no_session_update,
    .key_phase = no_session_phase,
    .discard_previous_keys = no_session_discard_previous,
    .discard_keys = no_session_discard,
};

/// chapulin counts a token's lifetime in seconds, and colibri passes nanoseconds. The two instants
/// a check compares come from the same clock, so the epoch does not matter.
fn seconds_of(now_ns: u64) u64 {
    return now_ns / constants.nanoseconds_per_second;
}

/// RFC 9000 §8.1.4: the token binds the address and the instant, and decision 55 has it carry the
/// two connection IDs the server needs again. RFC 9369 §4.1: chapulin binds the original version
/// too.
fn retry_token_write(context: *anyopaque, named: suite_module.Version, address: []const u8, ids: *const suite_module.RetryConnectionIds, now_ns: u64, output: []u8) suite_module.TokenError!usize {
    const retry: *const Retry = @ptrCast(@alignCast(context));
    var cids = std.mem.zeroes(c.ch_quic_retry_cids);
    @memcpy(cids.original_dcid[0..ids.original_destination_len], ids.original_destination_slice());
    cids.original_dcid_len = ids.original_destination_len;
    @memcpy(cids.retry_scid[0..ids.retry_source_len], ids.retry_source_slice());
    cids.retry_scid_len = ids.retry_source_len;
    return chapulin.quic.tokenMint(retry.key, chapulin_version(named), address, &cids, seconds_of(now_ns), output) catch |failure| switch (failure) {
        error.Cap => error.NoSpaceLeft,
        // RFC 9000 §8.1.4: an address longer than chapulin binds.
        error.Invalid => error.Unsupported,
    };
}

fn retry_token_check(context: *const anyopaque, named: suite_module.Version, address: []const u8, token: []const u8, now_ns: u64) suite_module.TokenCheck {
    const retry: *const Retry = @ptrCast(@alignCast(context));
    const found = chapulin.quic.tokenCheck(retry.key, chapulin_version(named), token, address, seconds_of(now_ns), retry.lifetime_seconds) catch return .invalid;
    return switch (found) {
        .retry => |cids| .{ .retry = .of(cids.original_dcid[0..cids.original_dcid_len], cids.retry_scid[0..cids.retry_scid_len]) },
        // RFC 9000 §8.1.3: not a Retry token, which leaves the client's address unvalidated.
        .not_retry => .not_retry,
        // RFC 9000 §8.1.2: a Retry token that fails, which the server closes on with
        // INVALID_TOKEN.
        .invalid => .invalid,
    };
}

/// The members a session holds and a Retry never reaches: a Retry is written before any key exists.
fn no_session_install(_: *anyopaque, _: suite_module.Role, _: []const u8) suite_module.InstallError!void {
    unreachable;
}
fn no_session_switch(_: *anyopaque, _: suite_module.Version) suite_module.SwitchError!void {
    unreachable;
}
fn no_session_available(_: *const anyopaque, _: Level, _: suite_module.Direction) bool {
    unreachable;
}
fn no_session_seal(_: *anyopaque, _: suite_module.Sealing, _: []u8) suite_module.SealError!usize {
    unreachable;
}
fn no_session_open(_: *anyopaque, _: suite_module.Opening) suite_module.OpenError!suite_module.Opened {
    unreachable;
}
fn no_session_tag_valid(_: *const anyopaque, _: suite_module.Version, _: []const u8, _: *const [crypto.constants.retry_integrity_tag_len]u8) bool {
    unreachable;
}
fn no_session_update(_: *anyopaque) suite_module.UpdateError!void {
    unreachable;
}
fn no_session_phase(_: *const anyopaque) bool {
    unreachable;
}
fn no_session_discard_previous(_: *anyopaque) void {
    unreachable;
}
fn no_session_discard(_: *anyopaque, _: Level) void {
    unreachable;
}
