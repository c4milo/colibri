//! The packet protection half of `chapulin_quic.zig`: chapulin's `ch_quic_*` packet calls behind
//! colibri's `crypto.Suite` (decisions 10 and 48). Part of design §8 step 9e, piece 11.
//!
//! Every member is one chapulin call, and what is left here is naming. chapulin answers result
//! codes and colibri's vtable answers errors, so each call's codes map onto the errors
//! `crypto/suite.zig` defines.
//!
//! A server's Retry comes before any session exists (RFC 9000 §8.1.2), so a session's suite mints
//! and checks no token. `Retry` is the suite a server writes its Retry and reads the returned token
//! with: chapulin's stateless token calls (`quic_token.h`) under a key drawn once for the
//! deployment (decision 55), and the Retry Integrity Tag, which RFC 9001 §5.8 fixes for every
//! connection.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const chapulin_quic_c = @import("chapulin_quic_c.zig");
const chapulin_quic = @import("chapulin_quic.zig");
const constants = @import("../constants.zig");

const c = chapulin_quic_c.c;
const crypto = quic.crypto;
const suite_module = crypto.suite;
const Session = chapulin_quic.Session;
const Level = crypto.Level;
const ok = chapulin_quic.ok;

pub const vtable: suite_module.VTable = .{
    .install_initial_keys = install_initial_keys,
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

/// The bits of a short or long header's byte 0 that hold the Packet Number Length less one,
/// once header protection is removed (RFC 9000 §17.2, §17.3.1).
const packet_number_len_mask: u8 = 0x03;

/// chapulin's AEAD limits, past which `ch_quic_seal` refuses the Initial keys (RFC 9001 §6.6).
const initial_level: u8 = @intFromEnum(Level.initial);

fn held(context: *anyopaque) *Session {
    return @ptrCast(@alignCast(context));
}

fn held_const(context: *const anyopaque) *const Session {
    return @ptrCast(@alignCast(context));
}

/// RFC 9001 §5.2: the Initial keys derive from the Destination Connection ID. chapulin keeps one
/// role per session, fixed when it started, and the caller installs before the first packet, so
/// the session must have started by then.
fn install_initial_keys(context: *anyopaque, role: suite_module.Role, dcid: []const u8) suite_module.InstallError!void {
    const session = held(context);
    if (role != session.role or !session.started) return error.Unsupported;
    if (c.ch_quic_initial_keys(&session.quic, dcid.ptr, dcid.len) != ok) return error.Unsupported;
}

fn keys_available(context: *const anyopaque, level: Level, direction: suite_module.Direction) bool {
    const session = held_const(context);
    const bit = chapulin_quic.ready_bit(@intFromEnum(level), @intFromEnum(direction));
    return session.quic.levels_ready & bit != 0;
}

fn seal(context: *anyopaque, sealing: suite_module.Sealing, output: []u8) suite_module.SealError!usize {
    const session = held(context);
    const level: u8 = @intFromEnum(sealing.level);
    // RFC 9001 §4.8: a handshake that failed still owes the peer a CONNECTION_CLOSE. chapulin
    // seals one close per level after a failure, through its own call, and then drops that
    // level's write keys, which `keys_available` reports and decision 84's `take_lost` reads.
    const failed = session.quic.t.state == c.CH_ST_FAILED;
    const seal_call = if (failed) &c.ch_quic_seal_close else &c.ch_quic_seal;
    var written: usize = 0;
    const code = seal_call(
        &session.quic,
        level,
        sealing.packet_number,
        sealing.packet_number_len,
        sealing.header.ptr,
        sealing.header.len,
        sealing.payload.ptr,
        sealing.payload.len,
        output.ptr,
        output.len,
        &written,
    );
    if (code == ok) return written;
    if (code == c.CH_ECAP) return error.NoSpaceLeft;
    // `quic.h`: after a failure, CH_EINVAL is a close chapulin does not seal at this level.
    if (failed) return error.KeysUnavailable;
    // chapulin answers CH_EINVAL for keys it does not hold, and at the Initial level also for the
    // packet past RFC 9001 §6.6's confidentiality limit. colibri's own framing it asserts.
    if (!keys_available(context, sealing.level, .write)) return error.KeysUnavailable;
    assert(level == initial_level);
    return error.ConfidentialityLimitReached;
}

fn open(context: *anyopaque, opening: suite_module.Opening) suite_module.OpenError!suite_module.Opened {
    const session = held(context);
    var key_set: u8 = 0;
    var packet_number: u64 = 0;
    var payload_len: usize = 0;
    const code = c.ch_quic_open(
        &session.quic,
        @intFromEnum(opening.level),
        opening.packet.ptr,
        opening.packet.len,
        opening.packet_number_offset,
        // RFC 9000 Appendix A.3, and chapulin's "or 0 before the first".
        opening.largest_packet_number orelse 0,
        // RFC 9001 §6.5: with nothing processed in the current phase, no packet is past it, so a
        // packet of the other phase is one of the phase before.
        opening.current_phase_lowest orelse std.math.maxInt(u64),
        &key_set,
        &packet_number,
        &payload_len,
    );
    switch (code) {
        ok => {},
        // RFC 9001 §5.5: a packet that fails is dropped and the connection goes on.
        c.CH_QUIC_DISCARD => return error.Discarded,
        // RFC 9001 §6.6: past the integrity limit.
        c.CH_QUIC_AEAD_LIMIT => return error.IntegrityLimitReached,
        // Keys not held, discarded, or §5.7's 1-RTT refusal before the handshake completes.
        else => return error.KeysUnavailable,
    }
    return .{
        .packet_number = packet_number,
        .packet_number_len = (opening.packet[0] & packet_number_len_mask) + 1,
        .payload_len = payload_len,
        .key_set = key_set_of(key_set),
    };
}

fn key_set_of(key_set: u8) suite_module.KeySet {
    return switch (key_set) {
        c.CH_QUIC_KEY_PREVIOUS => .previous,
        c.CH_QUIC_KEY_NEXT => .next,
        else => .current,
    };
}

/// RFC 9001 §5.8, which chapulin computes and compares in constant time.
fn retry_tag_valid(
    context: *const anyopaque,
    pseudo_packet: []const u8,
    tag: *const [crypto.constants.retry_integrity_tag_len]u8,
) bool {
    const session = held_const(context);
    return c.ch_quic_retry_ok(&session.quic, pseudo_packet.ptr, pseudo_packet.len, tag) == 1;
}

fn retry_tag_write(
    context: *const anyopaque,
    pseudo_packet: []const u8,
    tag: *[crypto.constants.retry_integrity_tag_len]u8,
) suite_module.RetryTagError!void {
    _ = context;
    c.ch_srv_quic_retry_tag(pseudo_packet.ptr, pseudo_packet.len, tag);
}

/// A session mints no token: a server writes its Retry with `Retry`, before the session exists.
fn session_token_write(
    context: *anyopaque,
    address: []const u8,
    ids: *const suite_module.RetryConnectionIds,
    now_ns: u64,
    output: []u8,
) suite_module.TokenError!usize {
    _ = context;
    _ = address;
    _ = ids;
    _ = now_ns;
    _ = output;
    return error.Unsupported;
}

fn session_token_check(context: *const anyopaque, address: []const u8, token: []const u8, now_ns: u64) suite_module.TokenCheck {
    _ = context;
    _ = address;
    _ = token;
    _ = now_ns;
    return .not_retry;
}

/// The suite a server writes a Retry and reads the token it returns with, before any session
/// exists (RFC 9000 §8.1.2). The key is the deployment's (decision 55): drawn once, never shown to
/// colibri, and the same for every token this server mints.
pub const Retry = struct {
    key: [c.CH_QUIC_TOKEN_KEY_LEN]u8,
    /// How long a token is accepted after it was minted (RFC 9000 §8.1.4).
    lifetime_seconds: u64,

    pub fn suite(retry: *Retry) crypto.Suite {
        return .{ .context = retry, .vtable = &retry_vtable };
    }
};

const retry_vtable: suite_module.VTable = .{
    .install_initial_keys = no_session_install,
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
/// two connection IDs the server needs again.
fn retry_token_write(
    context: *anyopaque,
    address: []const u8,
    ids: *const suite_module.RetryConnectionIds,
    now_ns: u64,
    output: []u8,
) suite_module.TokenError!usize {
    const retry: *const Retry = @ptrCast(@alignCast(context));
    var cids: c.ch_quic_retry_cids = undefined;
    @memcpy(cids.original_dcid[0..ids.original_destination_len], ids.original_destination_slice());
    cids.original_dcid_len = ids.original_destination_len;
    @memcpy(cids.retry_scid[0..ids.retry_source_len], ids.retry_source_slice());
    cids.retry_scid_len = ids.retry_source_len;
    var written: usize = 0;
    const code = c.ch_srv_quic_token_mint(&retry.key, address.ptr, address.len, &cids, seconds_of(now_ns), output.ptr, output.len, &written);
    if (code == c.CH_ECAP) return error.NoSpaceLeft;
    // CH_EINVAL is an address longer than chapulin binds, which the UDP endpoint never passes.
    if (code != ok) return error.Unsupported;
    return written;
}

fn retry_token_check(context: *const anyopaque, address: []const u8, token: []const u8, now_ns: u64) suite_module.TokenCheck {
    const retry: *const Retry = @ptrCast(@alignCast(context));
    var cids: c.ch_quic_retry_cids = undefined;
    const code = c.ch_srv_quic_token_check(&retry.key, token.ptr, token.len, address.ptr, address.len, seconds_of(now_ns), retry.lifetime_seconds, &cids);
    return switch (code) {
        ok => .{ .retry = .of(cids.original_dcid[0..cids.original_dcid_len], cids.retry_scid[0..cids.retry_scid_len]) },
        // §8.1.3: not a Retry token, which leaves the client's address unvalidated.
        c.CH_EPROTO => .not_retry,
        // §8.1.2: a Retry token that fails, which the server closes on with INVALID_TOKEN.
        else => .invalid,
    };
}

/// The members a session holds and a Retry never reaches: a Retry is written before any key exists.
fn no_session_install(_: *anyopaque, _: suite_module.Role, _: []const u8) suite_module.InstallError!void {
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
fn no_session_tag_valid(_: *const anyopaque, _: []const u8, _: *const [crypto.constants.retry_integrity_tag_len]u8) bool {
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

/// RFC 9001 §6.1 and §6.2. chapulin refuses before the handshake completes.
fn update_keys(context: *anyopaque) suite_module.UpdateError!void {
    const session = held(context);
    if (c.ch_quic_key_update(&session.quic) != ok) return error.KeysUnavailable;
}

fn key_phase(context: *const anyopaque) bool {
    const session = held_const(context);
    return c.ch_quic_key_phase(&session.quic) != 0;
}

/// RFC 9001 §6.5.
fn discard_previous_keys(context: *anyopaque) void {
    const session = held(context);
    c.ch_quic_drop_previous_keys(&session.quic);
}

/// RFC 9001 §4.9.
fn discard_keys(context: *anyopaque, level: Level) void {
    const session = held(context);
    const code = c.ch_quic_discard(&session.quic, @intFromEnum(level));
    // chapulin refuses only a level above the application's, which `Level` cannot name.
    assert(code == ok);
}

const testing = std.testing;

/// A client session whose trust is placeholder octets: `ch_quic_init` checks the anchors' shape
/// and reads them only to judge a server's chain, which these tests never receive. Test-only.
var test_session: Session = undefined;
var test_receive: [constants.tls_receive_len]u8 = undefined;
const placeholder_octet: u8 = 0x30;
const placeholder_len: usize = 8;
const placeholder: [placeholder_len]u8 = @splat(placeholder_octet);
const test_now_seconds: u64 = 1;
/// A P-256 point's length, X||Y, which a raw-pin build takes. Test-only.
const point_len: usize = 64;
const placeholder_point: [point_len]u8 = @splat(placeholder_octet);

fn start_test_client() !quic.crypto.Suite {
    const seed: [chapulin_quic_c.seed_len]u8 = @splat(0);
    c.ch_drbg_seed(&seed);
    const anchors = [_]chapulin_quic.Anchor{if (chapulin_quic.webpki) .{
        .name = &placeholder,
        .name_len = placeholder.len,
        .spki = &placeholder,
        .spki_len = placeholder.len,
    } else {}};
    const trust: chapulin_quic.Trust = if (chapulin_quic.webpki)
        .{ .webpki = .{ .anchors = &anchors, .hostname = "localhost", .now_seconds = test_now_seconds } }
    else
        .{ .pinned = .{ .public_point = &placeholder_point } };
    test_session.init(.{ .role = .client, .alpn = &.{"hq-interop"}, .receive = &test_receive, .trust = trust });
    // chapulin copies the parameters into its ClientHello unread (RFC 9001 §8.2).
    try test_session.provider().set_transport_params(&placeholder);
    const suite = test_session.suite();
    try suite.vtable.install_initial_keys(suite.context, .client, &placeholder);
    return suite;
}

test "RFC 9001 §4.9: a level colibri discards is gone from chapulin too" {
    if (!chapulin_quic_c.available) return error.SkipZigTest;
    const suite = try start_test_client();
    // RFC 9001 §5.2: the Initial keys exist once the connection ID is known, and no other level's.
    try testing.expect(suite.vtable.keys_available(suite.context, .initial, .read));
    try testing.expect(suite.vtable.keys_available(suite.context, .initial, .write));
    try testing.expect(!suite.vtable.keys_available(suite.context, .handshake, .write));
    suite.vtable.discard_keys(suite.context, .initial);
    try testing.expect(!suite.vtable.keys_available(suite.context, .initial, .read));
    try testing.expect(!suite.vtable.keys_available(suite.context, .initial, .write));
}

test "a key set is the one chapulin names" {
    if (!chapulin_quic_c.available) return error.SkipZigTest;
    try testing.expectEqual(suite_module.KeySet.previous, key_set_of(c.CH_QUIC_KEY_PREVIOUS));
    try testing.expectEqual(suite_module.KeySet.current, key_set_of(c.CH_QUIC_KEY_CURRENT));
    try testing.expectEqual(suite_module.KeySet.next, key_set_of(c.CH_QUIC_KEY_NEXT));
}

/// A token key and lifetime for the Retry test. Test-only.
const test_key_octet: u8 = 0x4b;
const test_lifetime_seconds: u64 = 10;

test "decision 55: chapulin mints a Retry token that gives both connection IDs back" {
    if (!chapulin_quic_c.available) return error.SkipZigTest;
    var retry: Retry = .{ .key = @splat(test_key_octet), .lifetime_seconds = test_lifetime_seconds };
    const suite = retry.suite();
    const ids = suite_module.RetryConnectionIds.of(&placeholder, "retry-id");
    var token: [c.CH_QUIC_TOKEN_MAX]u8 = undefined;
    const now_ns = test_now_seconds * constants.nanoseconds_per_second;
    const len = try suite.vtable.retry_token_write(suite.context, "address", &ids, now_ns, &token);
    const minted = token[0..len];
    const checked = suite.vtable.retry_token_check(suite.context, "address", minted, now_ns).retry;
    try testing.expectEqualSlices(u8, &placeholder, checked.original_destination_slice());
    try testing.expectEqualStrings("retry-id", checked.retry_source_slice());
    // RFC 9000 §8.1.4: bound to the address, and accepted for a short time only, which is seconds.
    const soon_ns = now_ns + constants.nanoseconds_per_second;
    try testing.expectEqualStrings("retry-id", suite.vtable.retry_token_check(suite.context, "address", minted, soon_ns).retry.retry_source_slice());
    try testing.expectEqual(.invalid, suite.vtable.retry_token_check(suite.context, "elsewhere", minted, now_ns));
    const late_ns = (test_now_seconds + test_lifetime_seconds + 1) * constants.nanoseconds_per_second;
    try testing.expectEqual(.invalid, suite.vtable.retry_token_check(suite.context, "address", minted, late_ns));
    // §8.1.3: a token of another type is no Retry token.
    minted[0] +%= 1;
    try testing.expectEqual(.not_retry, suite.vtable.retry_token_check(suite.context, "address", minted, now_ns));
    try testing.expectError(error.NoSpaceLeft, suite.vtable.retry_token_write(suite.context, "address", &ids, now_ns, token[0..1]));
}
