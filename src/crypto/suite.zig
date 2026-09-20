//! The packet-protection vtable colibri drives for QUIC (decisions 9 and 48). No production
//! implementation is in this tree and none ever will be (CLAUDE.md non-negotiable 2).
//!
//! The suite holds every key of a connection and colibri holds none. So no member takes or returns
//! a key, a secret or an IV, and every member is about a whole packet at an encryption level
//! (RFC 9001 §4.1.4). The secrets TLS produces go from the caller's TLS provider to the caller's
//! suite where colibri cannot see them, and what colibri is told is that a level is ready.
//!
//! colibri frames and the suite protects. For `seal` colibri writes the header with the packet
//! number encoded (RFC 9000 §17.1) and the Key Phase bit taken from `key_phase`, and pads the
//! payload so the header protection sample exists (RFC 9001 §5.4.2). `open` removes header
//! protection, recovers the packet number and removes packet protection in one call, because
//! §9.5 requires the three applied together with no side channel between them, and only the code
//! that holds the key can promise that. Every rule about when is colibri's: when a level's keys
//! are discarded (§4.9), when a key update may start (§6.1) and must be answered (§6.2), when
//! the previous keys go (§6.5).
//!
//! The shape is a context pointer and a read-only table, as in `tls.Provider`, for the same
//! reasons. Every member is mandatory, so colibri never compares a function pointer against null;
//! a suite that cannot do something answers `error.Unsupported`.
const std = @import("std");
const core = @import("core");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// Which end of the connection the suite protects packets for. RFC 9001 §5.2 derives a client's
/// and a server's Initial keys from the same connection ID under different labels, so a suite
/// must know which it writes with.
pub const Role = enum {
    client,
    server,

    pub fn peer(role: Role) Role {
        return if (role == .client) .server else .client;
    }
};

/// The encryption levels colibri uses (RFC 9001 §4.1.4). 0-RTT is not one: decision 20.
///
/// The type is `core`'s, because `tls`'s QUIC mode moves handshake octets at a level too and
/// design §3 makes `tls` and `crypto` siblings with no edge between them. These two are aliases,
/// not copies: there is one `Level` in the tree.
pub const Level = core.Level;
pub const levels_count = core.levels_count;

pub const Direction = enum(u1) { read = 0, write = 1 };

pub const directions_count = @typeInfo(Direction).@"enum".fields.len;

/// Which keys opened a 1-RTT packet (RFC 9001 §6.5). At every other level it is `current`.
pub const KeySet = enum {
    /// The keys of the phase before, kept for packets the network delayed.
    previous,
    current,
    /// The keys of the phase after: the peer has updated, and RFC 9001 §6.2 has colibri call
    /// `update_keys` before it sends the acknowledgment.
    next,
};

/// Why a suite did not install the Initial keys. It is a configuration error and never the
/// peer's fault (invariant 25).
pub const InstallError = error{
    /// The suite cannot protect Initial packets for this role, or at all. RFC 9001 §5 fixes them to
    /// AEAD_AES_128_GCM whatever TLS negotiates.
    Unsupported,
};

pub const SealError = error{
    /// The output cannot hold the header, the payload and the tag (RFC 9001 §5.3).
    NoSpaceLeft,
    /// The level's write keys were never installed, or were discarded (RFC 9001 §4.9). colibri
    /// asserts `keys_available` first, so a suite answering this is failing closed on a defect of
    /// colibri's (invariant 21).
    KeysUnavailable,
    /// RFC 9001 §6.6: the keys have protected as many packets as the AEAD's confidentiality limit
    /// permits. colibri updates the keys, or closes the connection when it cannot.
    ConfidentialityLimitReached,
};

pub const OpenError = error{
    /// The packet is too short to hold the sample (RFC 9001 §5.4.2), or its tag does not match.
    /// §5.5 says neither necessarily indicates a protocol error or an attack: colibri drops the
    /// packet and the connection goes on.
    Discarded,
    /// The level's read keys are not installed yet, or were discarded. RFC 9001 §5.7 lets an
    /// endpoint buffer such a packet, and forbids a client from processing a 1-RTT packet before
    /// the handshake completes even when it holds the keys.
    KeysUnavailable,
    /// RFC 9001 §6.6: more packets have failed authentication than the AEAD's integrity limit
    /// permits. colibri closes the connection with AEAD_LIMIT_REACHED.
    IntegrityLimitReached,
};

pub const RetryTagError = error{
    /// The suite does not compute the Retry Integrity Tag. A suite written for clients alone
    /// answers this, and a server over it sends no Retry packet.
    Unsupported,
};

pub const UpdateError = error{
    /// RFC 9001 §6.1: only 1-RTT keys are ever updated, and they are not installed.
    KeysUnavailable,
    Unsupported,
};

/// One packet to protect. Every slice is colibri's, and none overlaps the output.
pub const Sealing = struct {
    level: Level,
    /// The full packet number, which the nonce is built from (RFC 9001 §5.3).
    packet_number: u64,
    /// The header through its Packet Number field, unprotected. It is the associated data of the
    /// AEAD, so it is final before this call (RFC 9001 §5.3).
    header: []const u8,
    /// Octets of the Packet Number field, which are the last ones of `header`.
    packet_number_len: u8,
    /// The frames. With the Packet Number field they are at least `protected_len_min` octets.
    payload: []const u8,
};

/// One packet to open, in place.
pub const Opening = struct {
    level: Level,
    /// One whole packet, which colibri has separated from the rest of its datagram
    /// (RFC 9000 §12.2).
    packet: []u8,
    /// Octets from the start of `packet` to its Packet Number field, which colibri read from the
    /// header it could see.
    packet_number_offset: usize,
    /// The largest packet number processed in this packet number space, or null before any
    /// (RFC 9000 Appendix A.3).
    largest_packet_number: ?u64,
    /// The lowest packet number processed under the current key phase, or null before any. Read
    /// at the application level alone: it tells a delayed packet of the previous phase from the
    /// first of the next, which carry the same Key Phase bit (RFC 9001 §6.5).
    current_phase_lowest: ?u64 = null,
};

/// What `open` recovered. The unprotected header is at the front of the packet, and the payload
/// follows the Packet Number field.
pub const Opened = struct {
    packet_number: u64,
    /// Octets of the Packet Number field, read from byte 0 once it was unmasked.
    packet_number_len: u8,
    /// Octets of plaintext payload, which start at `packet_number_offset + packet_number_len`.
    payload_len: usize,
    key_set: KeySet,
};

/// The calls colibri makes on packet protection it does not own. Decision 48 fixes this list, and
/// a test below holds the names to it (invariant 23).
pub const VTable = struct {
    /// Derives the Initial keys of both directions from the Destination Connection ID of the
    /// client's first Initial packet (RFC 9001 §5.2). colibri calls it again after a Retry, which
    /// changes that connection ID and so the keys.
    install_initial_keys: *const fn (context: *anyopaque, role: Role, dcid: []const u8) InstallError!void,

    /// Whether the keys of `level` are installed in `direction` and not discarded.
    keys_available: *const fn (context: *const anyopaque, level: Level, direction: Direction) bool,

    /// Writes the protected packet into `output` and returns its length, which is the header's,
    /// the payload's and `aead_tag_len`. Packet protection first, then header protection over
    /// byte 0 and the Packet Number field (RFC 9001 §5.3, §5.4).
    seal: *const fn (context: *anyopaque, sealing: Sealing, output: []u8) SealError!usize,

    /// Removes header protection, recovers the packet number and removes packet protection, in
    /// place (RFC 9001 §5.3, §5.4, §9.5). A packet that fails changes nothing the suite holds but
    /// its count of failures, so one that seems to start a key update and does not authenticate
    /// starts none (§5.5, §6.3).
    open: *const fn (context: *anyopaque, opening: Opening) OpenError!Opened,

    /// Whether `tag` is the Retry Integrity Tag of `pseudo_packet` (RFC 9001 §5.8), compared in
    /// constant time. A client's call; colibri builds the pseudo-packet.
    retry_tag_valid: *const fn (
        context: *const anyopaque,
        pseudo_packet: []const u8,
        tag: *const [constants.retry_integrity_tag_len]u8,
    ) bool,

    /// Writes the Retry Integrity Tag of `pseudo_packet` (RFC 9001 §5.8). A server's call.
    retry_tag_write: *const fn (
        context: *const anyopaque,
        pseudo_packet: []const u8,
        tag: *[constants.retry_integrity_tag_len]u8,
    ) RetryTagError!void,

    /// Moves to the next key phase, in both directions, and keeps the previous read keys
    /// (RFC 9001 §6.1, §6.2). colibri calls it to start a key update and to answer one.
    update_keys: *const fn (context: *anyopaque) UpdateError!void,

    /// The Key Phase bit the next 1-RTT packet carries (RFC 9001 §6), which colibri writes into
    /// byte 0 before it calls `seal`.
    key_phase: *const fn (context: *const anyopaque) bool,

    /// Forgets the read keys of the phase before (RFC 9001 §6.5). colibri times it.
    discard_previous_keys: *const fn (context: *anyopaque) void,

    /// Forgets the keys of `level` in both directions (RFC 9001 §4.9). colibri says when.
    discard_keys: *const fn (context: *anyopaque, level: Level) void,
};

/// One connection's packet protection, as colibri sees it: state colibri never reads, and the
/// calls it makes on it.
pub const Suite = struct {
    context: *anyopaque,
    vtable: *const VTable,

    /// Protects one packet. The assertions are colibri's half of the contract: a packet framed
    /// wrongly is colibri's defect and never the peer's.
    pub fn seal(suite: Suite, sealing: Sealing, output: []u8) SealError!usize {
        assert(sealing.packet_number <= constants.packet_number_max);
        assert(sealing.packet_number_len >= 1);
        assert(sealing.packet_number_len <= constants.packet_number_len_max);
        assert(sealing.header.len > sealing.packet_number_len);
        // RFC 9001 §5.4.2: the sender pads so the sample lies inside the packet.
        assert(sealing.packet_number_len + sealing.payload.len >= constants.protected_len_min);
        const written = try suite.vtable.seal(suite.context, sealing, output);
        assert(written == sealing.header.len + sealing.payload.len + constants.aead_tag_len);
        assert(written <= output.len);
        return written;
    }

    /// Opens one packet in place, and checks what the suite answered against the packet's size.
    pub fn open(suite: Suite, opening: Opening) OpenError!Opened {
        assert(opening.packet_number_offset >= 1);
        assert(opening.packet_number_offset <= opening.packet.len);
        assert(opening.largest_packet_number == null or
            opening.largest_packet_number.? <= constants.packet_number_max);
        const opened = try suite.vtable.open(suite.context, opening);
        assert(opened.packet_number <= constants.packet_number_max);
        assert(opened.packet_number_len >= 1 and opened.packet_number_len <= constants.packet_number_len_max);
        const protected_len = opening.packet.len - opening.packet_number_offset;
        assert(opened.packet_number_len + opened.payload_len + constants.aead_tag_len == protected_len);
        assert(opening.level == .application or opened.key_set == .current);
        return opened;
    }
};

const testing = std.testing;

test "invariant 23: the vtable's members are the ten decision 48 lists, and none returns a key" {
    const expected = [_][]const u8{
        "install_initial_keys", "keys_available",  "seal",
        "open",                 "retry_tag_valid", "retry_tag_write",
        "update_keys",          "key_phase",       "discard_previous_keys",
        "discard_keys",
    };
    const fields = @typeInfo(VTable).@"struct".fields;
    try testing.expectEqual(expected.len, fields.len);
    inline for (fields, expected) |field, name| try testing.expectEqualStrings(name, field.name);
}

test "the three levels are the ones RFC 9001 §4.1.4 names, less 0-RTT" {
    try testing.expectEqual(3, levels_count);
    try testing.expectEqual(Role.server, Role.client.peer());
    try testing.expectEqual(Role.client, Role.server.peer());
}
