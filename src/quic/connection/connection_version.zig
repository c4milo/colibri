//! Version negotiation (RFC 9000 §6): the server's half writes a Version Negotiation packet and
//! the client's half reacts to one.
//!
//! The packet itself is read and written by `packet/invariant.zig`, because RFC 8999 §6 defines
//! it for every version of QUIC. What is here is §6's two connection-level decisions: when a
//! server owes one of those packets, and what a client does with one that arrives.
//!
//! **The server's half holds nothing.** RFC 9000 §6.1: "This system allows a server to process
//! packets with unsupported versions without retaining state." A server answers a datagram it
//! has no connection for, so `answer` takes no `Connection`, remembers nothing between calls,
//! and reads no clock.
//!
//! **It takes the datagram and not a packet.** RFC 9000 §17.2.1: "A server MUST NOT send more
//! than one Version Negotiation packet in response to a single UDP datagram." One datagram in
//! and at most one packet out is how that rule is kept, rather than by counting what was sent.
//! RFC 8999 §5 scopes the invariants to the first packet of a datagram, which is the packet
//! `answer` reads.
//!
//! **No version-1 rule reaches either decision.** RFC 9000 §17.2.1: "Version-specific rules for
//! the connection ID therefore MUST NOT influence a decision about whether to send a Version
//! Negotiation packet." So `answer` reads the datagram through `invariant.read_long`, which
//! cannot apply one, and a connection ID of 255 octets is echoed although version 1 stops at 20.
//!
//! **colibri speaks version 1 and no other**, which is what makes both halves short: the list a
//! server sends has one entry, and §6.2's client rule is the one for a client that supports only
//! this version.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const invariant = @import("../packet/invariant.zig");
const header = @import("../packet/packet_header.zig");
const connection_module = @import("connection.zig");

const Writer = core.Writer;
const Connection = connection_module.Connection;
const Role = crypto.suite.Role;

/// The versions colibri supports, which a Version Negotiation packet lists (RFC 9000 §6.1).
///
/// RFC 9000 §6.3 lets an endpoint add a reserved version here to test that a peer ignores what it
/// does not know. colibri adds none: the value would have to be chosen, and a fixed choice tests
/// a peer against one number rather than against the rule.
pub const supported_versions = [_]u32{constants.version_1};

/// Why no Version Negotiation packet was written.
pub const Silence = enum {
    /// RFC 9000 §17.2.1: "It is only sent by servers."
    not_a_server,
    /// RFC 8999 §6: "Packets with a short header do not trigger version negotiation."
    short_header,
    /// The datagram's first octets are not a long header at all.
    unreadable,
    /// RFC 9000 §6.1: "An endpoint MUST NOT send a Version Negotiation packet in response to
    /// receiving a Version Negotiation packet."
    is_version_negotiation,
    /// The version is one colibri speaks, so the packet belongs to a connection instead.
    version_supported,
    /// RFC 9000 §5.2.2: "Servers MUST drop smaller packets that specify unsupported versions."
    datagram_too_small,
};

/// What `answer` did with a datagram.
pub const Answer = union(enum) {
    /// No packet is owed, for this reason.
    none: Silence,
    /// The octets of `output` the Version Negotiation packet occupies. RFC 9000 §17.2.1 makes it
    /// a whole datagram of its own: it carries no Length field, so nothing may follow it.
    written: usize,
};

/// Answers `datagram` with a Version Negotiation packet when RFC 9000 §5.2.2 owes one, writing it
/// into `output`. `role` is this endpoint's, and only a server ever writes one.
///
/// It reads the datagram itself rather than taking a parsed packet, because the caller has no
/// connection to have parsed it with, and because §17.2.1's one-packet-per-datagram rule is kept
/// by the shape of this call.
pub fn answer(role: Role, datagram: []const u8, output: []u8) Answer {
    assert(datagram.len <= constants.datagram_len_max);
    // RFC 9000 §17.2.1: "It is only sent by servers."
    if (role != .server) return .{ .none = .not_a_server };
    if (datagram.len == 0) return .{ .none = .unreadable };
    // RFC 8999 §6: "Packets with a short header do not trigger version negotiation."
    if (invariant.form_of(datagram[0]) == .short) return .{ .none = .short_header };
    const received = invariant.read_long(datagram) catch return .{ .none = .unreadable };
    // RFC 9000 §6.1: "An endpoint MUST NOT send a Version Negotiation packet in response to
    // receiving a Version Negotiation packet."
    if (received.is_version_negotiation()) return .{ .none = .is_version_negotiation };
    if (speaks(received.version)) return .{ .none = .version_supported };
    // RFC 9000 §5.2.2: "If a server receives a packet that indicates an unsupported version and
    // if the packet is large enough to initiate a new connection for any supported version, the
    // server SHOULD send a Version Negotiation packet". §14.1 puts version 1's size at 1200
    // octets, and §5.2.2 makes a smaller datagram one to drop: "Servers MUST drop smaller
    // packets that specify unsupported versions."
    if (datagram.len < constants.datagram_len_min) return .{ .none = .datagram_too_small };
    return .{ .written = write(received, output) };
}

/// Writes the packet, having decided one is owed.
fn write(received: invariant.Long, output: []u8) usize {
    // The caller's buffer holds the packet §17.2.1 makes a whole datagram. Its length is known
    // before a single octet is written, so a short buffer is the caller's mistake and not the
    // peer's doing.
    assert(output.len >= invariant.version_negotiation_len(received, supported_versions.len));
    var writer = Writer.init(output);
    // RFC 9000 §17.2.1: "servers SHOULD set the most significant bit of this field (0x40) to 1
    // so that Version Negotiation packets appear to have the Fixed Bit field." The other six
    // bits are arbitrary and colibri leaves them clear, which invariant 5 also requires: it has
    // no random number to put there.
    invariant.write_version_negotiation(&writer, constants.fixed_bit, received, &supported_versions) catch
        unreachable;
    return writer.written().len;
}

/// Whether colibri speaks `version` (RFC 9000 §6.1's "versions that the server will accept").
pub fn speaks(version: u32) bool {
    for (supported_versions) |supported| {
        if (version == supported) return true;
    }
    return false;
}

/// What a client did with a Version Negotiation packet (RFC 9000 §6.2). Every arm but `abandon`
/// is a discard, and none of them closes the connection with an error: a Version Negotiation
/// packet carries no integrity protection (RFC 8999 §6), so nothing in it is the server's word.
pub const Reaction = enum {
    /// RFC 9000 §6.2: "A client that supports only this version of QUIC MUST abandon the current
    /// connection attempt if it receives a Version Negotiation packet."
    abandon,
    /// RFC 9000 §17.2.1: "It is only sent by servers", so a server discards one.
    not_a_client,
    /// RFC 9000 §6.2: "A client MUST discard any Version Negotiation packet if it has received
    /// and successfully processed any other packet, including an earlier Version Negotiation
    /// packet."
    already_processed,
    /// RFC 9000 §6.2: "A client MUST discard a Version Negotiation packet that lists the QUIC
    /// version selected by the client."
    lists_selected_version,
    /// RFC 9000 §5.2.1: a packet whose Destination Connection ID is not one this client selected
    /// belongs to no connection of its, and is discarded.
    other_connection,
    /// RFC 9000 §17.2.1: the Source Connection ID did not echo what this client addressed, so
    /// the sender did not observe the Initial it claims to answer.
    not_an_echo,
};

/// What a client does with the Version Negotiation packet `negotiation` (RFC 9000 §6.2), applying
/// §6.2's rule and both of its exceptions. `abandon` is the only arm that changes the connection,
/// and it ends the attempt.
pub fn on_version_negotiation(
    connection: *Connection,
    negotiation: header.VersionNegotiation,
) Reaction {
    const reaction = verdict(connection, negotiation);
    if (reaction != .abandon) return reaction;
    // RFC 9000 §6.2: the connection attempt is abandoned. Nothing is sent, so the connection
    // does not enter §10.2.1's closing state; it is over, as an idle timeout leaves it.
    connection.termination.on_abandoned();
    return .abandon;
}

/// §6.2's rule read in order, with nothing written.
fn verdict(connection: *const Connection, negotiation: header.VersionNegotiation) Reaction {
    // RFC 9000 §17.2.1: a Version Negotiation packet "is only sent by servers", so a server that
    // receives one discards it before any other rule is read.
    if (connection.role != .client) return .not_a_client;
    // RFC 9000 §6.2's first exception: anything already processed makes this one a discard. The
    // spaces are the record, because the caller records a packet in one once its frames have
    // been processed, which is what "successfully processed" names. An earlier Version
    // Negotiation packet acted on left the connection no longer active, which `processed` reads
    // as well.
    if (processed(connection)) return .already_processed;
    // RFC 9000 §6.2's second exception: a packet listing the version the client chose says
    // nothing, and an attacker stripping the other entries must not end the attempt.
    if (negotiation.supported.contains(constants.version_1)) return .lists_selected_version;
    return addressing(connection, negotiation);
}

/// Whether this client has received and successfully processed any packet (RFC 9000 §6.2).
fn processed(connection: *const Connection) bool {
    // RFC 9000 §6.2 counts "an earlier Version Negotiation packet" among them, and one acted on
    // abandoned the attempt, which is what leaves the connection no longer active.
    if (connection.termination.state != .active) return true;
    // RFC 9000 §17.2.5.2: a Retry the client acted on was processed, and it carries no packet
    // number, so no space records it. The Source Connection ID it made the client address is
    // what says it happened.
    if (connection.identity.retry_source != null) return true;
    // Bounded by the levels, of which RFC 9000 §12.3 names three.
    for (0..core.levels_count) |index| {
        // `space_at` takes a mutable connection and nothing here writes one, so the array the
        // three spaces live in is indexed directly.
        if (!connection.spaces[index].received.is_empty()) return true;
    }
    return false;
}

/// Whether the packet is addressed as one answering this client's Initial (RFC 9000 §17.2.1).
///
/// §17.2.1 states the two echoes as rules on the server and their purpose on the client:
/// "Echoing both connection IDs gives clients some assurance that the server received the packet
/// and that the Version Negotiation packet was not generated by an entity that did not observe
/// the Initial packet." colibri makes the check the purpose names, for the reason design §8 step
/// 9c gave: the state that answers it is already here, and what turns on it is abandoning the
/// connection attempt, which an off-path sender must not be able to do.
fn addressing(connection: *const Connection, negotiation: header.VersionNegotiation) Reaction {
    const identity = &connection.identity;
    // §17.2.1: "The server MUST include the value from the Source Connection ID field of the
    // packet it receives in the Destination Connection ID field." RFC 9000 §5.2.1 is what makes
    // a mismatch a discard: a packet whose Destination Connection ID matches no value the client
    // selected belongs to no connection of its.
    if (!std.mem.eql(u8, negotiation.dcid, identity.source().slice())) return .other_connection;
    // §17.2.1: "The value for Source Connection ID MUST be copied from the Destination
    // Connection ID of the received packet". Nothing has been processed yet, so what this client
    // addressed is still the value it chose.
    if (!std.mem.eql(u8, negotiation.scid, identity.destination().slice())) return .not_an_echo;
    return .abandon;
}

comptime {
    // RFC 9000 §6.1: a Version Negotiation packet lists "versions that the server will accept",
    // and RFC 8999 §6 makes a packet with no Supported Version field one to ignore.
    assert(supported_versions.len > 0);
}

test {
    _ = @import("connection_version_test.zig");
}
