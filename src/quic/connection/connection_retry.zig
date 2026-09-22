//! What a client does with a Retry packet (RFC 9000 §17.2.5.2), and the token it repeats
//! afterwards (§8.1.2).
//!
//! **Nothing in a Retry is protected.** §17.2.5 says so in as many words, so every rule here is a
//! discard and none is a connection error. The Retry Integrity Tag of RFC 9001 §5.8 is what
//! separates a Retry the server sent from one an attacker injected, and it is the caller's
//! `crypto.Suite` that checks it ([decision 48](../../../docs/decisions.md)); colibri builds the
//! pseudo-packet §5.8 covers and asks.
//!
//! **The packet is `packet/packet_header.zig`'s; the decision is here.** What this file adds is
//! whether a Retry is one to act on, and what acting on it changes: the connection ID a client
//! addresses, and the token every later Initial carries.
//!
//! **colibri installs no key.** RFC 9001 §5.2: "These keys change after receiving a Retry
//! packet", and the Initial keys derive from the Destination Connection ID. `Taken` reports the
//! new one and the caller installs over it, exactly as it installed the first set.
//!
//! **What a client still owes after a Retry.** §17.2.5.3: "A client MUST use the same
//! cryptographic handshake message it included in this packet." colibri keeps no copy of what it
//! sent on the CRYPTO stream, so the Initial that repeats the ClientHello is not built here.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const header = @import("../packet/packet_header.zig");
const header_write = @import("../packet/packet_header_write.zig");
const connection_module = @import("connection.zig");

const Writer = core.Writer;
const Connection = connection_module.Connection;
const Suite = crypto.Suite;

/// The Retry token a client repeats (RFC 9000 §8.1.2). Decision 54 sizes it: both RFCs bound the
/// field only by the packet that carries it, so `token_len_max` is a judgement written down once.
pub const Token = struct {
    octets: [constants.token_len_max]u8,
    len: usize,

    pub fn init(token: *Token) void {
        token.octets = @splat(0);
        token.len = 0;
    }

    /// RFC 9000 §17.2.5.3: "The value of the Token field is copied to all subsequent Initial
    /// packets", so a client keeps the octets rather than the packet they came in.
    pub fn take(token: *Token, octets: []const u8) void {
        assert(octets.len <= constants.token_len_max);
        // §17.2.5.2: a client acts on one Retry per connection attempt, so this is written once.
        assert(token.len == 0);
        @memcpy(token.octets[0..octets.len], octets);
        token.len = octets.len;
    }

    /// What an Initial packet's Token field carries (RFC 9000 §17.2.2), empty until a Retry.
    pub fn slice(token: *const Token) []const u8 {
        return token.octets[0..token.len];
    }
};

/// Why a Retry packet changed nothing.
pub const Discarded = enum {
    /// RFC 9000 §17.2.5: a Retry "is used by a server that wishes to perform a retry", so only a
    /// client acts on one.
    not_a_client,
    /// §17.2.5.2: "A client MUST accept and process at most one Retry packet for each connection
    /// attempt", and none after an Initial from the server.
    already_answered,
    /// §17.2.5.1: "A client MUST discard a Retry packet that contains a Source Connection ID
    /// field that is identical to the Destination Connection ID field of its Initial packet."
    source_is_destination,
    /// A token longer than decision 54's storage. §8.1.2 has a client repeat the token in every
    /// later Initial, so one it cannot hold is one it cannot answer, and failing closed here
    /// leaves the connection attempt to time out rather than sending a Retry back malformed.
    token_too_long,
    /// §17.2.5.2: "Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot
    /// be validated" (RFC 9001 §5.8).
    tag_invalid,
    /// §17.2.5.3 has a client repeat the cryptographic handshake message it already sent, and its
    /// first flight was longer than the send window colibri keeps, so those octets are gone.
    flight_forgotten,
};

/// What the Retry changed.
pub const Taken = struct {
    /// RFC 9000 §17.2.5.2: the Retry's Source Connection ID, which the client now puts in the
    /// Destination Connection ID field of the packets it sends. RFC 9001 §5.2 derives the new
    /// Initial keys from it, which the caller installs.
    destination: []const u8,
};

pub const Outcome = union(enum) {
    taken: Taken,
    discarded: Discarded,
};

/// Acts on one Retry packet. `pseudo` is where the Retry Pseudo-Packet of RFC 9001 §5.8 is built,
/// which the caller places (decision 35) and nothing reads after this returns.
pub fn receive(
    connection: *Connection,
    suite: Suite,
    retry: header.Retry,
    pseudo: *[constants.retry_pseudo_packet_len_max]u8,
) Outcome {
    if (refuse(connection, retry)) |why| return .{ .discarded = why };
    if (!tag_valid(connection, suite, retry, pseudo)) return .{ .discarded = .tag_invalid };
    // RFC 9000 §17.2.5.2: "A client sets the Destination Connection ID field of this Initial
    // packet to the value from the Source Connection ID field in the Retry packet."
    connection.identity.on_retry(retry.scid);
    // §8.1.2: "This token MUST be repeated by the client in all Initial packets it sends for that
    // connection after it receives the Retry packet."
    connection.retry_token.take(retry.token);
    // §17.2.5.3: the same cryptographic handshake message goes out again, in a new Initial with
    // the new Destination Connection ID and the token. The packet number is not reset: §17.2.5.3
    // forbids it, and nothing here touches the space.
    connection.crypto_at(.initial).rewind();
    assert(connection.identity.retry_source != null);
    return .{ .taken = .{ .destination = retry.scid } };
}

/// Every rule RFC 9000 §17.2.5 states that the Retry Integrity Tag is not needed to apply. They
/// come first so a Retry colibri would refuse anyway costs no tag check.
fn refuse(connection: *const Connection, retry: header.Retry) ?Discarded {
    if (connection.role != .client) return .not_a_client;
    // §17.2.5.2: "After the client has received and processed an Initial or Retry packet from the
    // server, it MUST discard any subsequent Retry packets that it receives." §7.2 records both:
    // a Retry sets `retry_source` and an Initial that opened sets `peer_initial_source`.
    if (connection.identity.retry_source != null) return .already_answered;
    if (connection.identity.peer_initial_source != null) return .already_answered;
    // §17.2.5.1: the Source Connection ID "MUST NOT be equal to the Destination Connection ID
    // field of the packet sent by the client", which before any Retry is what `destination`
    // answers.
    if (std.mem.eql(u8, retry.scid, connection.identity.destination().slice())) {
        return .source_is_destination;
    }
    if (retry.token.len > constants.token_len_max) return .token_too_long;
    // §17.2.5.3: "A client MUST use the same cryptographic handshake message it included in this
    // packet." That message is what the Initial level's send window still holds, so a first
    // flight larger than the window is a Retry colibri cannot answer.
    if (!connection.crypto_streams.at_const(.initial).can_rewind()) return .flight_forgotten;
    return null;
}

/// RFC 9001 §5.8: the Retry Integrity Tag covers the Retry Pseudo-Packet, which is the Original
/// Destination Connection ID with its length octet followed by the Retry packet less its tag.
fn tag_valid(
    connection: *const Connection,
    suite: Suite,
    retry: header.Retry,
    pseudo: *[constants.retry_pseudo_packet_len_max]u8,
) bool {
    var writer = Writer.init(pseudo);
    // `refuse` bounded the token and the reader bounds both connection IDs at 20 octets
    // (RFC 9000 §17.2), so `retry_pseudo_packet_len_max` holds every Retry that reaches here.
    header_write.write_retry_pseudo_packet(
        &writer,
        connection.identity.original_destination.slice(),
        retry.without_tag,
    ) catch unreachable;
    return suite.vtable.retry_tag_valid(suite.context, writer.written(), retry.integrity_tag);
}

test {
    _ = @import("connection_retry_test.zig");
}
