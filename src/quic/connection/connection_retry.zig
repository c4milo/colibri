//! Retry (RFC 9000 §17.2.5): what a client does with one it receives, the token it repeats
//! afterwards (§8.1.2), and what a server writes to ask for address validation.
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
//! **What a client repeats after a Retry.** §17.2.5.3: "A client MUST use the same cryptographic
//! handshake message it included in this packet." `CryptoStream` keeps the level's own flow, so
//! the repeat is a rewind of what was already produced rather than a second ask of the provider.
//!
//! **The server's half holds nothing.** §8.1.2: a Retry lets a server "defer the state and
//! processing costs of connection establishment", so `answer` takes no `Connection`. It mints no
//! token either: decision 55 puts that on the suite, because §8.1.4 wants the token authenticated
//! and expiring, which needs a key non-negotiable 2 refuses colibri and an instant non-negotiable
//! 3 makes a parameter.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
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

/// What a server needs to write a Retry (RFC 9000 §17.2.5.1). colibri chooses none of it: §5.1
/// wants a connection ID unpredictable and invariant 5 forbids colibri a random number, and it
/// owns no socket, so the address is the caller's opaque octets.
pub const Request = struct {
    /// §17.2.5.1: "The server populates the Destination Connection ID with the connection ID that
    /// the client included in the Source Connection ID of the Initial packet."
    client_source: []const u8,
    /// The Destination Connection ID of that Initial, which RFC 9001 §5.8 covers as the Original
    /// Destination Connection ID and §7.3 later sends as original_destination_connection_id.
    original_destination: []const u8,
    /// §17.2.5.1: "The server includes a connection ID of its choice in the Source Connection ID
    /// field."
    server_source: []const u8,
    /// The client's address, which §8.1.4 binds the token to. colibri never reads what it means.
    address: []const u8,
    /// The instant, which the suite measures the token's lifetime against (non-negotiable 3).
    now_ns: u64,
};

/// Why no Retry packet was written.
pub const Refused = enum {
    /// §17.2.5.1: the Source Connection ID "MUST NOT be equal to the Destination Connection ID
    /// field of the packet sent by the client", which is what a client discards on.
    source_is_destination,
    /// The suite wrote no address validation token, so there is no Retry to send: §17.2.5.2 has
    /// a client discard "a Retry packet with a zero-length Retry Token field".
    no_token,
    /// The suite does not write the Retry Integrity Tag of RFC 9001 §5.8, as a suite for clients
    /// alone does not.
    no_tag,
    /// `output` cannot hold the packet.
    no_space,
};

pub const Answer = union(enum) {
    /// Octets of `output` the Retry packet occupies.
    written: usize,
    refused: Refused,
};

/// Writes one Retry packet into the front of `output` (RFC 9000 §17.2.5.1). `pseudo` is where the
/// Retry Pseudo-Packet of RFC 9001 §5.8 is built, which the caller places (decision 35).
///
/// §8.1.2 says when a server may call this: "In response to processing an Initial packet
/// containing a token that was provided in a Retry packet, a server cannot send another Retry
/// packet", so a server asks `verify_token` first and answers `.absent` alone.
pub fn answer(
    suite: Suite,
    request: Request,
    pseudo: *[constants.retry_pseudo_packet_len_max]u8,
    output: []u8,
) Answer {
    assert(request.client_source.len <= constants.connection_id_len_max);
    assert(request.server_source.len <= constants.connection_id_len_max);
    // §17.2.5.1: "This value MUST NOT be equal to the Destination Connection ID field of the
    // packet sent by the client", and a client that saw one would discard the Retry.
    if (std.mem.eql(u8, request.server_source, request.original_destination)) {
        return .{ .refused = .source_is_destination };
    }
    var token: [constants.token_len_max]u8 = undefined;
    const token_len = suite.vtable.retry_token_write(
        suite.context,
        request.address,
        request.now_ns,
        &token,
    ) catch return .{ .refused = .no_token };
    if (token_len == 0) return .{ .refused = .no_token };
    return write_packet(suite, request, token[0..token_len], pseudo, output);
}

/// The packet itself, once the token exists: RFC 9000 §17.2.5's fields, then RFC 9001 §5.8's tag
/// over what they amount to.
fn write_packet(
    suite: Suite,
    request: Request,
    token: []const u8,
    pseudo: *[constants.retry_pseudo_packet_len_max]u8,
    output: []u8,
) Answer {
    var writer = Writer.init(output);
    header_write.write_retry(&writer, .{
        // §17.2.5: "The value in the Unused field is set to an arbitrary value by the server; a
        // client MUST ignore these bits." Zero is arbitrary, and invariant 5 forbids colibri the
        // random number a greased value would need.
        .unused_bits = 0,
        .dcid = request.client_source,
        .scid = request.server_source,
        .token = token,
    }) catch return .{ .refused = .no_space };
    var pseudo_writer = Writer.init(pseudo);
    // The token is bounded above and both connection IDs at 20 octets (RFC 9000 §17.2), so
    // `retry_pseudo_packet_len_max` holds every packet this writes.
    header_write.write_retry_pseudo_packet(
        &pseudo_writer,
        request.original_destination,
        writer.written(),
    ) catch unreachable;
    var tag: [constants.retry_integrity_tag_len]u8 = undefined;
    suite.vtable.retry_tag_write(suite.context, pseudo_writer.written(), &tag) catch
        return .{ .refused = .no_tag };
    writer.write_bytes(&tag) catch return .{ .refused = .no_space };
    return .{ .written = writer.written().len };
}

/// What a client's Initial says about address validation (RFC 9000 §8.1.2), read off its Token
/// field before a server decides whether to send a Retry.
pub const TokenVerdict = enum {
    /// RFC 9000 §17.2.2: the Initial carried no token, so nothing validates the address and
    /// §8.1.2 lets the server send a Retry.
    absent,
    /// §8.1.2: the token is one this server wrote, which "proves to the server that it received
    /// the token". The address is validated and no further Retry may be sent.
    validated,
    /// §8.1.2: "If a server receives a client Initial that contains an invalid Retry token but is
    /// otherwise valid, it knows the client will not accept another Retry token."
    invalid,
};

/// Asks the suite whether the Initial's token is one it wrote for this address (RFC 9000 §8.1.4).
pub fn verify_token(suite: Suite, address: []const u8, token: []const u8, now_ns: u64) TokenVerdict {
    if (token.len == 0) return .absent;
    if (suite.vtable.retry_token_valid(suite.context, address, token, now_ns)) return .validated;
    return .invalid;
}

/// The code a CONNECTION_CLOSE carries for `verdict`, or null when the connection goes on.
pub fn connection_error_code(verdict: TokenVerdict) ?u64 {
    return switch (verdict) {
        .absent, .validated => null,
        // §8.1.2: the server "SHOULD immediately close (Section 10.2) the connection with an
        // INVALID_TOKEN error", which RFC 9000 §20.1 numbers 0x0b. §8.1.2 adds that the server
        // "has not established any state for the connection at this point and so does not enter
        // the closing period".
        .invalid => error_code.invalid_token,
    };
}

test {
    _ = @import("connection_retry_test.zig");
    _ = @import("connection_retry_server_test.zig");
}
