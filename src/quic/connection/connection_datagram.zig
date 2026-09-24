//! One UDP datagram received, from its octets to every state they change (decision 60). Part of
//! design §8 step 9e.
//!
//! The caller read the octets and owns them. This file runs every step one datagram asks for, in
//! the order the RFCs set, so no caller has to know that order:
//!
//! 1. The datagram counts toward RFC 9000 §8.1's anti-amplification limit before anything in it
//!    is read, because the limit counts what arrived from the address, readable or not.
//! 2. A Version Negotiation or Retry packet is the only packet in its datagram (§12.2), and each
//!    has a function of its own.
//! 3. Every other packet is walked (§12.2). Each one that opens has its frames processed, and only
//!    then is it recorded in its space (§13.1) and does it restart the idle timer (§10.1).
//! 4. A HANDSHAKE_DONE confirms the handshake at a client and discards its Handshake keys (RFC
//!    9001 §4.1.2, §4.9.2).
//! 5. The provider takes what the packet's CRYPTO frames completed (RFC 9001 §4.1.3), the peer's
//!    transport parameters are read once they have arrived (§8.2), and the handshake completes when
//!    the provider says it has (§4.1.1).
//! 6. Each level the suite now holds keys for is marked installed (decision 62).
//!
//! Steps 5 and 6 run after each packet and not once for the datagram. A server's first datagram
//! carries the ServerHello in an Initial packet and the rest of its flight in Handshake packets
//! behind it (§12.2), and those open only once the ServerHello has made the Handshake keys. RFC
//! 9001 §4.1.4 asks an endpoint to buffer "packets if they might be processed using keys that are
//! not yet available", and within one datagram the packets are already held.
//!
//! A connection that is closing reads nothing and counts the datagram, which is what RFC 9000
//! §10.2.1's limit on its answers is measured against. One that is draining or closed discards it.
const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("crypto");
const tls = @import("tls");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const header = @import("../packet/packet_header.zig");
const connection_module = @import("connection.zig");
const receive_module = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const keys_module = @import("connection_keys.zig");
const connection_crypto = @import("connection_crypto.zig");
const connection_handshake = @import("connection_handshake.zig");
const connection_recovery = @import("connection_recovery.zig");
const connection_retry = @import("connection_retry.zig");
const connection_version = @import("connection_version.zig");
const migration = @import("connection_migration.zig");

const Connection = connection_module.Connection;
const Datagram = receive_module.Datagram;

/// Why the datagram ended the connection. Each is a connection error, and `connection_error_code`
/// names the code the CONNECTION_CLOSE carries.
pub const Error = receive_module.Error || frames.Error || error{
    /// The suite would not derive the Initial keys a Retry's connection ID changed (RFC 9001
    /// §5.2), so no Initial packet can be sealed or opened again.
    InitialKeysRefused,
};

/// The code a CONNECTION_CLOSE carries for `failure` (RFC 9000 §20.1). Each piece's refusal keeps
/// the code that piece names.
pub fn connection_error_code(connection: *const Connection, failure: Error) u64 {
    if (frames.member_of(receive_module.Error, failure)) |held| return receive_module.connection_error_code(held);
    // Ahead of the frame layer, because an alert's code is the one the provider raised (RFC 9001
    // §4.8), which the connection holds.
    if (frames.member_of(connection_crypto.Error, failure)) |held| return connection_crypto.close_code(connection, held);
    if (frames.member_of(frames.Error, failure)) |held| return frames.connection_error_code(held);
    assert(failure == error.InitialKeysRefused);
    // RFC 9000 §11: an endpoint with no more specific code sends INTERNAL_ERROR.
    return error_code.internal_error;
}

/// Where one datagram's work is written. The caller places it (decision 35) and passes it with
/// every datagram.
pub const Scratch = struct {
    /// The packets an ACK frame takes out, and the streams they finish (decision 59).
    recovery: connection_recovery.Scratch,
    /// The Retry Pseudo-Packet of RFC 9001 §5.8, which a Retry's tag is checked over.
    retry_pseudo: [constants.retry_pseudo_packet_len_max]u8,
};

/// What the datagram did that the caller may want to act on.
pub const Received = struct {
    /// Packets that opened and whose frames were processed.
    processed: usize = 0,
    /// The peer's CONNECTION_CLOSE, when a packet carried one (RFC 9000 §19.19).
    close: ?frames.Close = null,
    /// Streams that entered "Data Recvd" (RFC 9000 §3.1), whose octets the caller may now drop
    /// (decision 57). `scratch.recovery.completed` holds them in order.
    completed_streams: usize = 0,
    /// The token of a NEW_TOKEN frame (RFC 9000 §19.7), which points into the datagram.
    new_token: ?[]const u8 = null,
    /// Whether the handshake completed with this datagram (RFC 9001 §4.1.1).
    handshake_completed: bool = false,
    /// What a Version Negotiation packet did (RFC 9000 §6.2), when the datagram was one.
    version_negotiation: ?connection_version.Reaction = null,
    /// What a Retry packet did (RFC 9000 §17.2.5), when the datagram was one.
    retry: ?connection_retry.Outcome = null,
    /// RFC 9000 §9: a client discarded the datagram because it came from an address other than
    /// its server's (decision 72).
    from_unknown_server: bool = false,
    /// Whether the datagram carried the highest-numbered non-probing packet so far, which is what
    /// moves the path when the datagram came from a new address (RFC 9000 §9.3).
    highest_non_probing: bool = false,
    /// The server moved its path to the address the datagram came from (RFC 9000 §9.3). The
    /// caller now owes `connection_migration.challenge` the data of two PATH_CHALLENGE frames.
    migrated: bool = false,
};

/// Takes one datagram the caller received on this connection's path.
pub fn receive(
    connection: *Connection,
    suite: crypto.Suite,
    provider: tls.QuicProvider,
    datagram: Datagram,
    scratch: *Scratch,
) Error!Received {
    var received: Received = .{};
    switch (connection.termination.state) {
        .active => {},
        // RFC 9000 §10.2.1: "An endpoint that is closing is not required to process any received
        // frame", and it answers "any incoming packet" at a rate limited by how many arrived.
        .closing => {
            connection.termination.on_packet_received(datagram.now_ns);
            return received;
        },
        // RFC 9000 §10.2.2: a draining endpoint "MUST NOT send any packets", so nothing that
        // arrives can change what it does.
        .draining, .closed => return received,
    }
    // Decision 72: which of the connection's paths the datagram came from.
    const arrived = migration.arrival(connection, &datagram.from);
    if (arrived == .unknown_server) {
        received.from_unknown_server = true;
        return received;
    }
    // RFC 9000 §8.1: a server may send "three times the amount of data received from that
    // address", which every datagram counts toward whether or not a packet in it opens.
    migration.on_datagram_received(connection, arrived, datagram.octets.len);
    // Decision 62: keys the caller's code gave the suite since the last call open packets here.
    keys_module.take_available(connection, suite);
    if (try take_whole(connection, suite, datagram.octets, scratch, &received)) return received;
    try walk_packets(connection, suite, provider, datagram, scratch, &received);
    if (connection.termination.state != .active) return received;
    received.migrated = migration.after_datagram(connection, datagram.from, arrived, datagram.octets.len, received.highest_non_probing);
    return received;
}

/// A Version Negotiation or Retry packet, which carries no Length and so is the whole datagram
/// (RFC 9000 §12.2). True when the datagram was one.
fn take_whole(
    connection: *Connection,
    suite: crypto.Suite,
    octets: []const u8,
    scratch: *Scratch,
    received: *Received,
) Error!bool {
    // A header that will not parse is the walk's to discard (§12.2).
    const parsed = header.read(octets, connection.identity.local_len()) catch return false;
    switch (parsed) {
        .version_negotiation => |negotiation| {
            received.version_negotiation = connection_version.on_version_negotiation(connection, negotiation);
            return true;
        },
        .retry => |retry| {
            const outcome = connection_retry.receive(connection, suite, retry, &scratch.retry_pseudo);
            received.retry = outcome;
            const taken = switch (outcome) {
                .taken => |held| held,
                .discarded => return true,
            };
            // RFC 9001 §5.2: the Initial keys derive from the Destination Connection ID, which the
            // Retry changed (RFC 9000 §17.2.5.2).
            suite.vtable.install_initial_keys(suite.context, connection.role, taken.destination) catch
                return Error.InitialKeysRefused;
            return true;
        },
        .long, .short, .other_version => return false,
    }
}

/// Walks the packets of the datagram and processes each one that opens (RFC 9000 §12.2).
fn walk_packets(
    connection: *Connection,
    suite: crypto.Suite,
    provider: tls.QuicProvider,
    datagram: Datagram,
    scratch: *Scratch,
    received: *Received,
) Error!void {
    var walk: receive_module.Walk = undefined;
    walk.init(datagram);
    // Bounded by the walk, which separates at most `constants.coalesced_packets_max` packets.
    while (try receive_module.next(&walk, connection, suite)) |outcome| {
        const opened = switch (outcome) {
            .opened => |held| held,
            .discarded => continue,
        };
        try process_packet(connection, suite, opened, datagram, scratch, received);
        // RFC 9000 §10.2.2: a CONNECTION_CLOSE puts the connection into the draining state,
        // after which nothing the rest of the datagram holds changes anything.
        if (connection.termination.state != .active) return;
        // Before the next packet, which may need the keys this one's CRYPTO frames produced.
        try advance_handshake(connection, suite, provider, received);
    }
}

/// One packet that opened: its frames, then the record §13.1 keeps of it.
fn process_packet(
    connection: *Connection,
    suite: crypto.Suite,
    opened: receive_module.Opened,
    datagram: Datagram,
    scratch: *Scratch,
    received: *Received,
) Error!void {
    const initial_received_len = connection.crypto_at(.initial).received_len();
    const largest_before = connection.space_at(opened.level).received.largest();
    const report = try frames.process(connection, opened, datagram.now_ns, &scratch.recovery);
    // RFC 9000 §9.3: only a non-probing 1-RTT packet that raises the largest packet number moves
    // the path. Every packet before the handshake travels on the path it began on (§9).
    const raises = largest_before == null or opened.packet_number > largest_before.?;
    if (opened.level == .application and report.non_probing and raises) received.highest_non_probing = true;
    // RFC 9000 §13.1: "A packet MUST NOT be acknowledged until packet protection has been
    // successfully removed and all frames contained in the packet have been processed."
    // Decision 68: a caller that reads no codepoint passes Not-ECT, so no count rises.
    assert(connection.ecn_reads or datagram.ecn == .not_ect);
    _ = connection.space_at(opened.level).receive(opened.packet_number, datagram.now_ns, report.ack_eliciting, datagram.ecn);
    // RFC 9000 §10.1: "An endpoint restarts its idle timer when a packet from its peer is
    // received and processed successfully."
    connection.termination.on_packet_received(datagram.now_ns);
    received.processed += 1;
    // Only a 1-RTT packet acknowledges STREAM frames (RFC 9000 §12.4, Table 3), and a short header
    // is the last packet of its datagram (§12.2), so at most one packet here finishes streams and
    // the list `frames.process` writes from its start is that packet's.
    assert(received.completed_streams == 0 or report.completed_streams == 0);
    received.completed_streams += report.completed_streams;
    if (report.close) |close| received.close = close;
    if (report.owed.new_token) |token| received.new_token = token;
    // RFC 9001 §4.9.2: a client confirms the handshake on HANDSHAKE_DONE (§4.1.2), and "An
    // endpoint MUST discard its Handshake keys when the TLS handshake is confirmed".
    if (report.handshake_done) keys_module.on_handshake_confirmed(connection, suite);
    // Decision 65: an Initial packet can show the client lacks the server's CRYPTO octets.
    if (opened.level == .initial) {
        try connection_recovery.on_initial_processed(connection, report.ack_eliciting, initial_received_len, datagram.now_ns, &scratch.recovery);
    }
}

/// Hands the provider what arrived and reads back what the handshake reached.
fn advance_handshake(
    connection: *Connection,
    suite: crypto.Suite,
    provider: tls.QuicProvider,
    received: *Received,
) Error!void {
    // RFC 9001 §4.1.3: the octets CRYPTO frames delivered in order go to TLS.
    try connection_crypto.provide_handshake(connection, provider);
    // RFC 9001 §8.2: the peer's transport parameters travel in the handshake, and the connection
    // takes them the moment they have arrived.
    _ = try connection_crypto.take_peer_parameters(connection, provider);
    if (try connection_handshake.complete(connection, provider, suite)) received.handshake_completed = true;
    // RFC 9001 §4.1.4: "The availability of new keys is always a result of providing inputs to
    // TLS", so this is the moment to ask.
    keys_module.take_available(connection, suite);
}

test {
    _ = @import("connection_datagram_test.zig");
}
