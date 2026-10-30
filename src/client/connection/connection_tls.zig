//! The TLS half of a client connection (decision 100): the handshake through `tls.record.Client`,
//! then records opened into the protocol's octets and the protocol's octets sealed into records,
//! through h11's or h2's `connection_tls`, which apply each protocol's rules to its records.
//!
//! A handshake that fails ends the connection with what chapulin wrote, the alert that says why
//! last (RFC 9846 §6.2). A record that fails ends it with the alert the provider owes, which
//! `send` writes, and no data after it (RFC 9846 §6). A connection that is over sends its
//! `close_notify` after its last record (RFC 9846 §6.1). A ticket the server issues after the
//! handshake (RFC 9846 §4.6.1) is taken as the records that carried it open.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const h2 = @import("h2");
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");
const connection_h11 = @import("connection_h11.zig");
const Protocols = @import("../protocols.zig").Protocols;

const Connection = connection_module.Connection;
const Protocol = event.Protocol;

/// Why a record did not open or go out, in either protocol. Both name the same five.
const RecordError = h2.connection_tls.RecordError || h11.connection_tls.RecordError;

/// Runs the handshake over what the transport read, and returns the octets taken. Once it
/// completes, the protocol ALPN selected takes the session, and the rest of `input` is read as its
/// records.
pub fn handshake(connection: *Connection, input: []u8, now_ns: u64) usize {
    assert(connection.phase == .handshake);
    // chapulin writes all a call owes, a ClientHello or the alert of a refused flight, and the
    // output holds every flight the handshake writes before a send (`constants.limits.flights_max`).
    assert(internal.room(connection).len >= constants.limits.flight_len_max);
    const progress = connection.tls_client.handshake(input, internal.room(connection)) catch {
        // RFC 9846 §6.2: what the refused handshake wrote ends with the alert that says why, and
        // the connection closes once `send` has written it.
        connection.output_len += connection.tls_client.failure_written();
        connection.records_len = connection.output_len;
        connection.phase = .closed;
        internal.fail(connection);
        return 0;
    };
    connection.output_len += progress.written;
    connection.records_len = connection.output_len;
    if (!progress.complete) return progress.consumed;
    if (!attach(connection)) return progress.consumed;
    return progress.consumed + read(connection, input[progress.consumed..], now_ns);
}

/// Opens the protocol ALPN selected over the finished handshake, after that protocol's checks.
/// Returns whether the protocol took it.
fn attach(connection: *Connection) bool {
    return attach_provider(connection, connection.tls_client.provider());
}

/// `attach` over `provider`. The connection passes its handshake's own provider, and the record
/// tests pass one that protects nothing (`plain_provider_test_support.zig`).
pub fn attach_provider(connection: *Connection, provider: tls_provider.Provider) bool {
    // RFC 7301 §3.2: the protocol the server selected is definitive for the connection, and a
    // selection of none is h11 only while `versions` allows it (decisions 88 and 117).
    internal.open_session(connection, protocol_of(provider.vtable.negotiated_alpn(provider.context), connection.config.protocols));
    // RFC 9113 §3.2, §3.3, §9.2 and decision 88: the handshake is checked before any HTTP octet
    // moves, and h2 refuses one that did not select it.
    const attached = switch (connection.session) {
        .h2 => |*session| session.attach_tls(provider),
        .h11 => |*session| session.attach_tls(provider),
        .none => unreachable,
    };
    attached catch {
        connection.owed.connected = false;
        connection.phase = .closed;
        internal.fail(connection);
        return false;
    };
    return true;
}

/// The protocol a finished handshake runs: h2 when ALPN selected "h2" (RFC 9113 §3.2), and h11
/// when it selected "http/1.1". A selection of none is h11 while `versions` allows it (decision
/// 88), and otherwise h2, whose own check then refuses the handshake: RFC 9113 §3.3 has h2 over
/// TLS "use protocol negotiation in TLS" (decision 117).
pub fn protocol_of(selected: ?[]const u8, versions: Protocols) Protocol {
    const name = selected orelse return if (versions.h11) .h11 else .h2;
    return if (std.mem.eql(u8, name, &tls_provider.constants.protocol.alpn_h2)) .h2 else .h11;
}

/// Opens the records of `input` that fit, one that carries the protocol's octets at a time, and
/// has the protocol read all it can of each before the next one opens. Returns the octets of
/// `input` taken. A record that fails ends the protocol's session (RFC 9846 §6), so the protocol
/// reads what the records before it held first: some of a response arrived, and the pool does
/// not send the request again (decision 124).
pub fn read(connection: *Connection, input: []const u8, now_ns: u64) usize {
    var consumed: usize = 0;
    // Bounded: each pass opens a record that carries octets of the input, or ends the loop.
    for (0..input.len + 1) |_| {
        read_held(connection, now_ns);
        const taken = open_records(connection, input[consumed..], now_ns);
        consumed += taken.consumed;
        if (taken.failed) {
            internal.fail(connection);
            break;
        }
        if (!taken.data) break;
    }
    internal.collect_ticket(connection);
    // RFC 9846 §6.1: nothing follows the server's close_notify, so every exchange still awaiting
    // its response has what it will get.
    if (connection.peer_closed and connection.plain_in_len == 0 and !connection.stopped) peer_ended(connection);
    return consumed;
}

/// Reads the protocol from what earlier records opened until it takes nothing more: it needs more
/// octets, or it ended. Each exchange that ends is reported later, one a call.
fn read_held(connection: *Connection, now_ns: u64) void {
    // Bounded: each pass takes octets, or ends the loop.
    for (0..connection.plain_in_len + 1) |_| {
        if (connection.plain_in_len == 0) return;
        const taken = internal.read_protocol(connection, connection.plain_in[0..connection.plain_in_len], now_ns);
        internal.take_plaintext(connection, taken);
        if (taken == 0) return;
    }
}

/// The server's `close_notify` arrived and every octet before it is read: a body that runs until
/// the close ends with it (RFC 9112 §9.8), and every other exchange ends.
fn peer_ended(connection: *Connection) void {
    if (connection.session == .h11) connection_h11.transport_closed(connection);
    internal.fail(connection);
}

/// What `open_records` took: octets of the input, whether a record carried the protocol's octets,
/// and whether a record failed.
const Taken = struct {
    consumed: usize = 0,
    data: bool = false,
    failed: bool = false,
};

/// Opens whole records into the protocol's octets while one fits, up to the first that carries
/// some, and returns what it took. The caller ends the connection on a failed record, once the
/// protocol read what the records before it held.
fn open_records(connection: *Connection, input: []const u8, now_ns: u64) Taken {
    var taken: Taken = .{};
    // Bounded: every pass takes a whole record, or ends the loop.
    for (0..input.len + 1) |_| {
        // RFC 9846 §6.1: nothing after the peer's close_notify is read. RFC 9846 §4.7.3 asks for a
        // KeyUpdate's answer "prior to sending its next Application Data record". The provider
        // writes the answer in front of that record, so this loop opens records while it is owed.
        if (connection.peer_closed or connection.stopped) return taken;
        const room = connection.plain_in[connection.plain_in_len..];
        const record = decrypt(connection, input[taken.consumed..], room, now_ns) catch |failure| switch (failure) {
            // The protocol has not read enough of what earlier records held.
            error.NoSpaceLeft => return taken,
            // An h2 connection error with its GOAWAY queued, or TLS failed with its alert owed.
            error.ConnectionFailed, error.TlsFailed => {
                taken.failed = true;
                return taken;
            },
            // The protocol took the provider of a finished handshake.
            error.HandshakeIncomplete, error.NoProvider => unreachable,
        };
        if (record.consumed == 0) return taken;
        taken.consumed += record.consumed;
        taken.data = keep(connection, record);
        if (taken.data) return taken;
    }
    unreachable; // Each record takes at least its header, so the input ends first.
}

/// Keeps what an opened record held, and returns whether it carried the protocol's octets.
fn keep(connection: *Connection, record: Opened) bool {
    connection.plain_in_len += record.plaintext_len;
    if (record.end_of_data) connection.peer_closed = true;
    return record.plaintext_len > 0;
}

/// Writes what the handshake owes, or the flight's records, then seals the protocol's octets, then
/// the `close_notify` once the connection is over. Returns the octets written into `output`.
pub fn send(connection: *Connection, output: []u8, now_ns: u64) usize {
    // The ClientHello is staged at `init`, and goes out whether or not `receive` ran first.
    if (connection.phase == .handshake) _ = handshake(connection, &.{}, now_ns);
    const copied = @min(output.len, connection.records_len);
    @memcpy(output[0..copied], connection.output[0..copied]);
    internal.take_output(connection, copied);
    // Records the call leaves filled `output`, so nothing is sealed after them, and nothing is
    // sealed before the protocol opens or after the connection closed.
    if (connection.phase != .open) return copied;
    var written = copied + seal(connection, output[copied..], now_ns);
    if (connection.close_sent or connection.output_len > 0 or !internal.finished(connection)) return written;
    // RFC 9846 §6.1: "Each party MUST send a "close_notify" alert before closing its write side of
    // the connection".
    written += close_notify(connection, output[written..]) catch return written;
    connection.close_sent = true;
    return written;
}

/// Seals as much of the protocol's octets as `output` holds. A provider that owes the answer to a
/// KeyUpdate writes it in front of the first record. After a failure, it writes only its alert.
fn seal(connection: *Connection, output: []u8, now_ns: u64) usize {
    var written: usize = 0;
    // Bounded: a pass seals a record at least, or ends the loop.
    for (0..constants.limits.seals_per_send_max) |_| {
        const plaintext = connection.output[0..connection.output_len];
        const sealed = encrypt(connection, plaintext, output[written..], now_ns) catch |failure| switch (failure) {
            // The provider refused `output` as shorter than a record it may write
            // (`tls_provider.constants.protocol.record_write_len_min`): the rest waits for the next call.
            error.NoSpaceLeft => return written,
            // RFC 9846 §6: no data goes out after a failure, and the next pass writes the alert
            // the provider owes.
            error.TlsFailed => {
                connection.output_len = 0;
                internal.fail(connection);
                continue;
            },
            error.ConnectionFailed, error.HandshakeIncomplete, error.NoProvider => unreachable,
        };
        written += sealed.written;
        internal.take_output(connection, sealed.consumed);
        if (sealed.consumed == 0) return written;
    }
    return written;
}

/// What one opened record gave, in either protocol.
const Opened = struct {
    consumed: usize,
    plaintext_len: usize,
    end_of_data: bool,
};

fn decrypt(connection: *Connection, input: []const u8, plaintext: []u8, now_ns: u64) RecordError!Opened {
    return switch (connection.session) {
        .h2 => |*session| opened(try h2.connection_tls.decrypt(session, input, plaintext, now_ns)),
        .h11 => |*session| opened(try h11.connection_tls.decrypt(session, input, plaintext)),
        // Records open only once the protocol took the handshake's provider.
        .none => unreachable,
    };
}

fn opened(decrypted: anytype) Opened {
    return .{
        .consumed = decrypted.consumed,
        .plaintext_len = decrypted.plaintext_len,
        .end_of_data = decrypted.end_of_data,
    };
}

fn encrypt(connection: *Connection, plaintext: []const u8, output: []u8, now_ns: u64) RecordError!tls_provider.provider.Sealed {
    return switch (connection.session) {
        .h2 => |*session| h2.connection_tls.encrypt(session, plaintext, output, now_ns),
        .h11 => |*session| h11.connection_tls.encrypt(session, plaintext, output, now_ns),
        .none => unreachable,
    };
}

fn close_notify(connection: *Connection, output: []u8) RecordError!usize {
    return switch (connection.session) {
        .h2 => |*session| h2.connection_tls.close_notify(session, output),
        .h11 => |*session| h11.connection_tls.close_notify(session, output),
        .none => unreachable,
    };
}
