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
    // output holds every flight the handshake writes before a send (`constants.flights_max`).
    assert(internal.room(connection).len >= constants.flight_len_max);
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
    const provider = connection.tls_client.provider();
    // RFC 7301 §3.2: the protocol the server selected is definitive for the connection, and a
    // selection of none is h11 (decision 88).
    internal.open_session(connection, protocol_of(provider.vtable.negotiated_alpn(provider.context)));
    // RFC 9113 §3.2, §9.2 and decision 88: the handshake is checked before any HTTP octet moves.
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
/// when it selected "http/1.1" or nothing (decision 88).
pub fn protocol_of(selected: ?[]const u8) Protocol {
    const name = selected orelse return .h11;
    return if (std.mem.eql(u8, name, &tls_provider.constants.alpn_h2)) .h2 else .h11;
}

/// Opens the records of `input` that fit, then reads the protocol from what they held until an
/// exchange ends. Returns the octets of `input` taken.
pub fn read(connection: *Connection, input: []const u8, now_ns: u64) usize {
    const consumed = open_records(connection, input, now_ns);
    internal.collect_ticket(connection);
    const taken = internal.read_protocol(connection, connection.plain_in[0..connection.plain_in_len], now_ns);
    internal.take_plaintext(connection, taken);
    // RFC 9846 §6.1: nothing follows the server's close_notify, so every exchange still awaiting
    // its response has what it will get.
    if (connection.peer_closed and connection.plain_in_len == 0 and !connection.stopped) peer_ended(connection);
    return consumed;
}

/// The server's `close_notify` arrived and every octet before it is read: a body that runs until
/// the close ends with it (RFC 9112 §9.8), and every other exchange ends.
fn peer_ended(connection: *Connection) void {
    if (connection.session == .h11) connection_h11.transport_closed(connection);
    internal.fail(connection);
}

/// Opens whole records into the protocol's octets while one fits, and returns the octets taken.
fn open_records(connection: *Connection, input: []const u8, now_ns: u64) usize {
    var consumed: usize = 0;
    // Bounded: every pass takes a whole record, or ends the loop.
    for (0..input.len + 1) |_| {
        // RFC 9846 §6.1: nothing after the peer's close_notify is read. RFC 9846 §4.7.3: a
        // KeyUpdate's reply goes out before the next record opens.
        if (connection.peer_closed or connection.reply_owed or connection.stopped) return consumed;
        const room = connection.plain_in[connection.plain_in_len..];
        const record = decrypt(connection, input[consumed..], room, now_ns) catch |failure| switch (failure) {
            // The protocol has not read enough of what earlier records held.
            error.NoSpaceLeft => return consumed,
            // An h2 connection error with its GOAWAY queued, or TLS failed with its alert owed.
            error.ConnectionFailed, error.TlsFailed => {
                internal.fail(connection);
                return consumed;
            },
            // The protocol took the provider of a finished handshake.
            error.HandshakeIncomplete, error.NoProvider => unreachable,
        };
        if (record.consumed == 0) return consumed;
        consumed += record.consumed;
        connection.plain_in_len += record.plaintext_len;
        if (record.end_of_data) connection.peer_closed = true;
        if (record.owes_handshake) connection.reply_owed = true;
    }
    unreachable; // Each record takes at least its header, so the input ends first.
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

/// Seals as much of the protocol's octets as `output` holds. A provider that owes a KeyUpdate's
/// reply, or the alert of a failure, writes it first.
fn seal(connection: *Connection, output: []u8, now_ns: u64) usize {
    var written: usize = 0;
    // Bounded: a pass seals a record at least, or ends the loop.
    for (0..constants.seals_per_send_max) |_| {
        const plaintext = connection.output[0..connection.output_len];
        const sealed = encrypt(connection, plaintext, output[written..], now_ns) catch |failure| switch (failure) {
            // The output holds no whole record: the rest waits for the next call.
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
        connection.reply_owed = false;
        if (sealed.consumed == 0) return written;
    }
    return written;
}

/// What one opened record gave, in either protocol.
const Opened = struct {
    consumed: usize,
    plaintext_len: usize,
    end_of_data: bool,
    owes_handshake: bool,
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
        .owes_handshake = decrypted.owes_handshake,
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
