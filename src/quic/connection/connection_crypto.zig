//! The handshake over CRYPTO frames (RFC 9001 §4.1.3), which is what step 9e is named for.
//!
//! Three things meet here and none of them owns the other two. `quic.crypto_stream` turns the
//! frames a peer sent into an in-order run of octets per encryption level (RFC 9000 §19.6). The
//! caller's `tls.QuicProvider` consumes that run and produces the octets colibri owes back
//! (decision 8). And `quic.frame` writes those into CRYPTO frames. This file is the wiring, and
//! it holds no key: the secrets go from the provider to the caller's `crypto.Suite` without
//! passing through colibri ([decision 48](../../../docs/decisions.md)).
//!
//! **The transport parameters are part of the handshake, not something beside it.** RFC 9001
//! §8.2 carries them in a TLS extension, so colibri hands its own to the provider before the
//! handshake starts and reads the peer's out of the provider once the handshake has carried
//! them. `take_peer_parameters` is where the connection learns what it may spend.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const tls = @import("tls");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const frame_module = @import("../frame/frame.zig");
const frame_stream = @import("../frame/frame_stream.zig");
const transport_parameters = @import("../transport_parameters.zig");
const transport_parameters_read = @import("../transport_parameters_read.zig");
const connection_module = @import("connection.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const identity_module = @import("connection_identity.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Record = recovery_sent.Record;
const Writer = core.Writer;

/// Why the handshake failed. Each one is a QUIC connection error, and `connection_error_code`
/// says which code the CONNECTION_CLOSE carries.
pub const Error = error{
    /// RFC 9000 §7.5: more out-of-order CRYPTO data than colibri buffers.
    CryptoBufferExceeded,
    /// RFC 9001 §4.8: the provider raised an alert, whose description the connection turns into
    /// a CRYPTO_ERROR code.
    TlsAlert,
    /// The provider failed and raised no alert colibri could read, which §4.8 still makes a
    /// connection error.
    TlsFailed,
    /// RFC 9000 §12.5: CRYPTO octets at a level the provider is not reading.
    WrongLevel,
    /// RFC 9000 §7.4: the peer's transport parameters were refused.
    ParametersRefused,
    /// RFC 9001 §8.2: "endpoints that receive ClientHello or EncryptedExtensions messages without
    /// the quic_transport_parameters extension MUST close the connection".
    ParametersMissing,
    /// RFC 9000 §7.3: the peer's parameters do not authenticate the connection IDs its packets
    /// carried, and `connection_identity.Error` says which of §7.3's rules it broke.
    ConnectionIdsUnauthenticated,
    /// One handshake message is larger than the provider's storage, or the output cannot hold
    /// what it owes.
    NoSpaceLeft,
};

/// The code a CONNECTION_CLOSE carries for `failure`. A TLS alert is not among them: RFC 9001
/// §4.8 makes its code the description plus 0x0100, which `alert_error_code` computes from the
/// description the provider reported.
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        // RFC 9000 §20.1: CRYPTO_BUFFER_EXCEEDED, which §7.5 names for exactly this.
        error.CryptoBufferExceeded => error_code.crypto_buffer_exceeded,
        // RFC 9000 §7.4: a parameter with an invalid value, or a missing extension (§8.2).
        error.ParametersRefused, error.ParametersMissing => error_code.transport_parameter_error,
        // RFC 9000 §7.3 names TRANSPORT_PARAMETER_ERROR for the absence of a connection ID
        // parameter, and permits it for every other rule the section states.
        error.ConnectionIdsUnauthenticated => error_code.transport_parameter_error,
        // RFC 9000 §12.5: octets at the wrong encryption level violate the protocol.
        error.WrongLevel => error_code.protocol_violation,
        // RFC 9000 §11: an endpoint with no more specific code sends INTERNAL_ERROR.
        error.NoSpaceLeft, error.TlsFailed, error.TlsAlert => error_code.internal_error,
    };
}

/// The code a CONNECTION_CLOSE carries for `failure` on `connection`: an alert's own CRYPTO_ERROR
/// code when the provider raised one (RFC 9001 §4.8), and `connection_error_code` otherwise.
pub fn close_code(connection: *const Connection, failure: Error) u64 {
    if (failure == error.TlsAlert) {
        if (connection.tls_alert) |description| return alert_error_code(description);
    }
    return connection_error_code(failure);
}

/// The code a TLS alert closes the connection with (RFC 9001 §4.8): "The AlertDescription value
/// is added to 0x0100 to produce a QUIC error code from the range reserved for CRYPTO_ERROR."
pub fn alert_error_code(description: tls.Alert) u64 {
    return error_code.crypto_error(@intFromEnum(description));
}

/// Takes one CRYPTO frame the peer sent at `level` (RFC 9000 §19.6). What it holds joins the
/// level's in-order run, and a retransmission of octets already read changes nothing.
pub fn receive_crypto(connection: *Connection, level: Level, crypto: frame_stream.Crypto) Error!void {
    connection.crypto_at(level).receive(crypto.offset, crypto.data) catch |failure| switch (failure) {
        error.CryptoBufferExceeded => return Error.CryptoBufferExceeded,
    };
}

/// Hands the provider every octet it can read now, at every level (RFC 9001 §4.1.3). A level with
/// nothing in order yet is skipped, and what the provider takes is forgotten.
pub fn provide_handshake(connection: *Connection, provider: tls.QuicProvider) Error!void {
    // Bounded by the levels, of which RFC 9001 §4.1.4 names three.
    for (0..core.levels_count) |index| {
        const level: Level = @enumFromInt(index);
        const stream = connection.crypto_at(level);
        const readable = stream.readable();
        if (readable.len == 0) continue;
        provider.provide_handshake(level, readable) catch |failure| return provider_failure(connection, provider, failure);
        // The provider took the whole run: RFC 9001 §4.1.3 gives it octets and keeps no offset,
        // so a message it cannot finish yet is the provider's to hold, not colibri's.
        stream.consume(readable.len);
    }
}

/// Writes the handshake octets the provider owes at `level` into `output` as a CRYPTO frame, and
/// returns how many octets of `output` the frame occupies. 0 means the provider owes none there.
/// What one CRYPTO frame took, which the send path reports so RFC 9000 §13.3 can send the same
/// octets again if the packet carrying them is lost.
pub const Written = struct {
    /// Octets of `output` the frame occupies, its own header included.
    len: usize = 0,
    /// Where its payload sits in the level's flow (RFC 9000 §19.6).
    offset: u64 = 0,
    /// Octets of that payload, which one packet bounds.
    payload_len: u16 = 0,
};

pub fn write_crypto(
    connection: *Connection,
    provider: tls.QuicProvider,
    level: Level,
    output: []u8,
) Error!Written {
    assert(output.len > 0);
    const stream = connection.crypto_at(level);
    // The provider gives its octets up once, so they go into the level's own window before they
    // go into a packet: RFC 9000 §13.3 retransmits them and §17.2.5.3 repeats them after a Retry.
    const room = stream.send_room();
    if (room.len > 0) {
        const produced = provider.write_handshake(level, room) catch |failure|
            return provider_failure(connection, provider, failure);
        stream.produced(produced);
    }
    const waiting = stream.unsent();
    if (waiting.len == 0) return .{};
    // The frame's own header costs octets, so the payload cannot have all of `output`. The
    // Offset it reserves room for is the one `write_frame` will write: RFC 9000 §19.6 makes it
    // how many octets colibri has sent at this level, which is a different number from how many
    // it has read out of the peer's flow at the same level.
    const header_len = crypto_frame_header_len(stream.sent_len, output.len);
    if (output.len <= header_len) return .{};
    const len = @min(waiting.len, output.len - header_len);
    const offset = stream.sent_len;
    return .{
        .len = try write_frame(connection, level, waiting[0..len], output),
        .offset = offset,
        .payload_len = @intCast(len),
    };
}

/// What a lost flight amounted to (RFC 9000 §13.3).
pub const Lost = struct {
    /// How many of the lost packets carried CRYPTO octets, which is what will be framed again.
    packets: usize = 0,
    /// Whether any of them sat below the level's send window, so its octets are gone. §13.3 has
    /// no answer for that: the handshake cannot go on, and the caller ends the connection.
    forgotten: bool = false,
};

/// RFC 9000 §13.3's first rule over what RFC 9002's loss detection declared lost: "Data sent in
/// CRYPTO frames is retransmitted according to the rules in [QUIC-RECOVERY], until all data has
/// been acknowledged." The records are the caller's storage (decision 35), so they arrive as a
/// slice rather than being reached for.
///
/// §13.3 also says "Data in CRYPTO frames for Initial and Handshake packets is discarded when
/// keys for the corresponding packet number space are discarded", which is `Recovery.discard_space`
/// dropping the records before they can be reported here.
pub fn on_packets_lost(connection: *Connection, level: Level, lost: []const Record) Lost {
    var held: Lost = .{};
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (lost) |record| {
        if (record.carries != .crypto) continue;
        held.packets += 1;
        if (!connection.crypto_at(level).on_lost(record.data_offset)) held.forgotten = true;
    }
    return held;
}

/// Puts the octets in a CRYPTO frame at the level's current offset, and advances it.
fn write_frame(connection: *Connection, level: Level, payload: []const u8, output: []u8) Error!usize {
    const stream = connection.crypto_at(level);
    var writer = Writer.init(output);
    // RFC 9000 §19.6: the Offset is where these octets sit in the level's own flow, which is how
    // many colibri has already sent on it.
    frame_stream.write_crypto(&writer, .{ .offset = stream.sent_len, .data = payload }) catch
        return Error.NoSpaceLeft;
    stream.framed(payload.len);
    return writer.written().len;
}

/// What a CRYPTO frame's type, offset and length cost before its payload (RFC 9000 §19.6). It is
/// an upper bound: the length is encoded for the whole of `room`, so the payload never overruns.
fn crypto_frame_header_len(offset: u64, room: usize) usize {
    return frame_type_len + wire.varint.encoded_len_minimal(offset) +
        wire.varint.encoded_len_minimal(room);
}

/// A CRYPTO frame's type is 0x06, one octet as a variable-length integer (RFC 9000 §19.6).
const frame_type_len: usize = 1;

/// Reads the peer's transport parameters out of the provider once the handshake has carried them
/// (RFC 9001 §8.2), and gives them to the connection. Answers false while they have not arrived.
pub fn take_peer_parameters(connection: *Connection, provider: tls.QuicProvider) Error!bool {
    if (connection.peer_parameters != null) return true;
    const body = provider.peer_transport_params() orelse {
        // RFC 9001 §8.2 requires the extension, but a client has not read EncryptedExtensions
        // yet at this point in the handshake, so its absence is only fatal once the handshake
        // completes. `require_peer_parameters` is where that is decided.
        return false;
    };
    var reader = core.Reader.init(body);
    const peer = transport_parameters_read.read(&reader, connection.role.peer()) catch
        return Error.ParametersRefused;
    // RFC 9000 §7.3: "Endpoints MUST validate that received transport parameters match received
    // connection ID values." It runs before the limits are raised, so a peer that failed it never
    // widens what colibri may spend.
    identity_module.authenticate(&connection.identity, &peer, connection.role) catch
        return Error.ConnectionIdsUnauthenticated;
    connection.apply_peer_parameters(peer);
    return true;
}

/// RFC 9001 §8.2: a handshake that completed without the extension is a connection error.
pub fn require_peer_parameters(connection: *const Connection) Error!void {
    if (connection.peer_parameters == null) return Error.ParametersMissing;
}

/// Turns a provider's failure into the connection error RFC 9001 §4.8 makes it. The alert is
/// kept on the connection, so `close_code` can name its CRYPTO_ERROR code.
fn provider_failure(connection: *Connection, provider: tls.QuicProvider, failure: anyerror) Error {
    return switch (failure) {
        error.WrongLevel => Error.WrongLevel,
        error.NoSpaceLeft => Error.NoSpaceLeft,
        // RFC 9001 §4.8: TLS generates an alert, and a QUIC endpoint treats every one as fatal.
        error.TlsFailed => {
            connection.tls_alert = provider.take_alert();
            return if (connection.tls_alert != null) Error.TlsAlert else Error.TlsFailed;
        },
        else => Error.TlsFailed,
    };
}

test {
    _ = @import("connection_crypto_test.zig");
}
