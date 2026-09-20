//! The TLS provider vtable in QUIC mode, which serves h3 ([decision 8](../../docs/decisions.md)).
//! `provider.zig` is record mode, which serves h2. No production implementation is in this tree.
//!
//! **QUIC takes the record layer's job, so the interface is not the same one.** RFC 9001 §3 says
//! QUIC "takes over the responsibilities of the TLS record layer", and §4.1 replaces it with two
//! flows: handshake octets move at an encryption level and application data is protected by
//! `crypto.Suite` instead. So there is no `encrypt_record`, no `decrypt_record` and no
//! `send_close_notify` here — a QUIC connection closes with a CONNECTION_CLOSE frame, not an
//! alert record (§4.8).
//!
//! **colibri never sees a secret.** [Decision 48](../../docs/decisions.md) removed `on_secret`
//! and `hkdf_expand_label` from this list: the secrets of RFC 9001 §4.1.4 go from the provider to
//! the suite inside the caller's own code, and colibri asks `crypto.Suite.keys_available` when it
//! wants to know whether a level can carry a packet yet. That is why nothing below takes or
//! returns a key.
//!
//! **An alert is a value, not a record.** RFC 9001 §4.8 converts a TLS alert into a QUIC
//! connection error: "The AlertDescription value is added to 0x0100 to produce a QUIC error code
//! from the range reserved for CRYPTO_ERROR". So `take_alert` answers the description and the
//! connection does the addition, which `quic.error_code.crypto_error` holds — `tls` and `quic`
//! are not neighbours in design §3's graph, and the arithmetic belongs on the QUIC side anyway.
//! §4.8 also settles the level: "a QUIC endpoint MUST treat any alert from TLS as if it were at
//! the 'fatal' level", so there is no level to report beside the description.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const alert = @import("alert.zig");

const Alert = alert.Alert;

/// The encryption level handshake octets move at (RFC 9001 §4.1.4). It is `core`'s, because
/// `crypto.Suite` speaks it too and design §3 makes `tls` and `crypto` siblings.
pub const Level = core.Level;

/// Why a provider would not take the transport parameters colibri encoded.
pub const TransportParamsError = error{
    /// RFC 9001 §4.1.3: "Before starting the handshake, QUIC provides TLS with the transport
    /// parameters that it wishes to carry." A provider given them later has already sent the
    /// message that must carry them.
    HandshakeStarted,
    /// The provider refused them and `take_alert` names the description (RFC 9001 §4.8).
    TlsFailed,
};

/// Why a provider would not take handshake octets colibri read out of CRYPTO frames.
pub const ProvideError = error{
    /// The handshake failed. RFC 9001 §4.8 makes it a connection error, and `take_alert` names
    /// the description the CONNECTION_CLOSE carries.
    TlsFailed,
    /// RFC 9001 §4.1.3: each level is its own flow of octets, and the provider is not reading
    /// this one yet. RFC 9000 §12.5 makes octets at the wrong level a protocol violation.
    WrongLevel,
    /// One handshake message is larger than the provider's own storage. There is no record layer
    /// to bound a message in QUIC (RFC 9001 §4.1.3), so the provider states its own limit.
    NoSpaceLeft,
};

/// Why a provider would not write the handshake octets it owes.
pub const WriteError = error{
    TlsFailed,
    /// The output cannot hold what the provider owes at this level, and nothing was written.
    NoSpaceLeft,
};

/// Why a provider did not export keying material (RFC 9846 §7.5).
pub const ExportError = error{
    /// The exporter derives from `exporter_master_secret`, which exists after the server's
    /// Finished (RFC 9846 §7.5).
    HandshakeIncomplete,
    /// The provider does not offer the exporter.
    Unsupported,
    TlsFailed,
};

/// The calls colibri makes on a TLS stack it does not own, in QUIC mode. Decision 8 fixes this
/// list, and decision 48 is why no member moves a secret.
pub const VTable = struct {
    /// Gives the provider the `quic_transport_parameters` extension body colibri encoded
    /// (RFC 9001 §8.2, codepoint 0x39; the body is RFC 9000 §18's). RFC 9001 §4.1.3 requires
    /// this before the handshake starts, which is why it is not folded into the first
    /// `write_handshake`.
    set_transport_params: *const fn (context: *anyopaque, body: []const u8) TransportParamsError!void,

    /// The peer's `quic_transport_parameters` body, or null before it has arrived. RFC 9001 §8.2
    /// carries it in the ClientHello and in EncryptedExtensions, so a client has it only once it
    /// has read the server's EncryptedExtensions. The octets are the provider's and stay valid
    /// for the life of the connection; colibri reads them through `transport_parameters_read`.
    peer_transport_params: *const fn (context: *const anyopaque) ?[]const u8,

    /// Hands the provider handshake octets colibri reassembled from CRYPTO frames at `level`
    /// (RFC 9001 §4.1.3). They are unframed handshake-message bytes in order, which is what
    /// `quic.crypto_stream` produces, and a message may arrive across several calls.
    provide_handshake: *const fn (context: *anyopaque, level: Level, data: []const u8) ProvideError!void,

    /// Writes the handshake octets the provider owes at `level` and returns how many. 0 means it
    /// owes none there. colibri puts them in CRYPTO frames at the packet type RFC 9001 Table 1
    /// pairs with the level.
    write_handshake: *const fn (context: *anyopaque, level: Level, output: []u8) WriteError!usize,

    /// The protocol the handshake selected (RFC 7301 §3.1), or null before it has one. RFC 9001
    /// §8.1 makes ALPN mandatory in QUIC: "endpoints MUST use ALPN".
    negotiated_alpn: *const fn (context: *const anyopaque) ?[]const u8,

    /// Whether the handshake has completed (RFC 9001 §4.1.1). It is not the same as confirmed,
    /// which §4.1.2 defines and which the connection tracks: a server confirms when the handshake
    /// completes, a client when it receives a HANDSHAKE_DONE frame, and neither is TLS's to say.
    handshake_complete: *const fn (context: *const anyopaque) bool,

    /// The alert the provider raised, which the call clears, or null when it raised none. It is
    /// the AlertDescription value alone (RFC 9001 §4.8), because §4.8 makes every alert fatal in
    /// QUIC and the connection turns the description into a CRYPTO_ERROR code.
    take_alert: *const fn (context: *anyopaque) ?Alert,

    /// RFC 9846 §7.5's exporter, which decision 8 keeps in both modes because it is the one
    /// operation RFC 9846 gives a standard interface.
    export_keying_material: *const fn (
        context: *anyopaque,
        label: []const u8,
        context_value: ?[]const u8,
        output: []u8,
    ) ExportError!void,
};

/// One TLS session in QUIC mode, as colibri holds it. The wrapper asserts colibri's half of the
/// contract; what the provider owes is the vtable's documentation.
pub const QuicProvider = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub fn set_transport_params(held: QuicProvider, body: []const u8) TransportParamsError!void {
        // RFC 9001 §8.2: endpoints MUST send the extension, so an empty body is colibri failing
        // to encode its own parameters rather than a choice.
        assert(body.len > 0);
        return held.vtable.set_transport_params(held.context, body);
    }

    pub fn peer_transport_params(held: QuicProvider) ?[]const u8 {
        return held.vtable.peer_transport_params(held.context);
    }

    pub fn provide_handshake(held: QuicProvider, level: Level, data: []const u8) ProvideError!void {
        // A call with nothing to hand over is colibri's defect: `crypto_stream.readable` says how
        // many octets there are and a caller with none has no reason to call.
        assert(data.len > 0);
        return held.vtable.provide_handshake(held.context, level, data);
    }

    pub fn write_handshake(held: QuicProvider, level: Level, output: []u8) WriteError!usize {
        assert(output.len > 0);
        const written = try held.vtable.write_handshake(held.context, level, output);
        assert(written <= output.len);
        return written;
    }

    pub fn negotiated_alpn(held: QuicProvider) ?[]const u8 {
        return held.vtable.negotiated_alpn(held.context);
    }

    pub fn handshake_complete(held: QuicProvider) bool {
        return held.vtable.handshake_complete(held.context);
    }

    pub fn take_alert(held: QuicProvider) ?Alert {
        return held.vtable.take_alert(held.context);
    }

    pub fn export_keying_material(
        held: QuicProvider,
        label: []const u8,
        context_value: ?[]const u8,
        output: []u8,
    ) ExportError!void {
        assert(label.len > 0 and output.len > 0);
        return held.vtable.export_keying_material(held.context, label, context_value, output);
    }

    /// True when the handshake selected the protocol `wanted` (RFC 7301 §3.1). RFC 9001 §8.1
    /// makes ALPN mandatory in QUIC, so a session that selected nothing is refused rather than
    /// assumed.
    pub fn speaks(held: QuicProvider, wanted: []const u8) bool {
        const selected = held.negotiated_alpn() orelse return false;
        return std.mem.eql(u8, selected, wanted);
    }
};

const testing = std.testing;

test "decision 8: QUIC mode carries the members it names and none that moves a secret" {
    const names = @typeInfo(VTable).@"struct".fields;
    // The eight decision 8 lists for this mode, and nothing else.
    try testing.expectEqual(8, names.len);
    const expected = [_][]const u8{
        "set_transport_params",
        "peer_transport_params",
        "provide_handshake",
        "write_handshake",
        "negotiated_alpn",
        "handshake_complete",
        "take_alert",
        "export_keying_material",
    };
    inline for (expected, 0..) |name, index| {
        try testing.expectEqualStrings(name, names[index].name);
    }
    // Decision 48 removed `on_secret` and `hkdf_expand_label`, and invariant 23's rule holds here
    // too: no member of either vtable moves a key, a secret or an IV.
    inline for (names) |field| {
        try testing.expect(!std.mem.containsAtLeast(u8, field.name, 1, "secret"));
        try testing.expect(!std.mem.containsAtLeast(u8, field.name, 1, "key") or
            std.mem.eql(u8, field.name, "export_keying_material"));
    }
}

test "RFC 9001 §4.8: an alert is a description, and the connection makes the error code" {
    // The mapping itself is `quic.error_code.crypto_error`, which `tls` cannot reach. What this
    // pins is that the vtable answers a description at all, which is what that function takes.
    const reported: ?Alert = .handshake_failure;
    try testing.expectEqual(40, @intFromEnum(reported.?));
}

test "RFC 9001 §4.1.4: the levels are core's three, in the order Table 1 pairs with packet types" {
    try testing.expectEqual(3, core.levels_count);
    try testing.expectEqual(Level.initial, @as(Level, @enumFromInt(0)));
    try testing.expectEqual(Level.handshake, @as(Level, @enumFromInt(1)));
    try testing.expectEqual(Level.application, @as(Level, @enumFromInt(2)));
}
