//! The QUIC versions a null suite protects packets in (decision 108), with the rules chapulin's
//! packet calls apply: a connection starts in its original version, a client switches once to
//! the negotiated version, and from then on the Initial level admits both while the Handshake and
//! application levels admit the negotiated one alone (RFC 9369 §4.1).
const std = @import("std");
const assert = std.debug.assert;
const crypto = @import("crypto");

const Level = crypto.suite.Level;
const Role = crypto.suite.Role;
const Version = crypto.suite.Version;

pub const Versions = struct {
    /// The version the client's first Initial packet carries (RFC 9368 §2).
    original: Version = .v1,
    /// The version every Handshake and 1-RTT packet carries, which is the original one until a
    /// client switches or a server chooses another (RFC 9369 §4.1).
    negotiated: Version = .v1,
    switched: bool = false,

    pub fn of(original: Version) Versions {
        return .{ .original = original, .negotiated = original };
    }

    /// Whether a packet at `level` in `version` is one the suite protects. RFC 9369 §4.1: "Both
    /// endpoints MUST send Handshake and 1-RTT packets using the negotiated version", and a
    /// server answers Initial packets in the original version before it has chosen.
    pub fn admits(versions: Versions, level: Level, version: Version) bool {
        return version == versions.negotiated or (level == .initial and version == versions.original);
    }

    /// RFC 9369 §4.1's one switch, which is a client's. `handshake_keys` says the Handshake keys
    /// exist, which they do once the server's first CRYPTO octets were delivered, and after that
    /// no switch comes.
    pub fn switch_to(versions: *Versions, role: Role, handshake_keys: bool, version: Version) crypto.suite.SwitchError!void {
        if (role != .client or versions.switched or handshake_keys) return error.Refused;
        if (version == versions.negotiated) return error.Refused;
        versions.negotiated = version;
        versions.switched = true;
        assert(versions.negotiated != versions.original);
    }
};

const testing = std.testing;

test "RFC 9369 §4.1: a connection that has not switched admits its original version alone" {
    for ([_]Version{ .v1, .v2 }) |original| {
        const versions: Versions = .of(original);
        const other: Version = if (original == .v1) .v2 else .v1;
        for ([_]Level{ .initial, .handshake, .application }) |level| {
            try testing.expect(versions.admits(level, original));
            try testing.expect(!versions.admits(level, other));
        }
    }
}

test "RFC 9369 §4.1: a client switches once, and then the Initial level admits both versions" {
    var versions: Versions = .of(.v1);
    try versions.switch_to(.client, false, .v2);
    try testing.expectEqual(Version.v2, versions.negotiated);
    try testing.expect(versions.admits(.initial, .v1) and versions.admits(.initial, .v2));
    for ([_]Level{ .handshake, .application }) |level| {
        try testing.expect(versions.admits(level, .v2) and !versions.admits(level, .v1));
    }
    // "the first long header Version field that differs": one switch, and never back.
    try testing.expectError(error.Refused, versions.switch_to(.client, false, .v1));
    try testing.expectEqual(Version.v2, versions.negotiated);
}

test "RFC 9369 §4.1: a server, a client past the server's CRYPTO octets, and the same version are refused" {
    var server: Versions = .of(.v1);
    try testing.expectError(error.Refused, server.switch_to(.server, false, .v2));
    var late: Versions = .of(.v1);
    try testing.expectError(error.Refused, late.switch_to(.client, true, .v2));
    var same: Versions = .of(.v2);
    try testing.expectError(error.Refused, same.switch_to(.client, false, .v2));
    for ([_]Versions{ server, late, same }) |refused| {
        try testing.expect(!refused.switched);
        try testing.expectEqual(refused.original, refused.negotiated);
    }
}
