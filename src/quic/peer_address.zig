//! A peer's address as the caller names it (decision 72). colibri owns no socket
//! (non-negotiable 1), so it never learns an address on its own: the caller passes the one each
//! datagram came from, and colibri compares two of them to follow RFC 9000 §9's rules for a peer
//! whose address changed. It never reads the octets otherwise.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const PeerAddress = struct {
    /// The address's octets: 4 for IPv4 and 16 for IPv6, or none for a caller that names no
    /// address. The rest stay zero, so two equal addresses are equal octet for octet.
    octets: [constants.peer_address_len_max]u8 = @splat(0),
    len: u8 = 0,
    port: u16 = 0,

    /// The address `octets` and `port` name. The caller's octets must fit.
    pub fn of(octets: []const u8, port: u16) PeerAddress {
        assert(octets.len <= constants.peer_address_len_max);
        var held: PeerAddress = .{ .len = @intCast(octets.len), .port = port };
        @memcpy(held.octets[0..octets.len], octets);
        return held;
    }

    /// Whether the two name the same address and port.
    pub fn eql(address: *const PeerAddress, other: *const PeerAddress) bool {
        return address.port == other.port and address.same_host(other);
    }

    /// Whether the two differ, if at all, only in the port, which RFC 9000 §9.4 treats as the
    /// likely work of NAT rebinding.
    pub fn same_host(address: *const PeerAddress, other: *const PeerAddress) bool {
        return address.len == other.len and std.mem.eql(u8, address.host(), other.host());
    }

    fn host(address: *const PeerAddress) []const u8 {
        return address.octets[0..address.len];
    }
};

const testing = std.testing;

const test_port: u16 = 443;
const other_port: u16 = 444;
/// Two IPv4 hosts, each its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const other_octet: u8 = 0x7e;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const other_host: [ipv4_len]u8 = @splat(other_octet);

test "decision 72: two addresses are equal when their octets and their port are" {
    const address = PeerAddress.of(&loopback, test_port);
    try testing.expect(address.eql(&PeerAddress.of(&loopback, test_port)));
    try testing.expect(!address.eql(&PeerAddress.of(&loopback, other_port)));
    try testing.expect(!address.eql(&PeerAddress.of(&other_host, test_port)));
    // An IPv6 address is not an IPv4 one with the same leading octets.
    var longer: [constants.peer_address_len_max]u8 = @splat(0);
    @memcpy(longer[0..loopback.len], &loopback);
    try testing.expect(!address.eql(&PeerAddress.of(&longer, test_port)));
}

test "RFC 9000 §9.4: a change of port alone keeps the host" {
    const address = PeerAddress.of(&loopback, test_port);
    try testing.expect(address.same_host(&PeerAddress.of(&loopback, other_port)));
    try testing.expect(!address.same_host(&PeerAddress.of(&other_host, test_port)));
}
