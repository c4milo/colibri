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
    octets: [constants.limits.peer_address_len_max]u8 = @splat(0),
    len: u8 = 0,
    port: u16 = 0,
    /// The interface an IPv6 address is reached through, as the operating system numbers it in a
    /// socket address (`sin6_scope_id`), or 0 for none. A link-local address (fe80::/10) needs one
    /// before a program can dial it. The program sets it after `init`; colibri only compares it.
    scope_id: u32 = 0,

    /// The address `octets` and `port` name. The caller's octets must fit.
    pub fn init(octets: []const u8, port: u16) PeerAddress {
        assert(octets.len <= constants.limits.peer_address_len_max);
        var held: PeerAddress = .{ .len = @intCast(octets.len), .port = port };
        @memcpy(held.octets[0..octets.len], octets);
        return held;
    }

    /// Whether the two name the same address and port.
    pub fn eql(address: *const PeerAddress, other: *const PeerAddress) bool {
        return address.port == other.port and address.same_host(other);
    }

    /// Whether the two differ, if at all, only in the port, which RFC 9000 §9.4 treats as the
    /// likely work of NAT rebinding. The same octets through two interfaces are two hosts, and so
    /// two paths (RFC 9000 §9).
    pub fn same_host(address: *const PeerAddress, other: *const PeerAddress) bool {
        if (address.scope_id != other.scope_id) return false;
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
    const address = PeerAddress.init(&loopback, test_port);
    try testing.expect(address.eql(&PeerAddress.init(&loopback, test_port)));
    try testing.expect(!address.eql(&PeerAddress.init(&loopback, other_port)));
    try testing.expect(!address.eql(&PeerAddress.init(&other_host, test_port)));
    // An IPv6 address is not an IPv4 one with the same leading octets.
    var longer: [constants.limits.peer_address_len_max]u8 = @splat(0);
    @memcpy(longer[0..loopback.len], &loopback);
    try testing.expect(!address.eql(&PeerAddress.init(&longer, test_port)));
}

test "RFC 9000 §9.4: a change of port alone keeps the host" {
    const address = PeerAddress.init(&loopback, test_port);
    try testing.expect(address.same_host(&PeerAddress.init(&loopback, other_port)));
    try testing.expect(!address.same_host(&PeerAddress.init(&other_host, test_port)));
}

/// An IPv6 link-local address, fe80::1, which needs a scope id. Test-only.
const link_local: [constants.limits.peer_address_len_max]u8 = link_local_of();
/// fe80::/10's first two octets. Test-only.
const link_local_high: u8 = 0xfe;
const link_local_low: u8 = 0x80;

fn link_local_of() [constants.limits.peer_address_len_max]u8 {
    var octets: [constants.limits.peer_address_len_max]u8 = @splat(0);
    octets[0] = link_local_high;
    octets[1] = link_local_low;
    octets[octets.len - 1] = 1;
    return octets;
}
const interface_one: u32 = 1;
const interface_two: u32 = 2;

test "RFC 9000 §9: the same link-local octets through two interfaces are two hosts" {
    var through_one = PeerAddress.init(&link_local, test_port);
    through_one.scope_id = interface_one;
    var through_two = through_one;
    through_two.scope_id = interface_two;
    try testing.expect(!through_one.same_host(&through_two));
    try testing.expect(!through_one.eql(&through_two));
    // RFC 9000 §9.4: a new port alone, through the same interface, keeps the host.
    var rebound = through_one;
    rebound.port = other_port;
    try testing.expect(through_one.same_host(&rebound));
    try testing.expect(through_one.eql(&through_one));
}

test "decision 115: the calls a program makes on a PeerAddress" {
    // Design §8 step 51 names the constructor `init`, so an `of` beside it fails here.
    try @import("core").public_names.expect(PeerAddress, &.{ "init", "eql", "same_host" });
}
