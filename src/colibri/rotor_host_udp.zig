//! The UDP part of colibri's own Rotor host for `.private` (decision 159): the group of receive
//! buffers that one multishot receive reads into, the `Outbound` record that each send reads
//! until its event, and the conversions between Rotor's addresses and codepoints and colibri's.
//! The group of 16 buffers of 66 KiB moved here out of `datagram_socket.zig`, so its size does not
//! change. On Linux the kernel coalesces datagrams from one peer (UDP_GRO), which Rotor splits
//! again, and cuts each batch into datagrams (UDP_SEGMENT, design §8 step 13f.6).
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const rotor = @import("rotor");
const server = @import("server");
const constants = @import("constants.zig");
const host = @import("host.zig");

const group_options: rotor.datagram.GroupOptions = .{};
pub const group_bytes = rotor.buffers.group_bytes(constants.limits.udp_receive_buffers, constants.limits.udp_receive_buffer_len);

/// The buffer groups one host reserves on its own loop: one for its one UDP socket.
pub const buffer_groups = 1;

comptime {
    assert(buffer_groups <= rotor.constants.buffer_groups_max);
    assert(constants.limits.udp_batches <= std.math.maxInt(u8));
    // A program may place a `Datagrams` in a static, which macOS aligns to 16 KiB at most. So the
    // type asks for no more than the loop's alignment, and `group_memory` aligns the rest by hand.
    assert(@alignOf(Datagrams) <= rotor.memory_alignment);
}

/// The options a UDP socket opens with: Linux coalesces what arrives.
pub const socket_options: rotor.sync.DatagramOptions = .{ .coalesce = builtin.os.tag == .linux };

pub const Datagrams = struct {
    /// The receive buffers, and the group the loop knows them by. The field is larger than the
    /// group by its alignment, and `group_memory` aligns forward inside it. The field states no
    /// alignment of 64 KiB: macOS places a static at 16 KiB, so the compiler would trust an
    /// address that is not true, and an optimized build computes offsets from it that are wrong.
    group: [group_bytes + rotor.buffers.group_alignment]u8 align(rotor.memory_alignment),
    buffer_group: rotor.BufferGroup,
    /// Where each send goes, which Rotor reads until the send's event, and which records are in
    /// use.
    outbound: [constants.limits.udp_batches]rotor.datagram.Outbound,
    outbound_used: std.StaticBitSet(constants.limits.udp_batches),

    /// Reserves the group on a loop that the host just made, and gives the loop the buffers. The
    /// group id stays reserved until the loop's `deinit`.
    pub fn start(datagrams: *Datagrams, loop: *rotor.Loop) rotor.Loop.ProvideError!void {
        // The loop is new and the host reserves `buffer_groups` on it, so an id is free.
        datagrams.buffer_group = loop.reserve_buffer_group() catch unreachable;
        try loop.provide_datagram_buffers(datagrams.buffer_group, datagrams.group_memory(), constants.limits.udp_receive_buffers, constants.limits.udp_receive_buffer_len, group_options);
        datagrams.outbound_used = .initEmpty();
    }

    /// The receive buffers' block, aligned forward inside the field: a static declared that
    /// aligned is not always placed that aligned on macOS, which rotor's guide notes.
    fn group_memory(datagrams: *Datagrams) []align(rotor.buffers.group_alignment) u8 {
        const at = std.mem.alignForward(usize, @intFromPtr(&datagrams.group), rotor.buffers.group_alignment);
        const aligned: [*]align(rotor.buffers.group_alignment) u8 = @ptrFromInt(at);
        return aligned[0..group_bytes];
    }

    /// The multishot receive on `socket` into the group.
    pub fn receive(datagrams: *const Datagrams, user_data: u64, socket: rotor.Descriptor) rotor.Operation {
        return .{ .user_data = user_data, .kind = .{ .receive_from = .{ .socket = socket, .group = datagrams.buffer_group } } };
    }

    /// Takes a free `Outbound` record for one send, or null when each one is in use.
    pub fn take_outbound(datagrams: *Datagrams, written: anytype) ?u8 {
        var free = datagrams.outbound_used.complement();
        const index = free.toggleFirstSet() orelse return null;
        datagrams.outbound_used.set(index);
        datagrams.outbound[index] = outbound(written.to, written.ecn, written.segment_bytes);
        return @intCast(index);
    }

    /// The send that record `index` describes.
    pub fn send(datagrams: *Datagrams, user_data: u64, socket: rotor.Descriptor, bytes: []const u8, index: u8) rotor.Operation {
        assert(datagrams.outbound_used.isSet(index));
        return .{ .user_data = user_data, .kind = .{ .send_to = .{
            .socket = socket,
            .buffer = .{ .bytes = bytes },
            .to = &datagrams.outbound[index],
        } } };
    }

    /// Gives record `index` back once its send's event arrived.
    pub fn release(datagrams: *Datagrams, index: u8) void {
        assert(datagrams.outbound_used.isSet(index));
        datagrams.outbound_used.unset(index);
    }

    /// The completion of a receive's event, or null for a datagram cut short that more events
    /// follow, which is dropped as a lost datagram is. The bytes stay the loop's until
    /// `give_back` (Rotor's decision 15 as amended).
    pub fn completion(datagrams: *const Datagrams, loop: *const rotor.Loop, event: rotor.Event, id: host.OperationId) ?host.Completion {
        const more = event.flags.more;
        if (!event.flags.buffer) return .{ .id = id, .more = more, .result = failure_result(event) };
        const delivery = loop.datagram(datagrams.buffer_group, event);
        // Rotor splits what the kernel coalesced, so each delivery holds one datagram.
        assert(delivery.from.segment_bytes == 0);
        if (delivery.from.flags.truncated) {
            if (more) return null;
            return .{ .id = id, .result = .{ .failed = .other } };
        }
        return .{ .id = id, .more = more, .result = .{ .datagram = .{
            .bytes = delivery.bytes,
            .from = peer_address(delivery.from.peer),
            .ecn = received_ecn(&delivery.from),
        } } };
    }

    /// Gives a receive's buffer back to the loop, once colibri has read it.
    pub fn give_back(datagrams: *const Datagrams, loop: *rotor.Loop, event: rotor.Event) void {
        if (event.flags.buffer) loop.give_back_buffer(datagrams.buffer_group, event.flags.buffer_id);
    }
};

/// The result of an event that carries no datagram: a cancel, or a failure.
fn failure_result(event: rotor.Event) host.Completion.Result {
    _ = event.outcome() catch |failure| return result_of_error(failure);
    return .{ .failed = .other };
}

/// colibri's result for one of Rotor's errors (decision 159). A cancel and a deadline that
/// passed are both `.canceled`.
pub fn result_of_error(failure: rotor.Error) host.Completion.Result {
    return switch (failure) {
        error.Canceled, error.Timeout => .canceled,
        error.ConnectionRefused => .{ .failed = .refused },
        error.ConnectionReset, error.ConnectionAborted, error.BrokenPipe => .{ .failed = .reset },
        error.NetworkUnreachable => .{ .failed = .unreachable_address },
        error.NotConnected => .{ .failed = .closed },
        else => .{ .failed = .other },
    };
}

/// Where a batch goes, asking Rotor to set the codepoint colibri named (decision 68), and to cut
/// it into segments of its first datagram's length.
fn outbound(to: server.Address, ecn: server.Ecn, segment_bytes: u16) rotor.datagram.Outbound {
    const sent = sent_ecn(ecn);
    return .{
        .peer = rotor_address(to),
        .local = undefined,
        .segment_bytes = segment_bytes,
        .ecn = sent,
        .flags = .{ .peer = true, .ecn = sent != .not_ect },
    };
}

/// A socket address as colibri names a peer's (decision 72).
pub fn peer_address(address: rotor.Address) server.Address {
    const len: usize = if (address.family == .ipv4) rotor.Address.ipv4_bytes else address.bytes.len;
    var peer = server.Address.init(address.bytes[0..len], address.port);
    peer.scope_id = address.scope_id;
    return peer;
}

/// A peer's address as colibri names it, back in Rotor's form, for a UDP send or a TCP connect.
pub fn rotor_address(address: server.Address) rotor.Address {
    if (address.len == rotor.Address.ipv4_bytes) return rotor.Address.ipv4(address.octets[0..rotor.Address.ipv4_bytes].*, address.port);
    assert(address.len == address.octets.len);
    return rotor.Address.ipv6(address.octets, address.port, address.scope_id);
}

/// The codepoint Rotor read off a datagram's IP header, as colibri names it (RFC 9000 §13.4).
fn received_ecn(from: *const rotor.datagram.Received) server.Ecn {
    if (!from.flags.ecn) return .not_ect;
    return switch (from.ecn) {
        .not_ect => .not_ect,
        .ect0 => .ect_0,
        .ect1 => .ect_1,
        .ce => .ecn_ce,
    };
}

/// The codepoint colibri named for a datagram, as Rotor sets it (RFC 9000 §13.4).
fn sent_ecn(ecn: server.Ecn) rotor.datagram.Ecn {
    return switch (ecn) {
        .not_ect => .not_ect,
        .ect_0 => .ect0,
        .ect_1 => .ect1,
        .ecn_ce => .ce,
    };
}

const testing = std.testing;

/// The peer of the tests of the codepoints, on loopback. Test-only.
const test_port: u16 = 4433;
const test_loopback_word: u32 = 0x7f00_0001;
const test_peer = rotor.Address.ipv4(@bitCast(std.mem.nativeToBig(u32, test_loopback_word)), test_port);
/// Each codepoint as Rotor names it, and as colibri names it, in the same order. Test-only.
const rotor_codepoints = [_]rotor.datagram.Ecn{ .not_ect, .ect0, .ect1, .ce };
const colibri_codepoints = [_]server.Ecn{ .not_ect, .ect_0, .ect_1, .ecn_ce };

test "design §8 step 37: a batch goes to Rotor with the codepoint the engine named" {
    for (colibri_codepoints, rotor_codepoints) |named, expected| {
        const sent = outbound(peer_address(test_peer), named, 0);
        // RFC 9000 §13.4: Rotor sets the codepoint in the IP header only when its flag is set.
        try testing.expectEqual(expected, sent.ecn);
        try testing.expectEqual(named != .not_ect, sent.flags.ecn);
        try testing.expect(sent.flags.peer);
        try testing.expectEqual(test_port, sent.peer.port);
    }
}

test "design §8 step 37: the engine gets the codepoint Rotor read, and Not-ECT when Rotor read none" {
    for (rotor_codepoints, colibri_codepoints) |read, expected| {
        var from: rotor.datagram.Received = .{ .peer = test_peer, .local = undefined, .segment_bytes = 0, .ecn = read, .flags = .{ .ecn = true } };
        try testing.expectEqual(expected, received_ecn(&from));
        from.flags.ecn = false;
        try testing.expectEqual(server.Ecn.not_ect, received_ecn(&from));
    }
}

test "decision 159: Rotor's errors become colibri's failures" {
    try testing.expectEqual(host.Completion.Result.canceled, result_of_error(error.Canceled));
    try testing.expectEqual(host.Completion.Result.canceled, result_of_error(error.Timeout));
    try testing.expectEqual(host.Failure.refused, result_of_error(error.ConnectionRefused).failed);
    try testing.expectEqual(host.Failure.reset, result_of_error(error.BrokenPipe).failed);
    try testing.expectEqual(host.Failure.other, result_of_error(error.SystemResources).failed);
}

test "decision 72: an address goes from Rotor's form to colibri's and back" {
    const ipv6 = rotor.Address.ipv6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, test_port, 3);
    for ([_]rotor.Address{ test_peer, ipv6 }) |address| {
        const back = rotor_address(peer_address(address));
        try testing.expectEqual(address.family, back.family);
        try testing.expectEqual(address.port, back.port);
        try testing.expectEqual(address.scope_id, back.scope_id);
    }
}
