//! The tests of a client's resume provider (`Config.resumes`, RFC 9959, decision 149, design §8
//! step 35d): the QUIC connection takes the set saved for its server when it starts, gives it back
//! when its start fails, and hands back what it observed when its flow closes.
const std = @import("std");
const quic = @import("quic");
const support = @import("quic_test_support.zig");

const testing = std.testing;
const connection = &support.connection;

/// A provider that holds one set, and what it was asked. Test-only.
const TestResumes = struct {
    held: ?quic.ResumeState,
    taken: u32,
    put: u32,
    dropped: u32,
    peer: quic.PeerAddress,
};
threadlocal var test_resumes: TestResumes align(@alignOf(TestResumes)) = undefined;
const test_vtable: quic.ResumeProvider.VTable = .{ .take = take, .put = put, .drop = drop };

fn take(context: *anyopaque, peer: quic.PeerAddress, now_ns: u64) ?quic.ResumeState {
    _ = now_ns;
    const resumes: *TestResumes = @ptrCast(@alignCast(context));
    resumes.taken += 1;
    resumes.peer = peer;
    return resumes.held;
}

fn put(context: *anyopaque, peer: quic.PeerAddress, observed: ?quic.ResumeState, now_ns: u64) void {
    _ = observed;
    _ = now_ns;
    const resumes: *TestResumes = @ptrCast(@alignCast(context));
    std.debug.assert(peer.eql(&resumes.peer));
    resumes.put += 1;
}

fn drop(context: *anyopaque, peer: quic.PeerAddress) void {
    const resumes: *TestResumes = @ptrCast(@alignCast(context));
    std.debug.assert(peer.eql(&resumes.peer));
    std.debug.assert(resumes.put == 0);
    resumes.dropped += 1;
}

const saved_window_len: u64 = 400_000;
const saved_rtt_ns: u64 = 20_000_000;
const saved: quic.ResumeState = .{ .window_len = saved_window_len, .rtt_ns = saved_rtt_ns, .saved_at_ns = support.start_ns };

fn start_resuming(held: ?quic.ResumeState) !void {
    try support.prepare(&support.alpn_h3, &support.alpn_h3, false);
    test_resumes = .{ .held = held, .taken = 0, .put = 0, .dropped = 0, .peer = .{} };
    support.config.resumes = .{ .context = &test_resumes, .vtable = &test_vtable };
    try support.init_connection(support.client_pool.storage());
}

test "RFC 9959 §3.2: a client's connection takes the set saved for its server" {
    try start_resuming(saved);
    try testing.expectEqual(1, test_resumes.taken);
    try testing.expect(test_resumes.peer.eql(&support.config.server_address));
    try testing.expectEqual(.reconnaissance, connection.transport.recovery.careful_resume.phase);
    try testing.expectEqual(saved_window_len, connection.transport.recovery.careful_resume.saved.window_len);
    connection.transport_closed();
}

test "RFC 9959 §3.1: a client's connection puts back what it observed, once, when its flow closes" {
    try start_resuming(null);
    try testing.expectEqual(0, test_resumes.put);
    connection.transport_closed();
    try testing.expectEqual(1, test_resumes.put);
    connection.transport_closed();
    try testing.expectEqual(1, test_resumes.put);
    try testing.expectEqual(0, test_resumes.dropped);
}

test "RFC 9959 §3.5: a client's connection that retreated drops the saved set before it puts" {
    try start_resuming(saved);
    connection.transport.recovery.careful_resume.retreated = true;
    connection.transport_closed();
    try testing.expectEqual(1, test_resumes.dropped);
    try testing.expectEqual(1, test_resumes.put);
}
