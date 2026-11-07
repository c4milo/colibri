//! The tests of a server's resume provider (`Config.resumes`, RFC 9959, decision 149, design §8
//! step 35d): a connection takes the set saved for its client when it starts, and hands back
//! what it observed, after a deletion when it retreated, when it ends.
const std = @import("std");
const quic = @import("quic");
const support = @import("../quic/quic_test_support.zig");

const testing = std.testing;
const engine_support = support.engine_support;
const engine = &engine_support.engine;
const ok: u16 = 200;
/// RFC 9000 §10.2: the closing state lasts three PTOs, which this many rounds pass.
const closing_rounds = support.rounds_default * closing_rounds_factor;
const closing_rounds_factor = 8;

/// A provider that holds one set, and what it was asked. Test-only.
const TestResumes = struct {
    held: ?quic.ResumeState,
    taken: u32,
    put: u32,
    dropped: u32,
    peer: quic.PeerAddress,
    observed: ?quic.ResumeState,
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
    _ = now_ns;
    const resumes: *TestResumes = @ptrCast(@alignCast(context));
    std.debug.assert(peer.eql(&resumes.peer));
    resumes.put += 1;
    resumes.observed = observed;
}

fn drop(context: *anyopaque, peer: quic.PeerAddress) void {
    const resumes: *TestResumes = @ptrCast(@alignCast(context));
    std.debug.assert(peer.eql(&resumes.peer));
    // §3.5's deletion comes before the connection's `put`.
    std.debug.assert(resumes.put == 0);
    resumes.dropped += 1;
}

/// A set for any client, saved at the start of the test's clock.
const saved_window_len: u64 = 400_000;
const saved_rtt_ns: u64 = 20_000_000;

fn start_resuming_engine(held: ?quic.ResumeState) !void {
    try support.start_engine(null);
    test_resumes = .{ .held = held, .taken = 0, .put = 0, .dropped = 0, .peer = .{}, .observed = null };
    engine_support.engine_config.resumes = .{ .context = &test_resumes, .vtable = &test_vtable };
}

/// One request answered, then the connection shut down and over.
fn finish() !void {
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    engine.shutdown(support.now_ns);
    try engine.respond(engine_support.id_of(fetch.id), .{ .status = ok, .end = true });
    try support.pump(closing_rounds);
    try testing.expectEqual(1, engine_support.ended_len);
}

test "RFC 9959 §3.2: a connection takes the set saved for its client and starts Careful Resume" {
    try start_resuming_engine(.{ .window_len = saved_window_len, .rtt_ns = saved_rtt_ns, .saved_at_ns = support.start_ns });
    defer engine_support.engine_config.resumes = null;
    try support.connect();
    try testing.expectEqual(1, test_resumes.taken);
    try testing.expect(test_resumes.peer.eql(&support.served.transport.path.address));
    // The connection holds the set it took, which only a usable set reaches.
    try testing.expectEqual(saved_window_len, support.served.transport.recovery.careful_resume.saved.window_len);
}

test "RFC 9959 §3.1: a connection that is over puts back what it observed, once" {
    try start_resuming_engine(null);
    defer engine_support.engine_config.resumes = null;
    try support.connect();
    try testing.expectEqual(.off, support.served.transport.recovery.careful_resume.phase);
    try testing.expectEqual(0, test_resumes.put);
    try finish();
    try testing.expectEqual(1, test_resumes.put);
    try testing.expectEqual(0, test_resumes.dropped);
}

test "RFC 9959 §3.5: a connection that retreated drops the saved set before it puts" {
    try start_resuming_engine(.{ .window_len = saved_window_len, .rtt_ns = saved_rtt_ns, .saved_at_ns = support.start_ns });
    defer engine_support.engine_config.resumes = null;
    try support.connect();
    support.served.transport.recovery.careful_resume.retreated = true;
    try finish();
    try testing.expectEqual(1, test_resumes.dropped);
    try testing.expectEqual(1, test_resumes.put);
}

test "decision 149: an engine with no provider resumes nothing" {
    try support.start_engine(null);
    try support.connect();
    try testing.expectEqual(.off, support.served.transport.recovery.careful_resume.phase);
}
