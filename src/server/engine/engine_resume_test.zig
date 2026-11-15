//! The tests of a server's resume provider (`Config.resumes`, RFC 9959, decision 149, design §8
//! step 35d): a connection takes the set saved for its client when it starts, and hands back
//! what it observed, after a deletion when it retreated, when it ends.
const std = @import("std");
const quic = @import("quic");
const http = @import("http");
const support = @import("../quic/quic_test_support.zig");

const testing = std.testing;
const engine_support = support.engine_support;
const engine = &engine_support.engine;
const ok: http.Status = .ok;
/// RFC 9000 §10.2: the closing state lasts three PTOs, which this many rounds pass.
const closing_rounds = support.rounds_default * closing_rounds_factor;
const closing_rounds_factor = 8;

/// A provider that holds one set, and what it was asked. Test-only.
const TestResumes = struct {
    held: ?quic.ResumeState,
    taken: u32,
    put: u32,
    dropped: u32,
    /// The addresses that `take`, `put` and `drop` named last.
    peer: quic.PeerAddress,
    put_peer: quic.PeerAddress,
    dropped_peer: quic.PeerAddress,
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
    resumes.put += 1;
    resumes.put_peer = peer;
    resumes.observed = observed;
}

fn drop(context: *anyopaque, peer: quic.PeerAddress) void {
    const resumes: *TestResumes = @ptrCast(@alignCast(context));
    // §3.5's deletion comes before the connection's `put`.
    std.debug.assert(resumes.put == 0);
    resumes.dropped += 1;
    resumes.dropped_peer = peer;
}

/// A set for any client, saved at the start of the test's clock.
const saved_window_len: u64 = 400_000;
const saved_rtt_ns: u64 = 20_000_000;

fn start_resuming_engine(held: ?quic.ResumeState) !void {
    try support.start_engine(null);
    test_resumes = .{ .held = held, .taken = 0, .put = 0, .dropped = 0, .peer = .{}, .put_peer = .{}, .dropped_peer = .{}, .observed = null };
    engine_support.engine_config.resumes = .{ .context = &test_resumes, .vtable = &test_vtable };
    // The engine copies its configuration at `init` (decision 158 ruling 2).
    try engine_support.restart();
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
    try testing.expect(test_resumes.put_peer.eql(&test_resumes.peer));
    try testing.expectEqual(0, test_resumes.dropped);
}

test "RFC 9959 §3.5: a connection that retreated drops the saved set before it puts" {
    try start_resuming_engine(.{ .window_len = saved_window_len, .rtt_ns = saved_rtt_ns, .saved_at_ns = support.start_ns });
    defer engine_support.engine_config.resumes = null;
    try support.connect();
    support.served.transport.recovery.careful_resume.retreated = true;
    try finish();
    try testing.expectEqual(1, test_resumes.dropped);
    try testing.expect(test_resumes.dropped_peer.eql(&test_resumes.peer));
    try testing.expectEqual(1, test_resumes.put);
}

test "decision 149: an engine with no provider resumes nothing" {
    try support.start_engine(null);
    try support.connect();
    try testing.expectEqual(.off, support.served.transport.recovery.careful_resume.phase);
}

/// A window that RFC 9959 §3.1 saves: four initial windows and more, past slow start.
const grown_window_len: u64 = 200_000;

/// An engine with a provider whose connections run CUBIC, whose saved window is the congestion
/// window, so a test sets what the connection observes.
fn start_cubic_engine() !void {
    try start_resuming_engine(null);
    engine_support.engine_config.congestion_controller = .cubic;
    try engine_support.restart();
}

/// The connection's window grows to `grown_window_len`, then the connection answers `fetch`,
/// shuts down and is over.
fn end_grown(fetch: *const support.Fetch) !void {
    const congestion = &support.served.transport.recovery.congestion;
    congestion.window = grown_window_len;
    congestion.slow_start_threshold = grown_window_len;
    engine.shutdown(support.now_ns);
    try engine.respond(engine_support.id_of(fetch.id), .{ .status = ok, .end = true });
    try support.pump(closing_rounds);
    try testing.expectEqual(1, engine_support.ended_len);
}

test "RFC 9959 §3.2: a client that moved its port gets put and drop at the address that take got" {
    try start_cubic_engine();
    defer engine_support.engine_config.resumes = null;
    try support.connect();
    const started = support.client_address();
    support.client_port_now = support.client_port + 1;
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    try testing.expectEqual(support.client_port_now, support.served.transport.path.address.port);
    support.served.transport.recovery.careful_resume.retreated = true;
    try end_grown(fetch);
    try testing.expectEqual(1, test_resumes.put);
    try testing.expect(test_resumes.put_peer.eql(&started));
    try testing.expect(test_resumes.dropped_peer.eql(&started));
    // RFC 9959 §3.1: the path goes to the same host, so the connection saves what it observed.
    const observed = test_resumes.observed orelse return error.TestExpectedSet;
    try testing.expectEqual(grown_window_len, observed.window_len);
}

test "RFC 9959 §3.1: a client that moved to another host saves no set for the host it started on" {
    try start_cubic_engine();
    defer engine_support.engine_config.resumes = null;
    try support.connect();
    const started = support.client_address();
    support.client_octets_now[support.client_octets_now.len - 1] += 1;
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    try testing.expect(!support.served.transport.path.address.same_host(&started));
    try end_grown(fetch);
    try testing.expectEqual(1, test_resumes.put);
    try testing.expect(test_resumes.put_peer.eql(&started));
    try testing.expectEqual(null, test_resumes.observed);
}
