//! The tests of an honest TCP peer of the endpoint check (`endpoint_tcp.zig`) for what no seed of
//! the check brings: a pool that reports `close`, and one that asks for a second socket
//! (decision 120, design §8 step 21c). In every seed the endpoint closes each socket first, so
//! these tests play the endpoint by hand: an h11 response in cleartext that closes the connection
//! (RFC 9112 §9.6).
const std = @import("std");
const sim = @import("sim");
const deadline_plan = @import("../deadline_plan.zig");
const plan_module = @import("endpoint_plan.zig");
const tcp_module = @import("endpoint_tcp.zig");

const testing = std.testing;
const limits = sim.constants.endpoint;
const Peer = tcp_module.Peer;
const TcpPeer = plan_module.TcpPeer;

/// The peers the tests start their one peer in, outside any stack frame. Test-only.
var peers: tcp_module.Peers align(@alignOf(tcp_module.Peers)) = undefined;

/// The one instant every call of a test is made at.
const now_ms: u64 = 1;
const now_ns: u64 = now_ms * limits.ns_per_ms;
/// The content each request of an uploading peer carries, in octets.
const upload_len: u32 = 16;

/// A response with no content, after which the server closes the connection (RFC 9112 §9.6).
const closing_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The plan of a peer colibri's client plays over h11 in cleartext, which makes `exchanges_len`
/// exchanges. Every field the tests do not name is 0: the peer arrives at once and has no overlay.
fn plan_of(behaviour: deadline_plan.Peer, exchanges_len: u8) TcpPeer {
    var plan = std.mem.zeroes(TcpPeer);
    plan.security = .cleartext;
    plan.overlay = .none;
    plan.behaviour.protocol = .h11;
    plan.behaviour.peer = behaviour;
    plan.behaviour.exchanges_len = exchanges_len;
    plan.behaviour.upload_len = @splat(upload_len);
    plan.behaviour.piece_len = limits.to_server_len;
    return plan;
}

/// Starts the first peer on `plan`, as the run does once the endpoint accepted it.
fn start(plan: *const TcpPeer) !*Peer {
    peers.init(0);
    const peer = &peers.peers[0];
    peer.state = .waiting;
    try peers.start(0, plan, .{ .slot = 0, .generation = 1 }, now_ns, now_ms);
    return peer;
}

/// The peer writes what it owes, and the endpoint reads all of it.
fn write_all(peer: *Peer, plan: *const TcpPeer) !void {
    var wire = std.hash.Crc32.init();
    _ = try tcp_module.write(peer, plan, now_ns, now_ms, &wire);
    peer.to_server.consumed = peer.to_server.written;
}

/// The endpoint writes `octets` into the peer's socket.
fn answer(peer: *Peer, octets: []const u8) void {
    const stream = &peer.to_client;
    @memcpy(stream.free()[0..octets.len], octets);
    stream.written += octets.len;
}

test "decision 120: a peer closes its socket once its pool reported close, and no sooner" {
    const plan = plan_of(.honest, 1);
    const peer = try start(&plan);
    // In cleartext the pool handed its connection the exchange at the start, so the first write
    // carries the request.
    try write_all(peer, &plan);
    try testing.expect(std.mem.startsWith(u8, peer.to_server.octets[0..peer.to_server.written], "GET / HTTP/1.1\r\n"));
    // The endpoint read every octet, and the pool has reported no `close`.
    try testing.expect(!tcp_module.closes(peer, &plan, now_ms));
    answer(peer, closing_response);
    try testing.expect(try tcp_module.read(peer, &plan, now_ns, now_ms));
    try testing.expectEqual(1, peer.exchanges_done);
    try testing.expectEqual(.response, peer.responses[0].outcome);
    // RFC 9112 §9.6: the server closes, so the connection is over, and the pool says so.
    try testing.expect(tcp_module.closes(peer, &plan, now_ms));
    // The peer waits for the endpoint to read what it wrote.
    peer.to_server.consumed -= 1;
    try testing.expect(!tcp_module.closes(peer, &plan, now_ms));
}

test "decision 120: a peer opens no second socket, and the exchange that waited for one ends refused" {
    // An uploading peer makes its exchanges one at a time, so its second one starts once the
    // connection is over, and the pool asks for a socket to carry it.
    const plan = plan_of(.upload, 2);
    const peer = try start(&plan);
    try write_all(peer, &plan);
    try testing.expect(std.mem.startsWith(u8, peer.to_server.octets[0..peer.to_server.written], "POST / HTTP/1.1\r\n"));
    const written = peer.to_server.written;
    answer(peer, closing_response);
    try testing.expect(try tcp_module.read(peer, &plan, now_ns, now_ms));
    try testing.expectEqual(1, peer.exchanges_done);
    try testing.expectEqual(2, peer.exchanges_requested);
    // RFC 9113 §8.7: no server processed the request, so it ends refused.
    try testing.expectEqual(.refused, peer.responses[1].outcome);
    // The pool reported the first connection's close before it asked for a second socket.
    try testing.expect(peer.close_reported);
    // The peer started no second connection, so it writes nothing more into its one socket.
    try write_all(peer, &plan);
    try testing.expectEqual(written, peer.to_server.written);
    try testing.expectEqual(.closed, peer.client.phase(0));
}
