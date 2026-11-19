//! The tests of decision 167: a TCP connection over TLS takes its TLS session from the buffer the
//! program passes in `Config.tls_buffer`, a cleartext connection takes none, and a slot gives its
//! session back, wiped, when the engine releases it.
const std = @import("std");
const support = @import("engine_tcp_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const engine_module = @import("engine.zig");

const testing = std.testing;
const engine = &support.engine;

test "decision 167: a connection over TLS holds a session of the buffer, and a cleartext one none" {
    try support.start(support.identity(), .{});
    const cleartext = engine.accept(.{ .tls = false }, support.now_ns).?;
    try testing.expectEqual(null, engine.tcp[cleartext.slot].tls_session);
    const sealed = engine.accept(.{}, support.now_ns).?;
    const session = engine.tcp[sealed.slot].tls_session.?;
    const buffer = support.config.tls_buffer;
    try testing.expect(@intFromPtr(session) >= @intFromPtr(buffer.ptr));
    try testing.expect(@intFromPtr(session) + @sizeOf(@TypeOf(session.*)) <= @intFromPtr(buffer.ptr) + buffer.len);
}

test "decision 167: accept over TLS returns null while each session is in use, and not in cleartext" {
    try support.start_held(support.identity(), .{}, 1);
    const sealed = engine.accept(.{}, support.now_ns).?;
    // A slot is free, but no session is.
    try testing.expectEqual(null, engine.accept(.{}, support.now_ns));
    const cleartext = engine.accept(.{ .tls = false }, support.now_ns).?;
    try testing.expectEqual(null, engine.tcp[cleartext.slot].tls_session);
    // The connection over TLS ends, and its slot gives the session back.
    engine.transport_closed(sealed);
    support.collect();
    try testing.expectEqual(sealed, support.nth(.ended, 0).?.connection);
    engine.transport_closed(cleartext);
    support.collect();
    const again = engine.accept(.{}, support.now_ns).?;
    try testing.expect(engine.tcp[again.slot].tls_session != null);
}

test "decision 167: a socket over TLS that finds every slot in use leaves its session free" {
    try support.start(support.identity(), .{});
    var cleartext: [support.tcp_slots]@TypeOf(engine.accept(.{}, support.now_ns).?) = undefined;
    for (&cleartext) |*handle| handle.* = engine.accept(.{ .tls = false }, support.now_ns).?;
    // Every slot is in use, and every session is free.
    for (0..support.tcp_slots) |_| try testing.expectEqual(null, engine.accept(.{}, support.now_ns));
    for (cleartext) |handle| engine.transport_closed(handle);
    support.collect();
    // Each slot takes a session over TLS: none was lost.
    for (0..support.tcp_slots) |_| try testing.expect(engine.accept(.{}, support.now_ns) != null);
}

test "decision 167: a session goes back wiped, and an engine with no buffer serves cleartext alone" {
    try support.start_held(support.identity(), .{}, 1);
    const sealed = engine.accept(.{}, support.now_ns).?;
    try support.start_client(&tcp_support.protocols_both);
    try testing.expect(try support.handshake(sealed));
    const session = engine.tcp[sealed.slot].tls_session.?;
    try testing.expectEqual(.connected, session.server.session.state());
    // The program closes the socket after the peer left. The slot's release wipes the session
    // before another connection can take it.
    engine.transport_closed(sealed);
    support.collect();
    try testing.expectEqual(sealed, support.nth(.ended, 0).?.connection);
    try testing.expectEqual(.closed, session.server.session.state());
    // With an identity and no buffer, a socket over TLS starts no connection, and one in cleartext
    // does: the identity serves QUIC alone.
    try support.start_held(support.identity(), .{}, 0);
    try testing.expectEqual(null, engine.accept(.{}, support.now_ns));
    try testing.expect(engine.accept(.{ .tls = false }, support.now_ns) != null);
}

test "decision 167: Config's one call sizes its buffer" {
    try @import("core").public_names.expect(engine_module.Config, &.{"tls_buffer_len"});
}
