//! The caller's answer to each `open` event of the client trace run, split from
//! `client_trace_world.zig` because a hand-written source file stays at or under 500 lines
//! (CLAUDE.md). The caller starts a QUIC connection over a fresh flow to a fresh server, and a TCP
//! connection over a fresh link. When the plan's TCP server refuses each connect (design §8 step
//! 43), the caller's connect fails, and it tells the pool with `transport_closed`.
const client = @import("client");
const world_module = @import("client_trace_world.zig");
const identity = @import("client_trace_identity.zig");

const World = world_module.World;
const tls_source = world_module.tls_source;

/// Starts the QUIC connection the pool asked for, over a fresh flow to a fresh server.
pub fn open_quic(world: *World, connection: client.ConnectionHandle) void {
    world.quic_connection = connection;
    world.network.init(world.random.next(), world.schedule());
    world.quic_server.reset(world.pool.quic_link.opens);
    // The pool draws the grease value, then the two IDs, then the session's draws, from this one
    // source (decision 120). A start chapulin refuses is the pool's to report.
    world.pool.start_quic(tls_source(&world.tls_random), identity.now_seconds, world.now_ns, null) catch {};
}

/// Starts the TCP connection the pool asked for, over a fresh link, or fails its connect when
/// the plan's TCP server refuses it.
pub fn open_tcp(world: *World, connection: client.ConnectionHandle) void {
    world.tcp_connection = connection;
    world.to_server.clear();
    world.to_client.clear();
    if (world.plan.tcp == .refused) {
        // The connect fails before a TLS session starts, so the pool hears of it as the end of
        // the transport, as a program tells it of a refused connect.
        world.tcp_server.stop();
        world.pool.transport_closed(connection);
        return;
    }
    world.tcp_server.reset(world.pool.tcp_links[0].opens, tls_source(&world.tls_random)) catch {};
    world.pool.start_tcp(connection, tls_source(&world.tls_random), identity.now_seconds, null) catch {};
}
