//! What the client trace run's pool sends, split from `client_trace_world.zig` because a
//! hand-written source file stays at or under 500 lines (CLAUDE.md). Each datagram goes to the
//! network, and each TCP segment to the link. Both go into the run's wire checksum, which the
//! census pins, so a change to a byte the pool sends changes it (decision 175).
const sim = @import("sim");
const world_module = @import("client_trace_world.zig");

const limits = sim.constants.client_trace;
const World = world_module.World;

/// Hands the network each datagram the pool owes and the link the TCP bytes it owes, and adds
/// both to `world.wire`. Returns whether anything moved.
pub fn pool_sends(world: *World) world_module.Error!bool {
    var moved = false;
    for (0..limits.datagrams_per_round_max) |_| {
        const sent = world.pool.send_datagram(&world.datagram, world.now_ns) orelse break;
        world.wire.update(sent.bytes);
        _ = world.network.send(world.now_ns, .client, sent.bytes, .not_ect);
        moved = true;
    }
    const written = world.pool.send_stream(world.tcp_connection, &world.segment, world.now_ns);
    if (written > 0) {
        world.wire.update(world.segment[0..written]);
        try world.to_server.push(world.segment[0..written], world.now_ns + limits.tcp_delay_ns);
        moved = true;
    }
    return moved;
}
