//! What the tests of the endpoint's TCP slots share (`endpoint_held_tcp.zig`, decision 119): an
//! endpoint with two TCP slots and one QUIC slot, the events it reported, and what each TCP
//! connection sent, which a program writes to its socket. The fixture answers each `send` with
//! `send_stream` and notes each `close`, as a program's loop does. Over TLS, `connection_test_support`'s
//! client runs the handshake and seals the requests. Test-only.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const event = @import("../event.zig");
const endpoint_module = @import("endpoint.zig");
const versions_module = @import("../versions.zig");
const support = @import("../connection/connection_test_support.zig");

const Event = event.Event;
const ConnectionHandle = event.ConnectionHandle;

/// Two TCP slots and one QUIC slot. Test-only.
pub const TcpEndpoint = endpoint_module.EndpointOf(.{ .tcp_connections = tcp_slots, .quic_connections = 1 });
pub const tcp_slots: usize = 2;
pub var endpoint: TcpEndpoint align(@alignOf(TcpEndpoint)) = undefined;
pub var config: endpoint_module.Config align(@alignOf(endpoint_module.Config)) = undefined;

/// What the endpoint reported, oldest first.
pub const Seen = struct {
    kind: std.meta.Tag(Event),
    connection: ConnectionHandle = .{ .slot = 0, .generation = 0 },
    number: u64 = 0,
    user_data: usize = 0,
    end: bool = false,
    reason: ?event.CancelReason = null,
    failed: bool = false,
};
pub const seen_max: usize = 256;
pub var seen: [seen_max]Seen align(@alignOf(Seen)) = undefined;
pub var seen_len: usize = 0;

/// What each TCP slot's connection sent, and how much of it the TLS client has read.
pub var sent: [tcp_slots][sent_len_max]u8 = undefined;
pub var sent_len: [tcp_slots]usize = @splat(0);
pub var client_read: [tcp_slots]usize = @splat(0);
const sent_len_max: usize = 262_144;
/// Whether the endpoint reported each slot's `close`.
pub var closed: [tcp_slots]bool = @splat(false);
/// Whether the fixture answers a `send` with `send_stream` at once, as a program whose socket
/// takes every octet does. A test that clears it calls `flush` itself.
pub var flushing: bool = true;
/// Whether the TLS client opened an alert, such as the connection's close_notify.
pub var client_saw_alert: bool = false;
/// Where a test's octets wait for the endpoint, which may open records in place.
var input: [support.input_len]u8 = undefined;

pub const now_ns = support.now_ns;
const rounds_max: usize = 64;

/// The server's identity, which names no protocol. Test-only.
pub fn identity() tls.Server {
    return .{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .cpu = support.cpu,
    };
}

/// Starts the endpoint with `with` as its identity, or none, serving `versions`. Test-only.
pub fn start(with: ?tls.Server, versions: versions_module.Versions) !void {
    config = .{ .tls = with, .versions = versions };
    seen_len = 0;
    sent_len = @splat(0);
    client_read = @splat(0);
    closed = @splat(false);
    flushing = true;
    client_saw_alert = false;
    try endpoint.init(&config, support.stream.random(), support.now_seconds, now_ns);
}

/// Passes `octets` as what the socket of `handle` read, again until the endpoint consumed them or
/// stopped consuming, keeping each event and answering each `send`. Returns the octets left.
pub fn give(handle: ConnectionHandle, octets: []const u8) usize {
    @memcpy(input[0..octets.len], octets);
    var rest = input[0..octets.len];
    // Bounded: each pass consumes octets or reports an event, or ends the loop.
    for (0..rounds_max) |_| {
        const received = endpoint.receive(.{ .stream = .{ .connection = handle, .octets = rest } }, now_ns);
        check_deadline();
        rest = rest[received.consumed..];
        if (received.event) |reported| note(reported);
        collect();
        if (rest.len == 0 or (received.consumed == 0 and received.event == null)) break;
    }
    return rest.len;
}

/// Keeps every event the endpoint reports until it reports none.
pub fn collect() void {
    // Bounded: the log holds `seen_max` events.
    for (0..seen_max) |_| {
        const reported = endpoint.receive(.none, now_ns).event;
        check_deadline();
        note(reported orelse return);
    }
}

/// INV-31: the endpoint's deadline is the soonest its slots hold, each read from its own
/// connection, after any call the fixture makes.
pub fn check_deadline() void {
    var soonest: ?u64 = null;
    for (0..endpoint.live.len) |slot| {
        const at_ns = endpoint.held.deadline_of(@intCast(slot)) orelse continue;
        soonest = @min(soonest orelse at_ns, at_ns);
    }
    assert(std.meta.eql(soonest, endpoint.deadline_ns()));
}

/// Keeps `reported`, answering a `send` with `send_stream` until a call leaves room, and noting a
/// `close`.
fn note(reported: Event) void {
    assert(seen_len < seen.len);
    const entry = &seen[seen_len];
    entry.* = .{ .kind = reported };
    seen_len += 1;
    switch (reported) {
        .request => |request| {
            entry.connection = request.id.connection;
            entry.number = request.id.number;
            entry.end = request.end;
        },
        .body => |body| entry.* = .{ .kind = reported, .connection = body.id.connection, .number = body.id.number, .user_data = body.user_data, .end = body.end },
        .trailers => |trailers| entry.* = .{ .kind = reported, .connection = trailers.id.connection, .number = trailers.id.number, .user_data = trailers.user_data },
        .cancelled => |cancelled| entry.* = .{ .kind = reported, .connection = cancelled.id.connection, .number = cancelled.id.number, .user_data = cancelled.user_data, .reason = cancelled.reason },
        .done => |done| entry.* = .{ .kind = reported, .connection = done.id.connection, .number = done.id.number, .user_data = done.user_data },
        .writable => |writable| entry.* = .{ .kind = reported, .connection = writable.id.connection, .number = writable.id.number, .user_data = writable.user_data },
        .send => |handle| {
            entry.connection = handle;
            if (flushing) flush(handle);
        },
        .close => |handle| {
            entry.connection = handle;
            closed[handle.slot] = true;
        },
        .ended => |over| entry.* = .{ .kind = reported, .connection = over.connection, .failed = over.failed },
        .closed => {},
    }
}

/// Writes what the connection `handle` names owes into its slot's buffer, as a program writes to
/// the socket, until a call leaves room.
pub fn flush(handle: ConnectionHandle) void {
    const slot = handle.slot;
    // Bounded: each pass fills the room it had, or ends the loop.
    for (0..rounds_max) |_| {
        const room = sent[slot][sent_len[slot]..];
        const written = endpoint.send_stream(handle, room, now_ns);
        sent_len[slot] += written;
        if (written < room.len) return;
    }
}

/// The `n`th event of `kind` the endpoint reported, or null.
pub fn nth(kind: std.meta.Tag(Event), n: usize) ?*const Seen {
    var count: usize = 0;
    for (seen[0..seen_len]) |*entry| {
        if (entry.kind != kind) continue;
        if (count == n) return entry;
        count += 1;
    }
    return null;
}

/// Where the first event of `kind` is among those the endpoint reported, or null.
pub fn index_of(kind: std.meta.Tag(Event)) ?usize {
    for (seen[0..seen_len], 0..) |entry, index| {
        if (entry.kind == kind) return index;
    }
    return null;
}

/// What the connection in `slot` sent, as the transport carried it.
pub fn sent_of(slot: u32) []const u8 {
    return sent[slot][0..sent_len[slot]];
}

/// The id of request `number` on the connection `handle` names.
pub fn id_of(handle: ConnectionHandle, number: u64) event.Id {
    return .{ .connection = handle, .number = number };
}

/// Starts `connection_test_support`'s TLS client, which offers `protocols`. Test-only.
pub fn start_client(protocols: []const []const u8) !void {
    try support.client_config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &support.anchors, .server_name = "localhost" } },
        .alpn = protocols,
        .cpu = support.cpu,
    });
    try support.client.start(&support.client_config, support.stream.random(), support.now_seconds, null);
}

/// Runs the TLS client's handshake against the connection `handle` names, until the client has
/// completed it. Returns false when the endpoint closed the connection first.
pub fn handshake(handle: ConnectionHandle) !bool {
    var flight: [support.input_len]u8 = undefined;
    // Bounded: a handshake takes a few flights each way.
    for (0..rounds_max) |_| {
        if (support.client.state.completed) return true;
        if (closed[handle.slot]) return false;
        const slot = handle.slot;
        const progress = try support.client.handshake(sent[slot][client_read[slot]..sent_len[slot]], &flight);
        client_read[slot] += progress.consumed;
        if (progress.written > 0) _ = give(handle, flight[0..progress.written]);
    }
    return error.TestUnexpectedResult;
}

/// Seals `plaintext` as the TLS client's records and passes them to the connection `handle` names.
pub fn give_sealed(handle: ConnectionHandle, plaintext: []const u8) !usize {
    var records: [support.input_len]u8 = undefined;
    const provider = support.client.provider();
    var sealed_len: usize = 0;
    var taken: usize = 0;
    // Bounded: each record takes at least one octet of plaintext.
    for (0..plaintext.len) |_| {
        if (taken == plaintext.len) break;
        const sealed = try provider.vtable.encrypt_record(provider.context, plaintext[taken..], records[sealed_len..]);
        taken += sealed.consumed;
        sealed_len += sealed.written;
    }
    return give(handle, records[0..sealed_len]);
}

/// Opens every whole record the connection in `slot` sent that the TLS client has not read, and
/// returns their plaintext.
pub fn open_sent(slot: u32) ![]const u8 {
    const provider = support.client.provider();
    var gathered: usize = 0;
    // Bounded: each record the client opens takes at least its header.
    for (0..sent_len_max) |_| {
        const record = provider.vtable.decrypt_record(provider.context, sent[slot][client_read[slot]..sent_len[slot]], support.opened[gathered..]) catch |failure| {
            // The client reads a close_notify as the end of the data, and nothing after it.
            if (failure == error.TlsFailed) break;
            return failure;
        };
        if (record.content == .incomplete) break;
        client_read[slot] += record.consumed;
        gathered += record.plaintext_len;
        if (record.content == .alert) {
            client_saw_alert = true;
            break;
        }
    }
    return support.opened[0..gathered];
}
