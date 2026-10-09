//! The QUIC connections of the server's endpoint (`endpoint.zig`), and what the endpoint does with
//! each datagram: the routing, the start of a connection from a client's first Initial in a free
//! QUIC slot, and the Version Negotiation and Retry packets it owes (decision 103). It holds slices
//! of the arrays `EndpointOf` places, so it takes no size of its own. Split out of `endpoint.zig`
//! for length.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const internal = @import("../quic/quic_connection_internal.zig");
const endpoint_stateless = @import("endpoint_stateless.zig");
const endpoint_slots = @import("endpoint_slots.zig");
const endpoint_config = @import("endpoint_config.zig");

const QuicConnection = quic_connection.QuicConnection;
const PeerAddress = quic_connection.PeerAddress;
const ReceiveStorage = quic_connection.ReceiveStorage;
const Sent = quic_connection.Sent;
const Ecn = quic.connection_receive.Datagram.Ecn;

/// The caller's source of qlog logs, a provider the endpoint asks once for each connection it
/// starts (decision 102 as amended). colibri writes the connection's QUIC and h3 events into the
/// log the caller returns. The caller takes the records after each call it makes, and gets the
/// log back through `close` once the connection is over.
pub const LogProvider = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// A log whose header the caller wrote, for the connection whose client first addressed
        /// `original_destination` (RFC 9000 §7.3), which main schema §12.1 names a file after; or
        /// null for a connection the caller does not log.
        open: *const fn (context: *anyopaque, original_destination: []const u8, now_ns: u64) ?*quic.qlog.Log,
        /// Hands `log` back once its connection is over. Nothing writes into it again, and the
        /// caller takes its last records.
        close: *const fn (context: *anyopaque, log: *quic.qlog.Log) void,
    };

    pub fn open(provider: LogProvider, original_destination: []const u8, now_ns: u64) ?*quic.qlog.Log {
        return provider.vtable.open(provider.context, original_destination, now_ns);
    }

    pub fn close(provider: LogProvider, log: *quic.qlog.Log) void {
        provider.vtable.close(provider.context, log);
    }
};

pub const Connections = struct {
    config: *const endpoint_config.Config,
    /// What each QUIC connection borrows, which `endpoint_config.build` filled.
    quic: *const quic_connection.Config,
    random: tls.Random,
    /// Unix seconds at `base_ns`, from which each connection's tickets count, or 0 for none.
    base_seconds: u64,
    base_ns: u64,
    /// Each QUIC connection and its receive pool, at the index its slot has among the QUIC slots,
    /// and the slots, which say which run.
    connections: []QuicConnection,
    pools: []const ReceiveStorage,
    slots: *endpoint_slots.Slots,
    replies: Replies,

    /// Holds no connection. Every value the endpoint draws comes from `random`.
    pub fn init(held: *Connections, config: *const endpoint_config.Config, quic_config: *const quic_connection.Config, connections: []QuicConnection, pools: []const ReceiveStorage, slots: *endpoint_slots.Slots, random: tls.Random, now_seconds: u64, now_ns: u64) void {
        assert(connections.len == pools.len and slots.tcp_count + connections.len == slots.live.len);
        held.* = .{
            .config = config,
            .quic = quic_config,
            .random = random,
            .base_seconds = now_seconds,
            .base_ns = now_ns,
            .connections = connections,
            .pools = pools,
            .slots = slots,
            .replies = .{},
        };
    }

    /// The QUIC connection slot `slot` holds.
    pub fn at(held: *Connections, slot: u32) *QuicConnection {
        assert(held.slots.kind_of(slot) == .quic);
        return &held.connections[slot - held.slots.tcp_count];
    }

    /// Takes one datagram the socket read from `from`, which the suite opens in place, and
    /// returns the slot of the connection that took it, or null when none did. With `accepting`
    /// false, a client's first Initial starts no connection.
    pub fn receive(held: *Connections, datagram: []u8, ecn: Ecn, from: PeerAddress, now_ns: u64, accepting: bool) ?u32 {
        if (endpoint_stateless.destination_of(datagram)) |dcid| {
            if (held.slot_for(dcid)) |slot| {
                internal.take(held.at(slot), datagram, ecn, from, now_ns);
                return slot;
            }
        }
        if (held.answer_version(datagram, from)) return null;
        if (!accepting) return null;
        const long = endpoint_stateless.first_initial(datagram) orelse return null;
        // RFC 9000 §14.1: "A server MUST discard an Initial packet that is carried in a UDP
        // datagram with a payload that is smaller than the smallest allowed maximum datagram
        // size of 1200 bytes."
        if (datagram.len < quic.constants.datagram_len_min) return null;
        // RFC 9000 §7.2: a client's first Destination Connection ID "MUST be at least 8 bytes
        // in length". The Initial keys come from it, so a shorter one starts nothing and owes no
        // Retry (INV-24: it never reaches the start's assertion).
        if (long.dcid.len < quic.constants.initial_destination_len_min) return null;
        const slot = held.accept(long, from, now_ns) orelse return null;
        internal.take(held.at(slot), datagram, ecn, from, now_ns);
        return slot;
    }

    /// The slot of the running connection `dcid` addresses (RFC 9000 §5.2), or null.
    fn slot_for(held: *Connections, dcid: []const u8) ?u32 {
        for (held.connections, 0..) |*connection, index| {
            const slot: u32 = @intCast(held.slots.tcp_count + index);
            if (held.slots.live[slot] and internal.addressed_by(connection, dcid)) return slot;
        }
        return null;
    }

    /// Owes a Version Negotiation packet for a datagram that asks for another version, and
    /// says whether it did.
    fn answer_version(held: *Connections, datagram: []const u8, from: PeerAddress) bool {
        var answer: [quic.constants.datagram_len_min]u8 = undefined;
        const written = endpoint_stateless.version_negotiation(datagram, &answer) orelse return false;
        held.replies.push(written, from);
        return true;
    }

    /// Starts a connection for a client's first Initial, or with Retry configured first
    /// checks the Initial's token (RFC 9000 §8.1.2).
    fn accept(held: *Connections, long: quic.packet.header.Long, from: PeerAddress, now_ns: u64) ?u32 {
        const retry = held.config.retry orelse return held.start(long.version, long.dcid, long.scid, null, from, now_ns);
        var address_storage: [endpoint_stateless.token_address_len_max]u8 = undefined;
        const address = endpoint_stateless.token_address(from, &address_storage);
        return switch (quic.connection_retry.verify_token(retry.suite(), long.version, address, long.token, long.dcid, now_ns)) {
            .absent => blk: {
                held.owe_retry(retry, long, address, from, now_ns);
                break :blk null;
            },
            // RFC 9000 §8.1.2: a server "can discard such a packet and allow the client to
            // time out", which needs no connection it would refuse.
            .invalid => null,
            .validated => |ids| held.start(long.version, ids.original_destination_slice(), long.scid, ids.retry_source_slice(), from, now_ns),
        };
    }

    /// Owes a Retry for a client's first Initial (RFC 9000 §17.2.5.1), from a Source
    /// Connection ID drawn at random, which the client addresses next.
    fn owe_retry(held: *Connections, retry: *const tls.quic.Retry, long: quic.packet.header.Long, address: []const u8, from: PeerAddress, now_ns: u64) void {
        var source: [constants.quic_id_len]u8 = undefined;
        held.random.bytes(&source);
        var pseudo: [quic.constants.retry_pseudo_packet_len_max]u8 = undefined;
        var packet: [quic.constants.datagram_len_min]u8 = undefined;
        const answered = quic.connection_retry.answer(retry.suite(), .{
            .version = long.version,
            .client_source = long.scid,
            .original_destination = long.dcid,
            .server_source = &source,
            .address = address,
            .now_ns = now_ns,
        }, &pseudo, &packet);
        switch (answered) {
            .written => |len| held.replies.push(packet[0..len], from),
            // RFC 9000 §8.1.2: with no Retry to send, the Initial goes unanswered, and the
            // client sends it again.
            .refused => {},
        }
    }

    /// A connection in a free slot, from values the caller's source draws. With every slot
    /// in use the Initial goes unanswered: RFC 9000 §5.2.2 lets a server drop what it will
    /// not serve, and the client sends it again.
    fn start(held: *Connections, version: quic.packet.header.Version, original_destination: []const u8, peer_source: []const u8, retry_source: ?[]const u8, from: PeerAddress, now_ns: u64) ?u32 {
        const handle = held.slots.take(.quic) orelse return null;
        var how: quic_connection.Start = .{
            .version = version,
            .local_id = undefined,
            .original_destination = original_destination,
            .peer_source = peer_source,
            .retry_source = retry_source,
            .grease = held.random.int(u64),
            .peer = from,
        };
        // RFC 9000 §7.2: the server chooses its own connection ID, unpredictable (§5.1).
        held.random.bytes(&how.local_id);
        const connection = held.at(handle.slot);
        const pool = held.pools[handle.slot - held.slots.tcp_count];
        internal.start(connection, held.quic, pool, how, held.random, held.seconds_at(now_ns), now_ns) catch {
            held.slots.release(handle);
            return null;
        };
        // Decision 102 as amended: a log only for a connection that started, so each log the
        // provider gives comes back through `close`.
        if (held.config.logs) |logs| {
            if (logs.open(original_destination, now_ns)) |log| internal.attach_log(connection, log, now_ns);
        }
        return handle.slot;
    }

    /// Hands the log of a connection that is over back to the caller.
    pub fn close_log(held: *const Connections, connection: *QuicConnection) void {
        const logs = held.config.logs orelse return;
        const log = connection.transport.qlog.log orelse return;
        logs.close(log);
    }

    /// The Unix seconds a connection starting at `now_ns` issues its tickets at.
    pub fn seconds_at(held: *const Connections, now_ns: u64) u64 {
        if (held.base_seconds == 0) return 0;
        return held.base_seconds + (now_ns -| held.base_ns) / constants.nanoseconds_per_second;
    }
};

/// The Version Negotiation and Retry packets the endpoint owes, oldest first, with where each
/// goes. A reply that finds the queue full is dropped, and its client sends again.
pub const Replies = struct {
    packets: [constants.quic_replies_max][quic.constants.datagram_len_min]u8 = undefined,
    lens: [constants.quic_replies_max]usize = undefined,
    to: [constants.quic_replies_max]PeerAddress = undefined,
    first: usize = 0,
    len: usize = 0,

    pub fn push(replies: *Replies, packet: []const u8, to: PeerAddress) void {
        assert(packet.len <= quic.constants.datagram_len_min);
        if (replies.len == replies.packets.len) return;
        const index = (replies.first + replies.len) % replies.packets.len;
        @memcpy(replies.packets[index][0..packet.len], packet);
        replies.lens[index] = packet.len;
        replies.to[index] = to;
        replies.len += 1;
    }

    /// Copies the oldest reply into `output`, or returns null when none is owed.
    pub fn take(replies: *Replies, output: []u8) ?Sent {
        if (replies.len == 0) return null;
        const index = replies.first;
        const len = replies.lens[index];
        if (output.len < len) return null;
        @memcpy(output[0..len], replies.packets[index][0..len]);
        replies.first = (replies.first + 1) % replies.packets.len;
        replies.len -= 1;
        return .{ .octets = output[0..len], .ecn = .not_ect, .to = replies.to[index] };
    }
};
