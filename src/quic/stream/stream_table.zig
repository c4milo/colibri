//! The streams of one connection, against their identifiers (RFC 9000 §2.1, §3, §4.6). Part of
//! design §8 step 9c.
//!
//! Each of the four stream types has its own space of identifiers and its own watermark, which
//! is what `core.Pool` gives (decision 14). The watermark is not bookkeeping: RFC 9000 §3.2
//! says that before a stream is created, all streams of the same type with lower-numbered
//! identifiers must be created, so a frame naming stream 40 of its type creates every lower one
//! as well. That rule is why a peer can open many streams with one frame, and why the limit
//! below is checked before any of them exist.
//!
//! A stream holds both halves. A unidirectional stream has only one live half, and which one
//! depends on who opened it and which endpoint is asking, so the accessors assert rather than
//! guess: reaching for the half this endpoint does not have is a defect and not a peer's doing.
//!
//! The table's capacity bounds what the peer may open, and colibri never advertises a stream
//! limit larger than it. §3.2's implicit creation means an advertised limit is a promise to
//! hold that many streams at once, so a limit past the table would be a promise the table
//! cannot keep.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const flow = @import("../flow.zig");
const frame_latest = @import("../frame/frame_latest.zig");
const stream_id = @import("stream_id.zig");
const stream_send = @import("stream_send.zig");
const stream_recv = @import("stream_recv.zig");
const stream_outgoing = @import("stream_outgoing.zig");
const stream_incoming = @import("stream_incoming.zig");
const stream_lost = @import("stream_lost.zig");

const StreamId = stream_id.StreamId;
const Initiator = stream_id.Initiator;
const Directionality = stream_id.Directionality;

/// One stream: the two state machines of RFC 9000 §3, and the flow control limits of §4.1 that
/// belong to this stream alone. The connection's own limits are the caller's.
pub const Stream = struct {
    /// The identifier, which `core.Pool` requires by this name.
    id: u64,
    sending: stream_send.Sending = stream_send.Sending.init(),
    receiving: stream_recv.Receiving = stream_recv.Receiving.init(),
    /// What this endpoint may send on the stream, against the peer's limit (§4.1).
    send_flow: flow.Sender = flow.Sender.init(0),
    /// What the peer may send on it, against this endpoint's limit (§4.1).
    receive_flow: flow.Receiver = flow.Receiver.init(1, 1),
    /// How far this endpoint's octets reach, how far they went out and how many arrived
    /// (decision 57).
    outgoing: stream_outgoing.Outgoing = .{},
    /// The octets the peer sent and the application has not read, in the connection's receive
    /// pool (decision 61).
    incoming: stream_incoming.Incoming = .{},
    /// Where this stream's new octets go against other streams': a lower value first (RFC 9000
    /// §2.3).
    priority: u8 = constants.policy.stream_priority_default,
    /// The MAX_STREAM_DATA and STREAM_DATA_BLOCKED frames most recently sent for this stream
    /// (RFC 9000 §13.3).
    max_stream_data: frame_latest.Latest = .{},
    stream_data_blocked: frame_latest.Latest = .{},
    /// The RESET_STREAM this endpoint owes or sent (RFC 9000 §19.4), and its error code, which
    /// §13.3 says "MUST NOT change when it is sent again".
    reset_stream: frame_latest.Latest = .{},
    reset_error_code: u64 = 0,
    /// The STOP_SENDING this endpoint owes or sent (RFC 9000 §19.5), and its error code.
    stop_sending: frame_latest.Latest = .{},
    stop_error_code: u64 = 0,
    /// The error code of the peer's RESET_STREAM (RFC 9000 §19.4), which the application reads:
    /// §3.2 has the reset "signaled to the application", and the code is the application's.
    peer_reset_error_code: u64 = 0,

    pub fn stream_identifier(stream: *const Stream) StreamId {
        return .{ .value = stream.id };
    }
};

/// RFC 9000 §2.1: the two low bits give the type, which is the pool's class.
fn class_of(id: u64) u32 {
    return @intCast(id & (constants.protocol.stream_id_initiator_bit | constants.protocol.stream_id_directionality_bit));
}

const Pool = core.Pool(Stream, constants.limits.streams_per_connection_max, constants.protocol.stream_types, class_of);

/// Why a stream was not opened.
pub const OpenError = error{
    /// RFC 9000 §4.6: the identifier is past the limit the other side advertised. At a peer's
    /// frame this is STREAM_LIMIT_ERROR; at this endpoint's own request it is a wait, and the
    /// caller sends STREAMS_BLOCKED (§19.14).
    StreamLimitReached,
    /// Every slot holds a live stream. The advertised limit never exceeds the table, so a peer
    /// cannot cause this; only this endpoint opening past its own table can.
    Full,
    /// RFC 9000 §2.1: this endpoint has opened its largest identifier of the type.
    IdentifiersExhausted,
};

/// RFC 9000 §20.1: the code a peer's refused identifier closes the connection with.
pub fn connection_error_code(failure: OpenError) u64 {
    return switch (failure) {
        error.StreamLimitReached => error_code.stream_limit_error,
        // Neither can be reached by a peer: the limit is never advertised past the table.
        error.Full, error.IdentifiersExhausted => error_code.internal_error,
    };
}

/// What `lookup` found.
pub const Lookup = union(enum) {
    /// The stream is open, with its record.
    live: *Stream,
    /// The identifier is at or below its type's watermark, so it was opened and has closed.
    closed,
    /// Nothing of this type has reached the identifier yet.
    unopened,
};

pub const Streams = struct {
    pool: Pool,
    /// Which endpoint this is, which decides who initiated a given identifier (§2.1).
    role: Initiator,
    /// What the peer permits this endpoint to open, by directionality (§4.6).
    local_limit: [constants.protocol.stream_directionalities]flow.Sender,
    /// What this endpoint permits the peer to open (§4.6).
    peer_limit: [constants.protocol.stream_directionalities]flow.Receiver,
    /// The next index this endpoint opens, by directionality (§2.1).
    next_index: [constants.protocol.stream_directionalities]u64,
    /// The stream octets lost in transit and owed again (§13.3), across every stream.
    lost: stream_lost.LostRanges,
    /// The MAX_STREAMS and STREAMS_BLOCKED frames most recently sent for each stream type (§13.3).
    max_streams: [constants.protocol.stream_directionalities]frame_latest.Latest,
    streams_blocked: [constants.protocol.stream_directionalities]frame_latest.Latest,
    /// Whether this endpoint tried to open a stream of each type and the peer's limit refused it
    /// since the last one it opened, which is when §4.6 asks for STREAMS_BLOCKED.
    open_refused: [constants.protocol.stream_directionalities]bool,
    /// How many streams are in "Reset Sent", waiting for their RESET_STREAM to be acknowledged
    /// (RFC 9000 §3.1). An acknowledgment looks for one only while this is above zero.
    resets_unacknowledged: u32,
    /// The table slot of the stream that last sent new octets, so streams of one priority take
    /// turns: the slot after it goes next.
    send_turn: u32,
    /// The slots whose stream may owe a MAX_STREAM_DATA frame: each stream this endpoint receives
    /// on, set when it opens and cleared when it closes, or when `data_credit_owed` finds its
    /// receiving part out of "Recv" (§13.3). The walk then passes over the rest (design §8 step
    /// 29d.10).
    may_owe_credit: std.StaticBitSet(constants.limits.streams_per_connection_max),
    /// The slots whose stream may owe new STREAM octets: each stream this endpoint sends on, set
    /// when it opens and cleared when it closes, or when the send walk finds its sending part out
    /// of "Ready" and "Send" (§3.1). The walk then passes over the rest (design §8 step 29d.16).
    may_send_new: std.StaticBitSet(constants.limits.streams_per_connection_max),

    /// `peer_limits` are the counts this endpoint advertises, which `init` caps at the table's
    /// capacity: §3.2's implicit creation makes an advertised limit a promise to hold that many
    /// streams, and the table is what can hold them.
    pub fn init(
        streams: *Streams,
        role: Initiator,
        local_limits: [constants.protocol.stream_directionalities]u64,
        peer_limits: [constants.protocol.stream_directionalities]u64,
    ) void {
        streams.pool.init();
        streams.role = role;
        streams.next_index = @splat(0);
        streams.lost.init();
        streams.max_streams = @splat(.{});
        streams.streams_blocked = @splat(.{});
        streams.open_refused = @splat(false);
        streams.resets_unacknowledged = 0;
        streams.may_owe_credit = .initEmpty();
        streams.may_send_new = .initEmpty();
        // No stream has sent, so the turn starts at the first slot.
        streams.send_turn = constants.limits.streams_per_connection_max - 1;
        for (0..constants.protocol.stream_directionalities) |index| {
            streams.local_limit[index] = flow.Sender.init(local_limits[index]);
            const capped = @min(peer_limits[index], constants.limits.streams_per_connection_max);
            // A stream count is not data, so it never grows: decision 49 tunes a data window
            // against a round trip, and §4.6's limit is bounded by the table instead. Each
            // closed stream is worth a MAX_STREAMS frame (`count_frame_limit`, decision 130).
            const count = @max(capped, 1);
            streams.peer_limit[index] = flow.Receiver.init(count, count);
        }
    }

    pub fn len(streams: *const Streams) u32 {
        return streams.pool.len();
    }

    /// The stream `id` names, or why there is none. An identifier above its type's watermark was
    /// never opened, so the pool holds no entry for it (invariant 13). That answer comes first,
    /// because it reads no entry, and every new stream gets it.
    pub fn lookup(streams: *Streams, id: StreamId) Lookup {
        if (streams.pool.is_above_watermark(id.value)) return .unopened;
        if (streams.pool.get(id.value)) |stream| return .{ .live = stream };
        return .closed;
    }

    /// Opens the next stream this endpoint initiates, of `directionality` (RFC 9000 §2.1).
    pub fn open_local(streams: *Streams, directionality: Directionality) OpenError!*Stream {
        const which = @intFromEnum(directionality);
        if (streams.local_limit[which].is_blocked()) {
            // The refusal is what STREAMS_BLOCKED reports (§19.14).
            streams.open_refused[which] = true;
            // RFC 9000 §4.6: endpoints MUST NOT exceed the limit their peer set.
            return error.StreamLimitReached;
        }
        const index = streams.next_index[which];
        // RFC 9000 §2.1: a stream ID is 62 bits, so each type's indices end.
        if (index > constants.protocol.stream_index_max) return error.IdentifiersExhausted;
        const id = StreamId.init(streams.role, directionality, index);
        const stream = streams.pool.open(id.value) catch return error.Full;
        streams.on_opened(stream);
        streams.next_index[which] = index + 1;
        streams.local_limit[which].spend(1);
        streams.open_refused[which] = false;
        return stream;
    }

    /// Opens the stream a peer's frame named, and every lower-numbered stream of its type that
    /// does not exist yet (RFC 9000 §3.2). The identifier must be one the peer initiates and one
    /// `lookup` calls `unopened`: a frame for a stream that is open names that stream, and one
    /// for a stream that has closed is judged by §3.3 against the frame's type, and neither is
    /// this call's to decide.
    pub fn open_peer(streams: *Streams, id: StreamId) OpenError!*Stream {
        assert(id.is_initiated_by(streams.role.peer()));
        assert(streams.lookup(id) == .unopened);
        const which = @intFromEnum(id.directionality());
        // The count is one past the index, because §4.6 counts streams and indices start at 0.
        streams.peer_limit[which].use(id.index() + 1, error.StreamLimitExceeded) catch {
            // RFC 9000 §4.6: an endpoint that receives a frame with a stream ID exceeding the
            // limit it advertised treats it as a connection error of STREAM_LIMIT_ERROR.
            return error.StreamLimitReached;
        };
        // RFC 9000 §3.2: every lower-numbered stream of the same type is created too, so the
        // creation order is the same at both endpoints. The limit above bounds this walk.
        var index = streams.lowest_unopened(id);
        for (0..constants.limits.streams_per_connection_max + 1) |_| {
            const next = StreamId.init(id.initiator(), id.directionality(), index);
            const stream = streams.pool.open(next.value) catch return error.Full;
            streams.on_opened(stream);
            if (index == id.index()) return stream;
            index += 1;
        }
        unreachable; // The limit is capped at the table, so the walk ends inside it.
    }

    /// Marks the slot of a stream this endpoint receives on, which may come to owe credit, and
    /// of one it sends on, which may come to owe new octets.
    fn on_opened(streams: *Streams, stream: *Stream) void {
        assert(stream.receiving.state == .recv);
        assert(stream.sending.state == .ready);
        const id = stream.stream_identifier();
        const slot = streams.pool.index_of(stream);
        if (id.is_receivable_by(streams.role)) streams.may_owe_credit.set(slot);
        if (id.is_sendable_by(streams.role)) streams.may_send_new.set(slot);
    }

    /// The first index of `id`'s type that has not been opened, which is one past the watermark
    /// or 0 when the type has none. `open_peer` opens every index from here to `id`'s.
    pub fn lowest_unopened(streams: *const Streams, id: StreamId) u64 {
        const watermark = streams.pool.watermark_of(class_of(id.value)) orelse return 0;
        return (StreamId{ .value = watermark }).index() + 1;
    }

    /// Closes a stream whose two halves have both finished (RFC 9000 §3.1, §3.2). The
    /// identifier stays at or below its watermark, so it reads as closed from now on.
    pub fn close(streams: *Streams, id: StreamId) void {
        const stream = streams.pool.get(id.value).?;
        assert(stream.sending.state.is_terminal() or !id.is_sendable_by(streams.role));
        assert(stream.receiving.state.is_terminal() or !id.is_receivable_by(streams.role));
        const slot = streams.pool.index_of(stream);
        streams.may_owe_credit.unset(slot);
        streams.may_send_new.unset(slot);
        streams.pool.close(id.value);
        // RFC 9000 §4.6: "Implementations might choose to increase limits as streams are closed,
        // to keep the number of streams available to peers roughly consistent." A closed stream
        // the peer opened is what a MAX_STREAMS frame gives back.
        if (id.is_initiated_by(streams.role.peer())) {
            streams.peer_limit[@intFromEnum(id.directionality())].consume(1);
        }
    }

    /// Counts a range the peer acknowledged toward its stream (RFC 9000 §3.1). True when that
    /// acknowledged the whole stream, every octet and the FIN, which moves its sending part to
    /// "Data Recvd": from then on the caller may drop the stream's octets (decision 57).
    pub fn on_range_acknowledged(streams: *Streams, range: stream_lost.Range) bool {
        const stream = streams.sent_on(range) orelse return false;
        stream.outgoing.on_acknowledged(range.len, range.fin);
        if (!stream.outgoing.is_all_acknowledged()) return false;
        // A stream reset after its FIN went out stays in "Reset Sent", which §3.1 gives no way
        // to "Data Recvd".
        return stream.sending.on(.all_data_acknowledged) == .taken;
    }

    /// Keeps a range the peer did not receive so that `send` frames it again (RFC 9000 §13.3).
    /// Nothing is kept for a stream that sent RESET_STREAM: "Once an endpoint sends a
    /// RESET_STREAM frame, no further STREAM frames are needed."
    pub fn on_range_lost(streams: *Streams, range: stream_lost.Range) stream_lost.Error!void {
        const stream = streams.sent_on(range) orelse return;
        if (!stream.sending.retransmits_data()) return;
        try streams.lost.add(range);
    }

    /// The stream a range this endpoint sent belongs to, or null when that stream has closed,
    /// which a reset acknowledged before the range was can do.
    fn sent_on(streams: *Streams, range: stream_lost.Range) ?*Stream {
        const id: StreamId = .{ .value = range.stream_id };
        // colibri frames octets only for a stream it may send on (§2.1).
        assert(id.is_sendable_by(streams.role));
        return switch (streams.lookup(id)) {
            .live => |stream| stream,
            .closed => null,
            // Nothing is framed on a stream before it opens.
            .unopened => unreachable,
        };
    }

    /// Abandons sending on `stream` with `application_error_code` (RFC 9000 §3.1: from "Ready", "Send" or
    /// "Data Sent" an application "can signal that it wishes to abandon transmission"). The
    /// sending part enters "Reset Sent" now, when the frame is owed rather than when it goes out,
    /// so nothing is framed after the decision (§19.4: "After sending a RESET_STREAM, an endpoint
    /// ceases transmission and retransmission of STREAM frames"). False when the part has ended.
    pub fn reset(streams: *Streams, stream: *Stream, application_error_code: u64) bool {
        if (stream.sending.on(.sent_reset) != .taken) return false;
        stream.reset_error_code = application_error_code;
        stream.reset_stream.owed = true;
        streams.resets_unacknowledged += 1;
        return true;
    }

    /// The peer acknowledged the packet that carried `stream`'s RESET_STREAM, which enters "Reset
    /// Recvd" (RFC 9000 §3.1).
    pub fn on_reset_acknowledged(streams: *Streams, stream: *Stream) void {
        assert(streams.resets_unacknowledged > 0);
        const transition = stream.sending.on(.reset_acknowledged);
        assert(transition == .taken);
        streams.resets_unacknowledged -= 1;
        // Nothing more is owed or outstanding, so no later loss report can owe the frame again.
        stream.reset_stream = .{};
    }

    /// Raises what the peer permits this endpoint to open (RFC 9000 §19.11). False when the
    /// frame does not increase the limit, which §4.6 says MUST be ignored.
    pub fn raise_local_limit(streams: *Streams, directionality: Directionality, limit: u64) bool {
        return streams.local_limit[@intFromEnum(directionality)].raise(limit);
    }

    /// The limit to advertise in a MAX_STREAMS frame, or null when none is owed (§4.6).
    pub fn peer_limit_frame(streams: *Streams, directionality: Directionality, now_ns: u64) ?u64 {
        return streams.peer_limit[@intFromEnum(directionality)].count_frame_limit(now_ns);
    }

    /// The limit to name in a STREAMS_BLOCKED frame, or null when none is owed (§4.6, §19.14).
    pub fn blocked_frame_limit(streams: *Streams, directionality: Directionality) ?u64 {
        return streams.local_limit[@intFromEnum(directionality)].blocked_frame_limit();
    }
};

test {
    _ = @import("stream_table_test.zig");
}
