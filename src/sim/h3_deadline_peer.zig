//! The peer of the h3 deadline check (design §8 step 20c): a client on `quic`, `tls.quic.Client`
//! and h3, over the test identity of `src/testing/testdata/`. It makes the requests its plan
//! names, sends their content and reads their answers at the plan's pace, and keeps what the
//! server did to it, with the instant of each: each response's status, each stream the server
//! reset, the GOAWAY, and the close.
//!
//! A peer that reads slowly, or not at all, gives its streams or its connection a small credit,
//! and QUIC raises a limit only as h3 reads octets (RFC 9000 §4.1). It reads so only while it
//! waits for a response. A peer that is muted goes on writing datagrams the run drops, so the server
//! reads no acknowledgment from it.
//!
//! The peer names no `max_ack_delay`, so it acknowledges what the server sends within RFC 9000
//! §18.2's 25 milliseconds, which is how long the server's close follows its GOAWAY by at most.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const sim = @import("sim");
const identity = @import("client_trace_identity.zig");
const plan_module = @import("h3_deadline_plan.zig");

const limits = sim.constants.h3_deadline;
const Plan = plan_module.Plan;
const StreamId = quic.stream.StreamId;

pub const Error = error{
    /// The peer's own QUIC or h3 failed, or chapulin refused its handshake.
    PeerFailed,
};

/// The connection IDs the peer starts from, and the value its h3 draws reserved codes from.
pub const id_len: usize = 8;
const client_octet: u8 = 0xc1;
const original_octet: u8 = 0x0d;
const client_id: [id_len]u8 = @splat(client_octet);
const original_id: [id_len]u8 = @splat(original_octet);

/// The peer's own first Source Connection ID and the first Destination Connection ID it sends
/// (RFC 9000 §7.2). Two peers of one endpoint each need their own, or the endpoint hands the second
/// peer's Initial to the first peer's connection (RFC 9000 §5.2).
pub const Ids = struct { client: [id_len]u8, original: [id_len]u8 };

/// The IDs of a run that has one peer.
pub const ids_default: Ids = .{ .client = client_id, .original = original_id };
const grease: u64 = 0x1f2e_3d4c;
const parameters_len_max: usize = 1024;
const alpn_h3 = [_][]const u8{"h3"};
/// Octets of a request's frames before its content: a HEADERS frame and a DATA frame's header.
const prefix_len_max: usize = 512;
/// Octets h3 hands the peer in one data event.
const body_len: usize = 16_384;
/// The credit the peer gives the server's unidirectional streams, and each of its own streams
/// when it reads at once.
const uni_window: u64 = 65_536;
const window: u64 = quic.constants.receive_pool_len_default;
/// The field lines of a request, and the events one read takes at most.
const request_lines: usize = 4;
const Line = struct { name: []const u8, value: []const u8 };
const events_per_read_max: usize = 65_536;

/// One request the peer made, and what came back on its stream.
pub const Fetch = struct {
    id: u64,
    prefix: [prefix_len_max]u8 = undefined,
    prefix_len: usize = 0,
    /// The content the request declares, and how much of the stream the peer has supplied.
    content_len: usize = 0,
    supplied: usize = 0,
    finished: bool = false,
    status: ?u16 = null,
    status_ms: ?u64 = null,
    received_len: usize = 0,
    ended_ms: ?u64 = null,
    /// The code of the server's RESET_STREAM (RFC 9000 §19.4), and when the peer saw it.
    reset: ?u64 = null,
    reset_ms: ?u64 = null,

    /// Octets of the request's stream: its frames, then its content.
    pub fn total(fetch: *const Fetch) usize {
        return fetch.prefix_len + fetch.content_len;
    }
};

/// The server's CONNECTION_CLOSE as the peer read it (RFC 9000 §19.19).
pub const Close = struct {
    application: bool,
    error_code: u64,
    at_ms: u64,
};

pub const Peer = struct {
    config: tls.quic.ClientConfig,
    connection: quic.Connection,
    session: tls.quic.Client,
    send_scratch: quic.connection_send.DefaultScratch,
    scratch: quic.connection_datagram.Scratch,
    pool: quic.stream.stream_incoming.DefaultPool,
    h3: h3.Connection,
    section: h3.http.FieldSection,
    body: [body_len]u8,
    /// The octets every request's content is read from.
    content: [limits.slow_body_len]u8,
    fetches: [limits.requests_max]Fetch,
    fetches_len: usize,
    h3_started: bool,
    /// Whether the run drops the peer's datagrams, and whether it starts to once this instant's
    /// have left.
    muted: bool,
    mute_pending: bool,
    close: ?Close,
    goaway_ms: ?u64,
    /// The script: the exchanges begun, the next instant it acts at, and the next it reads at.
    exchanges_begun: u8,
    next_act_ms: ?u64,
    next_read_ms: u64,
    pings: u32,
    /// The connection IDs the peer started from, which its connection reads while it runs.
    ids: Ids,

    /// Starts the peer's connection at `now_ns`, with the credit its plan gives its streams.
    pub fn start(peer: *Peer, plan: *const Plan, random: tls.Random, now_ns: u64) Error!void {
        return peer.start_with(plan, random, now_ns, ids_default);
    }

    /// As `start`, from the connection IDs `ids`.
    pub fn start_with(peer: *Peer, plan: *const Plan, random: tls.Random, now_ns: u64, ids: Ids) Error!void {
        peer.ids = ids;
        peer.config.init(.{
            .trust = .{ .web_pki = .{ .anchors = &identity.anchors, .server_name = identity.authority } },
            .alpn = &alpn_h3,
            .cpu = identity.cpu,
        }) catch return error.PeerFailed;
        peer.connection.init(.{
            .role = .client,
            .version = .v1,
            .local_parameters = parameters(plan),
            .now_ns = now_ns,
            .identity = .{ .local_initial_source = &peer.ids.client, .original_destination = &peer.ids.original },
            .receive = peer.pool.storage(),
        });
        peer.send_scratch = .{};
        peer.h3.init(.{ .role = .client, .grease = grease });
        peer.config.values.quic_version = .v1;
        peer.session.start(&peer.config, random, identity.now_seconds, null) catch return error.PeerFailed;
        var encoded: [parameters_len_max]u8 = undefined;
        var writer = quic.core.Writer.init(&encoded);
        quic.transport_parameters.write(&writer, &peer.connection.local_parameters, .client) catch return error.PeerFailed;
        peer.session.provider().set_transport_params(writer.written()) catch return error.PeerFailed;
        const suite = peer.session.suite();
        suite.vtable.install_initial_keys(suite.context, .client, &peer.ids.original) catch return error.PeerFailed;
        for (&peer.content, 0..) |*octet, index| octet.* = content_letters[index % content_letters.len];
        peer.fetches_len = 0;
        peer.h3_started = false;
        peer.muted = false;
        peer.mute_pending = false;
        peer.close = null;
        peer.goaway_ms = null;
        peer.exchanges_begun = 0;
        peer.next_act_ms = null;
        peer.next_read_ms = 0;
        peer.pings = 0;
    }

    /// Writes the next datagram the peer owes into `output`, and returns its length, or null.
    pub fn send(peer: *Peer, output: []u8, now_ns: u64) Error!?usize {
        const provider = peer.h3.provider(.{ .context = peer, .vtable = &vtable });
        const sent = quic.connection_send.send(&peer.connection, peer.session.suite(), peer.session.provider(), provider, &peer.send_scratch, output, now_ns) catch return error.PeerFailed;
        const held = sent orelse return null;
        return held.len;
    }

    /// Takes one datagram the server sent, and keeps its CONNECTION_CLOSE when it carries one.
    pub fn receive(peer: *Peer, octets: []u8, now_ns: u64, now_ms: u64) Error!void {
        const received = quic.connection_datagram.receive(&peer.connection, peer.session.suite(), peer.session.provider(), .{ .octets = octets, .now_ns = now_ns, .ecn = .not_ect }, &peer.scratch) catch return error.PeerFailed;
        const close = received.close orelse return;
        if (peer.close == null) peer.close = .{ .application = close.layer == .application, .error_code = close.error_code, .at_ms = now_ms };
    }

    /// The instant the peer's QUIC next wants `on_instant` at, or null.
    pub fn timer_ns(peer: *Peer) ?u64 {
        const timer = quic.connection_timer.next(&peer.connection) orelse return null;
        return timer.at_ns;
    }

    pub fn on_instant(peer: *Peer, now_ns: u64) void {
        _ = quic.connection_timer.on_instant(&peer.connection, peer.session.suite(), &peer.scratch.recovery, now_ns) catch {};
    }

    /// Whether the peer's connection still runs.
    pub fn active(peer: *const Peer) bool {
        return peer.connection.termination.state == .active;
    }

    /// Starts h3 once the handshake completed, and reads what the plan's pace lets the peer read
    /// at `now_ms`. Returns whether it read anything.
    pub fn read(peer: *Peer, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
        if (!try peer.start_h3(now_ns)) return false;
        const moved = peer.note_resets(now_ms);
        // A peer that holds its credit reads nothing while it waits for a response.
        if (plan.reads_none() and peer.awaits_response()) return moved;
        // The plan's pace holds while the peer waits for a response; with none it reads at once,
        // as every peer reads the server's GOAWAY.
        const paced = plan.reads_paced() and peer.awaits_response();
        if (!paced) return try peer.read_events(peer.body.len, false, now_ns, now_ms) or moved;
        if (now_ms < peer.next_read_ms) return moved;
        peer.next_read_ms = now_ms + plan.read_gap_ms;
        return try peer.read_events(plan.read_len, true, now_ns, now_ms) or moved;
    }

    /// Whether the peer waits for a response: a request of its neither ended nor was reset.
    pub fn awaits_response(peer: *const Peer) bool {
        for (peer.fetches[0..peer.fetches_len]) |*fetch| {
            if (fetch.ended_ms == null and fetch.reset == null) return true;
        }
        return false;
    }

    /// Starts h3 once the handshake completed (RFC 9114 §6.2.1), and returns whether it runs.
    fn start_h3(peer: *Peer, now_ns: u64) Error!bool {
        if (peer.h3_started) return true;
        if (!peer.connection.handshake_complete) return false;
        peer.h3.start(&peer.connection, now_ns) catch return error.PeerFailed;
        peer.h3_started = true;
        return true;
    }

    /// Reads h3's events, and with `counted` stops once they carried `budget` octets of content.
    /// Returns whether it read any.
    fn read_events(peer: *Peer, budget: usize, counted: bool, now_ns: u64, now_ms: u64) Error!bool {
        var left = budget;
        var moved = false;
        // Bounded: each event reads an octet the pool holds, or ends a stream.
        for (0..events_per_read_max) |_| {
            if (left == 0) return true;
            const event = peer.h3.receive(&peer.connection, peer.body[0..@min(left, peer.body.len)], now_ns) catch return error.PeerFailed;
            const reported = event orelse return moved;
            moved = true;
            const taken = peer.note_event(reported, now_ms);
            if (counted) left -= taken;
        }
        return error.PeerFailed;
    }

    /// Keeps what an h3 event says, and returns the octets of content it carried.
    fn note_event(peer: *Peer, reported: h3.connection.Event, now_ms: u64) usize {
        switch (reported) {
            .response => |head| peer.note_response(head.stream_id, head.response.status, now_ms),
            .data => |data| {
                if (peer.fetch_of(data.stream_id)) |fetch| fetch.received_len += data.octets.len;
                return data.octets.len;
            },
            .end => |stream_id| if (peer.fetch_of(stream_id)) |fetch| {
                fetch.ended_ms = now_ms;
            },
            .reset => |ended| peer.note_reset(ended.stream_id, ended.error_code, now_ms),
            .goaway => peer.goaway_ms = peer.goaway_ms orelse now_ms,
            else => {},
        }
        return 0;
    }

    fn note_response(peer: *Peer, stream_id: u64, status: h3.http.Status, now_ms: u64) void {
        const fetch = peer.fetch_of(stream_id) orelse return;
        // RFC 9110 §15.2: an interim response is not the answer.
        if (status.is_interim()) return;
        fetch.status = status.code;
        fetch.status_ms = now_ms;
    }

    fn note_reset(peer: *Peer, stream_id: u64, code: u64, now_ms: u64) void {
        const fetch = peer.fetch_of(stream_id) orelse return;
        if (fetch.reset != null) return;
        fetch.reset = code;
        fetch.reset_ms = now_ms;
    }

    /// Notes each stream the server reset, which QUIC knows before h3 reads it (RFC 9000 §3.2).
    fn note_resets(peer: *Peer, now_ms: u64) bool {
        var moved = false;
        for (peer.fetches[0..peer.fetches_len]) |*fetch| {
            if (fetch.reset != null or fetch.ended_ms != null) continue;
            const code = quic.connection_stream_read.reset_code(&peer.connection, .{ .value = fetch.id }) orelse continue;
            fetch.reset = code;
            fetch.reset_ms = now_ms;
            moved = true;
        }
        return moved;
    }

    pub fn fetch_of(peer: *Peer, stream_id: u64) ?*Fetch {
        for (peer.fetches[0..peer.fetches_len]) |*fetch| {
            if (fetch.id == stream_id) return fetch;
        }
        return null;
    }

    /// Opens a request stream and writes the request's frames into a fetch: its head, and the
    /// header of a DATA frame for `content_len` octets. Null when the server's limit on streams
    /// leaves no room (RFC 9000 §4.6), or the peer holds as many requests as it can.
    pub fn stage(peer: *Peer, method: []const u8, content_len: usize, now_ns: u64) Error!?*Fetch {
        assert(peer.h3_started and content_len <= peer.content.len);
        if (peer.fetches_len == peer.fetches.len or !peer.active()) return null;
        const fetch = &peer.fetches[peer.fetches_len];
        fetch.* = .{ .id = 0, .content_len = content_len };
        peer.section.init();
        const lines = [request_lines]Line{
            .{ .name = ":method", .value = method },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = identity.authority },
            .{ .name = ":path", .value = "/" },
        };
        for (lines) |line| peer.section.append(line.name, line.value) catch return error.PeerFailed;
        const indexing: [request_lines]h3.qpack.encoder.Indexing = @splat(.no_insert);
        var writer = quic.core.Writer.init(&fetch.prefix);
        fetch.id = peer.h3.write_request(&peer.connection, &peer.section, &indexing, &writer, now_ns) catch |failure| {
            // RFC 9000 §4.6: the server's limit on streams is no failure of the peer's.
            if (failure == error.StreamsExhausted) return null;
            return error.PeerFailed;
        };
        if (content_len > 0) peer.h3.write_data_header(fetch.id, content_len, &writer, now_ns) catch return error.PeerFailed;
        fetch.prefix_len = writer.written().len;
        peer.fetches_len += 1;
        return fetch;
    }

    /// Supplies the stream of `fetch` up to `len` octets of it, and ends it there with `fin`. A
    /// stream the server asked the peer to stop takes no more (RFC 9000 §3.5).
    pub fn supply(peer: *Peer, fetch: *Fetch, len: usize, fin: bool) void {
        assert(len >= fetch.supplied and len <= fetch.total());
        if (fetch.finished) return;
        quic.connection_stream_send.supply(&peer.connection, .{ .value = fetch.id }, len, fin) catch return;
        fetch.supplied = len;
        fetch.finished = fin;
    }

    /// Cancels the request of `fetch` (RFC 9114 §4.1.1).
    pub fn cancel(peer: *Peer, fetch: *const Fetch) void {
        peer.h3.cancel(&peer.connection, fetch.id, h3.constants.error_request_cancelled);
    }

    /// Owes a PING, which keeps QUIC's idle timeout away and is no request (RFC 9000 §10.1.2).
    pub fn ping(peer: *Peer) void {
        if (!peer.active() or !peer.connection.handshake_complete) return;
        quic.connection_idle.owe_keep_alive(&peer.connection);
        peer.pings += 1;
    }
};

/// What the peer grants the server (RFC 9000 §18.2).
fn parameters(plan: *const Plan) quic.transport_parameters.Parameters {
    var held = quic.transport_parameters.Parameters.initial();
    held.initial_max_data = if (plan.small_connection_window()) limits.reader_stream_window else window;
    held.initial_max_stream_data_bidi_local = if (plan.small_window()) limits.reader_stream_window else window;
    held.initial_max_stream_data_uni = uni_window;
    held.initial_max_streams_uni = h3.constants.uni_streams_max;
    held.max_idle_timeout_ms = limits.quic_idle_timeout_ms;
    return held;
}

/// The octets of each request's content: letters alone.
const content_letters = "abcdefghijklmnopqrstuvwxyz";

comptime {
    // RFC 9000 §18.2: the delay of a peer that names none.
    assert(limits.close_after_goaway_ms_max * limits.ns_per_ms == quic.constants.max_ack_delay_default_ns);
}

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_fetch };

/// The stream provider QUIC reads the peer's request streams through (decision 57): a fetch's
/// frames, then its content.
fn read_fetch(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const peer: *Peer = @ptrCast(@alignCast(context));
    const fetch = peer.fetch_of(stream_id) orelse return 0;
    const from: usize = @intCast(offset);
    if (from >= fetch.total()) return 0;
    var written: usize = 0;
    if (from < fetch.prefix_len) {
        written = @min(output.len, fetch.prefix_len - from);
        @memcpy(output[0..written], fetch.prefix[from..][0..written]);
        if (written < fetch.prefix_len - from) return written;
    }
    const content_from = from + written - fetch.prefix_len;
    const len = @min(output.len - written, fetch.content_len - content_from);
    @memcpy(output[written..][0..len], peer.content[content_from..][0..len]);
    return written + len;
}
