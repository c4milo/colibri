//! One connection of the test-only h2 client, with no socket in it: octets in, octets out, and a
//! plan of exchanges it runs to the end (design §9). `client/client_loop.zig` is its socket, and
//! these tests drive the same code the socket does, against `h2_session.zig` in one process.
//!
//! `step` does four things in order, each bounded by the caller's buffers:
//!   1. writes what the connection owes: its preface, the acknowledgments, the window updates and
//!      the GOAWAY (RFC 9113 §3.4, §6.5.3, §6.9, §6.8);
//!   2. reads frames until the input runs out or the connection fails, and records what each one
//!      meant for the exchange on its stream;
//!   3. opens a stream for every exchange that has none, and writes as much request content as the
//!      windows and the caller's room allow (§8.1, §6.9.1);
//!   4. once every exchange has settled, queues the GOAWAY of a graceful shutdown (§6.8).
//! No call waits. A step that writes nothing and consumes nothing means the caller must read more
//! octets, or the session is finished, which `done` says.
//!
//! Every stream opens before any response is read, so the exchanges of one plan share the
//! connection at once: that is what makes a run say something about multiplexing (§5).
//!
//! Time is a value, never a clock: each step reports an instant `tick_ns` after the last
//! (design §4.2, invariant 6).
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const constants = @import("../constants.zig");

const client_exchange = @import("../client/client_exchange.zig");

const Connection = h2.Connection;
const Event = h2.Event;
const Exchange = client_exchange.Exchange;
const Plan = client_exchange.Plan;
const Crc32 = std.hash.Crc32;

/// What one step did.
pub const Step = struct {
    /// Octets of the caller's input the connection consumed.
    consumed: usize,
    /// Octets written into the caller's output, to be sent in order.
    written: usize,
    /// Whether the session is finished: every octet it will ever write has been written.
    done: bool,
};

/// One connection's client state, in storage the caller places.
pub const Session = struct {
    connection: Connection,
    /// The instant the next step reports (design §4.2).
    now_ns: u64,
    /// `http` or `https` (RFC 9113 §8.3.1), and the authority every request names.
    scheme: []const u8,
    authority: []const u8,
    exchanges: [constants.exchanges_max]Exchange,
    exchanges_count: u32,
    /// Whether the GOAWAY of the graceful shutdown is queued (RFC 9113 §6.8).
    shutdown_queued: bool,
    /// Whether the connection failed (§5.4.1).
    failed: bool,

    /// Makes a client connection that has read nothing and written nothing. The slices of `plans`,
    /// `scheme` and `authority` must outlive the session.
    pub fn init(session: *Session, scheme: []const u8, authority: []const u8, plans: []const Plan) void {
        assert(plans.len > 0 and plans.len <= constants.exchanges_max);
        assert(scheme.len > 0 and authority.len > 0);
        session.connection.init(.client);
        session.now_ns = 0;
        session.scheme = scheme;
        session.authority = authority;
        session.exchanges_count = @intCast(plans.len);
        session.shutdown_queued = false;
        session.failed = false;
        for (plans, 0..) |plan, index| {
            assert(plan.content_len <= constants.request_content_len_max);
            session.exchanges[index] = .init(plan);
        }
    }

    /// Consumes what it can of `input` and writes what it can into `output`. See the header.
    pub fn step(session: *Session, input: []const u8, output: []u8) Step {
        session.now_ns += constants.tick_ns;
        var written = session.connection.write_pending(output, session.now_ns);
        const consumed = if (session.failed) 0 else session.read_frames(input);
        if (!session.failed) written += session.write_requests(output[written..]);
        if (session.settled() and !session.shutdown_queued and !session.failed) {
            // RFC 9113 §6.8: an endpoint that is done with the connection says so before it
            // closes, so the peer knows every stream it answered was read.
            session.connection.shutdown(h2.constants.error_no_error);
            session.shutdown_queued = true;
        }
        // RFC 9113 §5.4.1: a GOAWAY queued in this step goes out in this step, so the socket
        // around the session sends it before it closes.
        written += session.connection.write_pending(output[written..], session.now_ns);
        const over = session.failed or session.shutdown_queued;
        return .{ .consumed = consumed, .written = written, .done = over and !session.connection.has_pending() };
    }

    /// Whether every exchange ended the way a working peer ends one: a final response, then
    /// END_STREAM, with the connection intact.
    pub fn succeeded(session: *const Session) bool {
        if (session.failed) return false;
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.outcome != .ended) return false;
            // RFC 9113 §8.1: a stream ends after a final response and never before one. The
            // connection refuses every frame that would end it sooner, so this is colibri's own
            // invariant and not a claim about the peer.
            assert(exchange.status != 0);
            if (exchange.content_sent != exchange.plan.content_len) return false;
        }
        return true;
    }

    /// Whether no exchange is still pending.
    fn settled(session: *const Session) bool {
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.outcome == .pending) return false;
        }
        return true;
    }

    /// Reads frames until the input runs out or the connection fails.
    fn read_frames(session: *Session, input: []const u8) usize {
        var consumed: usize = 0;
        for (0..input.len + 1) |_| {
            const received = session.connection.receive(input[consumed..], session.now_ns) catch {
                // RFC 9113 §5.4.1: the connection is over; its GOAWAY goes out in this step.
                session.failed = true;
                return consumed;
            };
            if (received.consumed == 0) return consumed;
            consumed += received.consumed;
            if (received.event) |event| session.record(event);
        } else unreachable; // Each frame takes at least one octet, so the input ends first.
    }

    /// Records what one frame meant for the exchange on its stream.
    fn record(session: *Session, event: Event) void {
        switch (event) {
            .response => |response| {
                const exchange = session.exchange_of(response.stream_id) orelse return;
                // RFC 9110 §15.2: any number of interim responses precede the final one.
                if (response.response.status.is_interim()) {
                    exchange.interim_count += 1;
                } else {
                    exchange.status = response.response.status.code;
                }
                if (response.end_stream) exchange.outcome = .ended;
            },
            .data => |data| {
                const exchange = session.exchange_of(data.stream_id) orelse return;
                exchange.content_received += data.payload.len;
                exchange.received_crc32.update(data.payload);
                if (data.end_stream) exchange.outcome = .ended;
            },
            .trailers => |trailers| {
                const exchange = session.exchange_of(trailers.stream_id) orelse return;
                exchange.outcome = .ended;
            },
            .stream_reset, .stream_refused => |reset| {
                const exchange = session.exchange_of(reset.stream_id) orelse return;
                exchange.outcome = .reset;
                exchange.error_code = reset.error_code;
            },
            .goaway => |goaway| session.abandon_after(goaway.last_stream_id),
            else => {},
        }
    }

    /// RFC 9113 §6.8: the peer processed no stream past `last_stream_id` and will process none
    /// that opens now, so every exchange still pending on one is over.
    fn abandon_after(session: *Session, last_stream_id: u32) void {
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.outcome != .pending) continue;
            const unopened = exchange.stream_id == 0;
            if (unopened or exchange.stream_id > last_stream_id) exchange.outcome = .abandoned;
        }
    }

    /// The pending exchange on `stream_id`, or null when none is.
    fn exchange_of(session: *Session, stream_id: u32) ?*Exchange {
        assert(stream_id != 0);
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.stream_id == stream_id and exchange.outcome == .pending) return exchange;
        }
        return null;
    }

    /// Opens every stream the plan still owes, then writes request content, in plan order. It
    /// stops at the first exchange that cannot open, so the identifiers follow the plan (§5.1.1).
    fn write_requests(session: *Session, output: []u8) usize {
        var written: usize = 0;
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.outcome != .pending or exchange.stream_id != 0) continue;
            written += session.open(exchange, output[written..]) orelse break;
        }
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            written += session.write_content(exchange, output[written..]);
        }
        return written;
    }

    /// Writes the request of `exchange`, or returns null when it must wait for room or for the
    /// peer's stream limit. A request colibri refuses settles the exchange and waits for nothing.
    fn open(session: *Session, exchange: *Exchange, output: []u8) ?usize {
        assert(exchange.stream_id == 0 and exchange.outcome == .pending);
        var digits: [constants.content_length_digits_max]u8 = undefined;
        const length = std.fmt.bufPrint(&digits, "{d}", .{exchange.plan.content_len}) catch unreachable;
        const fields = [_]h2.hpack.Field{
            .{ .name = "user-agent", .value = constants.user_agent },
            .{ .name = "content-length", .value = length },
        };
        const has_content = exchange.plan.content_len > 0;
        // RFC 9110 §8.6: a request with no content sends no content-length.
        const sent_fields: []const h2.hpack.Field = if (has_content) &fields else fields[0..1];
        const sent = session.connection.write_request(output, .{
            .method = exchange.plan.method,
            .scheme = session.scheme,
            .path = exchange.plan.path,
            .authority = session.authority,
        }, sent_fields, &.{}, !has_content) catch |failure| {
            exchange.outcome = switch (failure) {
                error.OutputTooSmall, error.PeerLimitReached, error.Full => return null,
                error.AfterGoawayReceived => .abandoned,
                else => .invalid,
            };
            return 0;
        };
        exchange.stream_id = sent.stream_id;
        return sent.written;
    }

    /// Writes as much of the request content as the windows and the room allow (§6.9.1).
    fn write_content(session: *Session, exchange: *Exchange, output: []u8) usize {
        if (exchange.stream_id == 0 or exchange.content_sent == exchange.plan.content_len) return 0;
        var written: usize = 0;
        for (0..exchange.plan.content_len / constants.request_content_period + 1) |_| {
            const left = exchange.plan.content_len - exchange.content_sent;
            if (left == 0) return written;
            const chunk = client_exchange.content_from(exchange.content_sent, left);
            const sent = session.connection.write_data(
                output[written..],
                exchange.stream_id,
                chunk,
                chunk.len == left,
            ) catch return written;
            if (sent.consumed == 0) return written;
            exchange.sent_crc32.update(chunk[0..sent.consumed]);
            exchange.content_sent += @intCast(sent.consumed);
            written += sent.written;
        }
        return written;
    }
};

const testing = std.testing;
const h2_session = @import("h2_session.zig");

/// The two sessions the tests run, and the octets each has written that the other has not read.
/// Placed outside any stack frame. Test-only.
var test_client: Session = undefined;
var test_server: h2_session.Session = undefined;
var test_to_server: [constants.write_buffer_len]u8 = @splat(0);
var test_to_client: [constants.write_buffer_len]u8 = @splat(0);

/// Most rounds a test exchanges octets for, which bounds its loop. Test-only.
const test_rounds_max: u32 = 4096;

/// Drops the first `consumed` of `len` octets and returns how many are left. Test-only.
fn test_drop(buffer: []u8, len: usize, consumed: usize) usize {
    std.mem.copyForwards(u8, buffer[0 .. len - consumed], buffer[consumed..len]);
    return len - consumed;
}

/// Runs `test_client` against `test_server` until the client is done or neither side moves, and
/// returns the rounds it took. Test-only.
fn test_run() u32 {
    var to_server_len: usize = 0;
    var to_client_len: usize = 0;
    for (0..test_rounds_max) |round| {
        const client = test_client.step(test_to_client[0..to_client_len], test_to_server[to_server_len..]);
        to_client_len = test_drop(&test_to_client, to_client_len, client.consumed);
        to_server_len += client.written;
        const server = test_server.step(test_to_server[0..to_server_len], test_to_client[to_client_len..]);
        to_server_len = test_drop(&test_to_server, to_server_len, server.consumed);
        to_client_len += server.written;
        const moved = client.consumed + client.written + server.consumed + server.written;
        if (client.done or moved == 0) return @intCast(round + 1);
    }
    return test_rounds_max;
}

/// Steps `test_client` once over `input` with all of `test_to_server` to write into. Test-only.
fn test_feed(input: []const u8) Step {
    return test_client.step(input, &test_to_server);
}

/// A server's SETTINGS frame, which RFC 9113 §3.4 makes the first frame it sends. Test-only.
const test_server_preface = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";

test "a GET is answered, the content is read whole, and the client says GOAWAY" {
    test_server.init();
    test_client.init("http", "localhost", &.{.{ .method = "GET", .path = "/", .content_len = 0 }});
    const rounds = test_run();
    try testing.expect(rounds < test_rounds_max);
    try testing.expect(test_client.succeeded());
    const exchange = &test_client.exchanges[0];
    try testing.expectEqual(1, exchange.stream_id);
    try testing.expectEqual(constants.response_status, exchange.status);
    try testing.expectEqual(constants.response_body.len, exchange.content_received);
    try testing.expectEqual(Crc32.hash(constants.response_body), exchange.received_crc32.final());
    // RFC 9113 §6.8: the shutdown was said, and nothing is left to write.
    try testing.expect(test_client.shutdown_queued);
    try testing.expect(!test_client.connection.has_pending());
    try testing.expect(!test_server.finished);
}

test "three exchanges share the connection, and content past the window waits for the peer" {
    test_server.init();
    // RFC 9113 §6.9.2: a stream starts with 65,535 octets of window, so this content finishes
    // only if the client reads the WINDOW_UPDATE frames the server sends.
    const content_len = 3 * h2.constants.initial_window_size_initial;
    test_client.init("http", "localhost", &.{
        .{ .method = "GET", .path = "/", .content_len = 0 },
        .{ .method = "POST", .path = "/upload", .content_len = content_len },
        .{ .method = "GET", .path = "/index.html", .content_len = 0 },
    });
    // Every stream opens in the first step, before a single response is read (§5).
    const first = test_feed("");
    try testing.expect(first.written > 0);
    for (test_client.exchanges[0..3], [_]u32{ 1, 3, 5 }) |*exchange, stream_id| {
        try testing.expectEqual(stream_id, exchange.stream_id);
    }
    test_client.init("http", "localhost", &.{
        .{ .method = "GET", .path = "/", .content_len = 0 },
        .{ .method = "POST", .path = "/upload", .content_len = content_len },
        .{ .method = "GET", .path = "/index.html", .content_len = 0 },
    });
    try testing.expect(test_run() < test_rounds_max);
    try testing.expect(test_client.succeeded());
    const upload = &test_client.exchanges[1];
    try testing.expectEqual(content_len, upload.content_sent);
    try testing.expectEqual(client_exchange.content_crc32(content_len), upload.sent_crc32.final());
    try testing.expectEqual(constants.response_status, upload.status);
}

test "a stream the peer resets settles its exchange, and the others go on" {
    test_client.init("http", "localhost", &.{
        .{ .method = "GET", .path = "/a", .content_len = 0 },
        .{ .method = "GET", .path = "/b", .content_len = 0 },
    });
    _ = test_feed(test_server_preface);
    var frames: [h2.constants.frame_header_len + h2.constants.rst_stream_len]u8 = undefined;
    var writer = h2.core.Writer.init(&frames);
    try h2.frame.write_rst_stream(&writer, 3, h2.constants.error_refused_stream);
    const step = test_feed(writer.written());
    try testing.expectEqual(writer.written().len, step.consumed);
    try testing.expectEqual(.reset, test_client.exchanges[1].outcome);
    try testing.expectEqual(h2.constants.error_refused_stream, test_client.exchanges[1].error_code);
    try testing.expectEqual(.pending, test_client.exchanges[0].outcome);
    // One exchange is still pending, so the client has not said GOAWAY, and has not succeeded.
    try testing.expect(!test_client.shutdown_queued and !step.done);
    try testing.expect(!test_client.succeeded());
}

test "a GOAWAY abandons the streams past its last identifier and no others" {
    test_client.init("http", "localhost", &.{
        .{ .method = "GET", .path = "/a", .content_len = 0 },
        .{ .method = "GET", .path = "/b", .content_len = 0 },
    });
    _ = test_feed(test_server_preface);
    var frames: [h2.constants.frame_header_len + h2.constants.goaway_len_min]u8 = undefined;
    var writer = h2.core.Writer.init(&frames);
    // RFC 9113 §6.8: stream 1 may still be answered; stream 3 was never processed.
    try h2.frame.write_goaway(&writer, 1, h2.constants.error_no_error, "");
    _ = test_feed(writer.written());
    try testing.expectEqual(.pending, test_client.exchanges[0].outcome);
    try testing.expectEqual(.abandoned, test_client.exchanges[1].outcome);
    try testing.expect(!test_client.succeeded());
}

test "a peer that breaks the protocol ends the session with a GOAWAY and no success" {
    test_client.init("http", "localhost", &.{.{ .method = "GET", .path = "/", .content_len = 0 }});
    _ = test_feed("");
    // RFC 9113 §3.4: the server's first frame must be SETTINGS, and this is a PING.
    const step = test_feed("\x00\x00\x08\x06\x00\x00\x00\x00\x00" ++ "colibri!");
    try testing.expect(test_client.failed and step.done);
    try testing.expectEqual(h2.constants.frame_type_goaway, test_to_server[3]);
    try testing.expect(!test_client.succeeded());
    // A failed session consumes nothing more.
    try testing.expectEqual(0, test_feed(test_server_preface).consumed);
}

test "a request RFC 9113 forbids settles as invalid and spends no stream" {
    test_client.init("http", "localhost", &.{
        .{ .method = "G ET", .path = "/", .content_len = 0 },
        .{ .method = "GET", .path = "/", .content_len = 0 },
    });
    _ = test_feed("");
    try testing.expectEqual(.invalid, test_client.exchanges[0].outcome);
    try testing.expectEqual(0, test_client.exchanges[0].stream_id);
    // RFC 9113 §5.1.1: the refused request spent no identifier, so the next one opens stream 1.
    try testing.expectEqual(1, test_client.exchanges[1].stream_id);
}

/// Where a test builds the frames a server would send. Test-only.
var test_frames: [h2.constants.frame_size_max]u8 = @splat(0);

/// One HEADERS frame carrying a response with `status` on `stream_id` (RFC 9113 §8.3.2). The
/// encoder indexes nothing, so every frame it writes stands alone. Test-only.
fn test_response_frame(stream_id: u32, status: []const u8, end_stream: bool) ![]const u8 {
    var block: [h2.constants.frame_size_max]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(h2.constants.header_table_size_initial, .never);
    var block_writer = h2.core.Writer.init(&block);
    try encoder.begin_block(&block_writer);
    try encoder.write_field(&block_writer, ":status", status, .without_indexing);
    encoder.commit_block();
    const end_flag = if (end_stream) h2.constants.flag_end_stream else 0;
    var writer = h2.core.Writer.init(&test_frames);
    try h2.frame.write_header(&writer, .{
        .length = @intCast(block_writer.written().len),
        .type = h2.constants.frame_type_headers,
        .flags = h2.constants.flag_end_headers | end_flag,
        .stream_id = stream_id,
    });
    try writer.write_bytes(block_writer.written());
    return writer.written();
}

test "interim responses are counted, and the final response after them gives the status" {
    test_client.init("http", "localhost", &.{.{ .method = "GET", .path = "/", .content_len = 0 }});
    _ = test_feed(test_server_preface);
    // RFC 9113 §8.1: zero or more interim responses, then one final response.
    _ = test_feed(try test_response_frame(1, "103", false));
    _ = test_feed(try test_response_frame(1, "103", false));
    const exchange = &test_client.exchanges[0];
    try testing.expectEqual(2, exchange.interim_count);
    try testing.expectEqual(0, exchange.status);
    try testing.expectEqual(.pending, exchange.outcome);
    const last = test_feed(try test_response_frame(1, "204", true));
    try testing.expectEqual(204, exchange.status);
    try testing.expectEqual(2, exchange.interim_count);
    try testing.expect(test_client.succeeded() and last.done);
    // RFC 9113 §6.8: the step that settles the last exchange writes the GOAWAY.
    try testing.expectEqual(h2.constants.frame_header_len + h2.constants.goaway_len_min, last.written);
    try testing.expectEqual(h2.constants.frame_type_goaway, test_to_server[3]);
}

test "an exchange past the peer's stream limit waits for a stream to close" {
    test_client.init("http", "localhost", &.{
        .{ .method = "GET", .path = "/a", .content_len = 0 },
        .{ .method = "GET", .path = "/b", .content_len = 0 },
    });
    // RFC 9113 §5.1.2: the peer allows one stream at once, and says so before any opens.
    var writer = h2.core.Writer.init(&test_frames);
    try h2.frame.write_settings(&writer, &.{.{ .id = h2.constants.setting_max_concurrent_streams, .value = 1 }});
    _ = test_feed(writer.written());
    try testing.expectEqual(1, test_client.exchanges[0].stream_id);
    try testing.expectEqual(0, test_client.exchanges[1].stream_id);
    try testing.expectEqual(.pending, test_client.exchanges[1].outcome);
    // The first stream closes, so the second exchange opens the next identifier (§5.1.1).
    _ = test_feed(try test_response_frame(1, "200", true));
    try testing.expectEqual(3, test_client.exchanges[1].stream_id);
    _ = test_feed(try test_response_frame(3, "200", true));
    try testing.expect(test_client.succeeded());
}

test "content the peer sends before any response is refused, and the exchange is reset" {
    test_client.init("http", "localhost", &.{.{ .method = "GET", .path = "/", .content_len = 0 }});
    _ = test_feed(test_server_preface);
    var writer = h2.core.Writer.init(&test_frames);
    try h2.frame.write_data(&writer, 1, "colibri\n", true, 0);
    _ = test_feed(writer.written());
    // RFC 9113 §8.1, §8.1.1: colibri's RST_STREAM settles the exchange, with no status to report.
    const exchange = &test_client.exchanges[0];
    try testing.expectEqual(.reset, exchange.outcome);
    try testing.expectEqual(h2.constants.error_protocol_error, exchange.error_code);
    try testing.expectEqual(0, exchange.content_received);
    try testing.expect(!test_client.succeeded());
}

test "a response that arrives before the content is sent whole is not a success" {
    const content_len = 2 * h2.constants.initial_window_size_initial;
    test_client.init("http", "localhost", &.{.{ .method = "POST", .path = "/", .content_len = content_len }});
    _ = test_feed(test_server_preface);
    // RFC 9113 §6.9.2: the window holds less than the content, and no WINDOW_UPDATE follows.
    try testing.expect(test_client.exchanges[0].content_sent < content_len);
    _ = test_feed(try test_response_frame(1, "200", true));
    try testing.expectEqual(.ended, test_client.exchanges[0].outcome);
    try testing.expect(!test_client.succeeded());
}

test "a connection that fails after every exchange ended is not a success" {
    test_client.init("http", "localhost", &.{.{ .method = "GET", .path = "/", .content_len = 0 }});
    _ = test_feed(test_server_preface);
    _ = test_feed(try test_response_frame(1, "200", true));
    try testing.expect(test_client.succeeded());
    // RFC 9113 §6.5: a SETTINGS frame on a stream other than 0 is a connection error.
    _ = test_feed("\x00\x00\x00\x04\x00\x00\x00\x00\x01");
    try testing.expect(test_client.failed);
    try testing.expect(!test_client.succeeded());
}
