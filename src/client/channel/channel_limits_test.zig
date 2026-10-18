//! The tests of the three limits a program sizes its buffers and bounds its loops by (decision
//! 123, `constants.zig`): the input from which `receive` takes octets, the output into which
//! `send_stream` writes a whole TLS record, and the events `receive` reports with no input. Each
//! test drives a channel to the worst case it can reach. The peers are h11's and h2's server sides
//! and the TLS server of `connection_tls_test_support.zig`, in the same process.
const std = @import("std");
const h2 = @import("h2");
const h11 = @import("h11");
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const support = @import("../connection/connection_test_support.zig");
const tls_support = @import("../connection/connection_tls_test_support.zig");
const quic_channel_support = @import("channel_quic_test_support.zig");
const channel_module = @import("channel.zig");
const event = @import("../event.zig");

const testing = std.testing;
const Channel = channel_module.Channel;
const Exchange = support.Exchange;

/// The channel the tests drive and its configuration, outside any stack frame. Test-only.
var channel: Channel align(@alignOf(Channel)) = undefined;
var config: channel_module.Config align(@alignOf(channel_module.Config)) = undefined;

/// The content of a response or a request: two DATA frames of the largest size colibri advertises
/// (RFC 9113 §4.2). The second frame, or the second record, does not fit beside the first in
/// `stream_input_len_min` octets.
const frames_count: usize = 2;
const content_len: usize = frames_count * h2.constants.frame_size_max;
const content_octet: u8 = 'c';
var content: [content_len]u8 = @splat(content_octet);
var body: [content_len]u8 = undefined;
/// An h11 response head of the longest length h11 reads (RFC 9112 §2.1).
var head: [h11.constants.head_len_max]u8 = undefined;
var exchanges: [constants.exchanges_max]Exchange align(@alignOf(Exchange)) = undefined;
var output: [constants.stream_output_len_min]u8 = undefined;

const ok: u16 = 200;
/// RFC 9110 §4.2.1 and §4.2.2: the ports of an "http" and an "https" origin whose URI names none.
const http_port: u16 = 80;
const https_port: u16 = 443;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]channel_module.Address{channel_module.Address.of(&loopback, 0)};

fn get() Exchange {
    return .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &body } };
}

/// Writes what the channel's connection owes into the peer's buffer.
fn send() void {
    support.to_peer_len += channel.send_stream(support.to_peer[support.to_peer_len..], support.now_ns);
}

/// Passes the channel what the peer sent, in calls until one takes nothing and reports nothing,
/// with `.none` once no octet is left. Starts the TCP connection an `open` event asks for.
fn collect() !void {
    // Bounded: each pass takes an octet or reports an event, and both are finite.
    for (0..support.buffer_len + support.events_max) |_| {
        const input: channel_module.Input = if (support.to_client_len > 0) .{ .stream = support.to_client[0..support.to_client_len] } else .none;
        const received = channel.receive(input, support.now_ns);
        take(received.consumed);
        const reported = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        if (reported == .open) try channel.start_tcp(support.stream.random(), support.now_seconds, null);
    }
    return error.TestUnexpectedResult;
}

/// Drops the first `consumed` octets the peer sent, which the channel took.
fn take(consumed: usize) void {
    std.mem.copyForwards(u8, &support.to_client, support.to_client[consumed..support.to_client_len]);
    support.to_client_len -= consumed;
}

/// A channel with no QUIC, whose TCP connection speaks `protocol` in cleartext and holds
/// `exchange`, which `send` has not written yet.
fn start_cleartext(protocol: event.Protocol, exchange: *Exchange) !void {
    config = .{ .authority = support.authority, .versions = support.only(protocol) };
    try channel.init(&config, .{ .addresses = &addresses, .port = http_port }, null);
    support.to_peer_len = 0;
    support.to_client_len = 0;
    _ = try channel.request(&exchange.request, &exchange.response);
    try collect();
}

/// A response head of `h11.constants.head_len_max` octets with no content. The whitespace before
/// its last field value fills it: RFC 9112 §5 lets OWS stand there, and RFC 9110 §5.6.3 lets OWS
/// hold any number of SP.
fn head_at_limit() []u8 {
    const start = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nPadding:";
    const end = "a\r\n\r\n";
    @memcpy(head[0..start.len], start);
    @memset(head[start.len .. head.len - end.len], ' ');
    @memcpy(head[head.len - end.len ..], end);
    return &head;
}

test "decision 124: receive takes an h11 head of the longest length from stream_input_len_min octets" {
    var exchange = get();
    try start_cleartext(.h11, &exchange);
    send();
    const whole = head_at_limit();
    try testing.expectEqual(h11.constants.head_len_max, whole.len);
    // The program holds the head and, past it, octets of the next response.
    @memcpy(support.to_client[0..whole.len], whole);
    @memcpy(support.to_client[whole.len..][0..whole.len], whole);
    support.to_client_len = whole.len * 2;
    // RFC 9112 §2.1: h11 reads the head again from its first octet until the head ends, so one
    // octet less of it takes nothing.
    const short = channel.receive(.{ .stream = support.to_client[0 .. whole.len - 1] }, support.now_ns);
    try testing.expectEqual(0, short.consumed);
    try testing.expectEqual(null, short.event);
    const taken = channel.receive(.{ .stream = support.to_client[0..constants.stream_input_len_min] }, support.now_ns);
    try testing.expectEqual(whole.len, taken.consumed);
    try testing.expectEqual(&exchange.response, taken.event.?.finished.response);
    try testing.expectEqual(.response, exchange.response.outcome);
    try testing.expectEqual(ok, exchange.response.status);
}

test "decision 124: receive takes an h2 frame of the largest size from stream_input_len_min octets" {
    var exchange = get();
    try start_cleartext(.h2, &exchange);
    support.peer_events_len = 0;
    // In cleartext, one octet of output takes one octet of what h2 wrote.
    try testing.expectEqual(1, channel.send_stream(support.to_peer[0..1], support.now_ns));
    support.to_peer_len = 1;
    send();
    // The peer reads the preface and the request, and writes its SETTINGS, which the client reads.
    support.peer_h2.init(.server);
    try support.peer_h2_read();
    try collect();
    support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], 1, ok, &.{}, false);
    try collect();
    try testing.expectEqual(0, support.to_client_len);
    // RFC 9113 §4.2: the content goes in frames of the largest size the client advertised.
    support.to_client_len = try peer_write_content(&support.to_client);
    // RFC 9113 §4.1: h2 takes whole frames, so one octet less of the first takes nothing.
    const short = channel.receive(.{ .stream = support.to_client[0 .. constants.frame_len_max - 1] }, support.now_ns);
    try testing.expectEqual(0, short.consumed);
    try testing.expectEqual(null, short.event);
    const taken = channel.receive(.{ .stream = support.to_client[0..constants.stream_input_len_min] }, support.now_ns);
    try testing.expectEqual(constants.frame_len_max, taken.consumed);
    take(taken.consumed);
    try collect();
    try testing.expectEqual(.response, exchange.response.outcome);
    try testing.expectEqualSlices(u8, &content, exchange.response.content_received());
}

/// The h2 peer writes `content` on stream 1 into `out`, in frames of the largest size the client
/// advertised (RFC 9113 §4.2), the last with END_STREAM. Returns the octets written.
fn peer_write_content(out: []u8) !usize {
    var written: usize = 0;
    var sent_len: usize = 0;
    // Bounded: each pass writes one frame.
    for (0..frames_count) |_| {
        const sent = try support.peer_h2.write_data(out[written..], 1, content[sent_len..], true);
        written += sent.written;
        sent_len += sent.consumed;
    }
    try testing.expectEqual(content.len, sent_len);
    return written;
}

/// A channel with no QUIC whose TCP connection runs h2 over TLS, past its handshake, with
/// `exchange` written. The TLS server has opened every record the client sent, and its h2 peer has
/// read the preface and the request.
fn start_tls(exchange: *Exchange) !void {
    try tls_support.prepare_server(&support.protocols_h2, false);
    config = .{ .tls = tls_support.client_values(support.authority), .authority = support.authority };
    try channel.init(&config, .{ .addresses = &addresses, .port = https_port }, null);
    try tls_support.start_server();
    _ = try channel.request(&exchange.request, &exchange.response);
    try collect();
    send();
    try testing.expectEqual(false, tls_support.server_flight().?);
    try collect();
    send();
    try testing.expectEqual(true, tls_support.server_flight().?);
    support.peer_h2.init(.server);
    try support.peer_h2.attach_tls(tls_support.server.provider());
    try tls_support.server_open();
    var consumed: usize = 0;
    // Bounded: each pass takes a frame, or ends the loop.
    for (0..tls_support.peer_plain_len + 1) |_| {
        const received = try support.peer_h2.receive(tls_support.peer_plain[consumed..tls_support.peer_plain_len], support.now_ns);
        if (received.consumed == 0) break;
        consumed += received.consumed;
    }
    try testing.expectEqual(tls_support.peer_plain_len, consumed);
    tls_support.peer_plain_len = 0;
}

/// The TLS server seals `plaintext` for the client: first one record of the most plaintext a record
/// carries (RFC 9846 §5.1), then the rest. Returns the octets of that first record.
fn seal_largest_first(plaintext: []const u8) !usize {
    const largest = tls_provider.constants.record_plaintext_len_max;
    const provider = tls_support.server.provider();
    const first = try provider.vtable.encrypt_record(provider.context, plaintext[0..largest], support.to_client[support.to_client_len..]);
    try testing.expectEqual(largest, first.consumed);
    support.to_client_len += first.written;
    try tls_support.server_seal(plaintext[largest..]);
    return first.written;
}

test "decision 124: receive takes a TLS record of the most plaintext from stream_input_len_min octets" {
    var exchange = get();
    try start_tls(&exchange);
    // The server's SETTINGS, the response's head, and its content in frames of the largest size.
    const out = &tls_support.peer_out;
    var written = support.peer_h2.write_pending(out, support.now_ns);
    written += try support.peer_h2.write_response(out[written..], 1, ok, &.{}, false);
    written += try peer_write_content(out[written..]);
    const record_len = try seal_largest_first(out[0..written]);
    // RFC 9846 §5.2: the connection opens whole records, so one octet less of the first takes
    // nothing.
    const short = channel.receive(.{ .stream = support.to_client[0 .. record_len - 1] }, support.now_ns);
    try testing.expectEqual(0, short.consumed);
    try testing.expectEqual(null, short.event);
    const taken = channel.receive(.{ .stream = support.to_client[0..constants.stream_input_len_min] }, support.now_ns);
    try testing.expectEqual(record_len, taken.consumed);
    take(taken.consumed);
    try collect();
    try testing.expectEqual(.response, exchange.response.outcome);
    try testing.expectEqualSlices(u8, &content, exchange.response.content_received());
}

test "decision 124: send_stream writes a TLS record of the most plaintext into stream_output_len_min octets" {
    var exchange = get();
    try start_tls(&exchange);
    // A POST whose content fills more than one record, on a connection that owes nothing else.
    var posted: Exchange = .{ .request = .{ .method = "POST", .path = "/", .content = &content }, .response = .{ .body = &body } };
    _ = try channel.request(&posted.request, &posted.response);
    try testing.expectEqual(0, support.to_peer_len);
    const written = channel.send_stream(&output, support.now_ns);
    try testing.expect(written > 0 and written <= output.len);
    // The server opens the first record whole, and it holds the most plaintext a record carries
    // (RFC 9846 §5.1).
    const provider = tls_support.server.provider();
    const opened = try provider.vtable.decrypt_record(provider.context, output[0..written], &tls_support.peer_plain);
    try testing.expectEqual(.application_data, opened.content);
    try testing.expectEqual(tls_provider.constants.record_plaintext_len_max, opened.plaintext_len);
}

/// What `receive` reported in a run with no input: the calls that reported an event, and whether
/// one of them was `closed`.
const Run = struct {
    events: usize = 0,
    closed: bool = false,
};

/// Calls `receive` with no input until a call reports no event, at most one call more than
/// `receive_events_without_input_max`. Each `open` names a transport that does not open, and the
/// channel shuts down at the last exchange's `finished`.
fn run_without_input() !Run {
    var run: Run = .{};
    var finished: usize = 0;
    for (0..constants.receive_events_without_input_max + 1) |_| {
        const received = channel.receive(.none, support.now_ns);
        try testing.expectEqual(0, received.consumed);
        const reported = received.event orelse return run;
        run.events += 1;
        switch (reported) {
            .open => |open| channel.transport_closed(open.transport),
            .finished => {
                finished += 1;
                if (finished == exchanges.len) channel.shutdown();
            },
            .closed => run.closed = true,
            .close, .connected, .ticket => return error.TestUnexpectedResult,
        }
    }
    return run;
}

test "decision 124: receive_events_without_input_max bounds the events a channel reports with no input" {
    // QUIC and TCP are offered, and the channel holds as many exchanges as it can.
    config = quic_channel_support.configured(true);
    try channel.init(&config, quic_channel_support.values_at(https_port), quic_channel_support.pool());
    for (&exchanges) |*exchange| {
        exchange.* = .{ .request = .{ .method = "GET", .path = "/" } };
        _ = try channel.request(&exchange.request, &exchange.response);
    }
    // Neither transport opens, so the channel gives up on every exchange at once, and then closes.
    const run = try run_without_input();
    try testing.expect(run.closed);
    try testing.expect(run.events <= constants.receive_events_without_input_max);
    try testing.expectEqual(null, channel.receive(.none, support.now_ns).event);
    for (&exchanges) |*exchange| try testing.expectEqual(.refused, exchange.response.outcome);
    // The worst case a test reaches: an `open` of each transport, a `finished` of each exchange,
    // and `closed`. The bound also counts the `close` of each transport and its connection's
    // `connected` and `ticket`. No run that a test reaches holds them beside these.
    const transports_opened = 2;
    try testing.expectEqual(@as(usize, transports_opened + constants.exchanges_max + 1), run.events);
}
