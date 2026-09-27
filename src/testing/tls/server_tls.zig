//! The TLS layer of design §9's server, which `h2spec -t -k` runs against (design §8 step 5):
//! one connection's records in, the byte stream to its session (`session.zig`), and what the
//! session writes back out as records. `server.zig` reads and writes the socket around it.
//!
//! The session is colibri's `tls.record.Server` (design §8 step 16b): the handshake takes the
//! octets the socket read and returns the flight, so no call here waits and the connection stays
//! one of the worker's loop's connections (decision 46). The server offers `h2` and `http/1.1`
//! through ALPN, or `http/1.1` alone, and once the handshake completes the session speaks the
//! protocol it selected (design §8 step 15d). That protocol's `attach_tls` checks the handshake,
//! and every octet after that crosses the record half the client shares, `records.zig`.
//!
//! A handshake or a record that fails ends the connection without an alert: the session names the
//! alert (`alert`), and this test-only endpoint closes the socket instead of sending it.
const std = @import("std");
const h2 = @import("h2");
const tls = @import("tls");
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const session_module = @import("../session.zig");
const tls_records = @import("records.zig");

const Session = session_module.Session;

/// Why a connection ends here. The socket around it closes it either way.
pub const Error = tls.record.Error || tls_records.AttachError || tls_records.Error;

/// The server issues no ticket, so it judges none at a clock: chapulin's 0 for none.
const no_clock: u64 = 0;

/// One connection's TLS state, in static storage `server.zig` places.
pub const Layer = struct {
    server: tls.record.Server,
    /// The protocol's byte stream in both directions, once the handshake completes.
    records: tls_records.Records,
    /// Whether `attach_tls` accepted the finished handshake.
    attached: bool,
};

pub const Step = tls_records.Step;

/// Prepares a layer for a connection the listener just accepted, under the configuration every
/// connection of the run borrows.
pub fn start(layer: *Layer, config: *const tls.record.ServerConfig) Error!void {
    try layer.server.start(config, no_clock);
    layer.records.reset();
    layer.attached = false;
}

/// Wipes what the layer's session still holds, once its connection is over, whether it closed or
/// failed.
pub fn finish(layer: *Layer) void {
    layer.server.close();
}

/// Whether `finish` has wiped the layer's session, for the server's tests.
pub fn wiped(layer: *const Layer) bool {
    return layer.server.session.recordState() == .closed;
}

/// Runs the handshake over what the socket read until it completes, then the record half.
pub fn step(layer: *Layer, session: *Session, input: []u8, output: []u8) Error!Step {
    var taken: Step = .{ .consumed = 0, .written = 0, .done = false };
    if (!layer.attached) {
        // The session writes a flight whole or fails the handshake, so it runs only once the
        // socket has taken enough of the output for a whole one.
        if (output.len < constants.tls_flight_len_max) return taken;
        const progress = try layer.server.handshake(input, output);
        taken.consumed = progress.consumed;
        taken.written = progress.written;
        if (!progress.complete) return taken;
        const provider = layer.server.provider();
        // RFC 7301 §3.2: the protocol ALPN selected is definitive for the connection, and a
        // selection of none is h11 (decision 88).
        session.init(session_module.protocol_of(provider.vtable.negotiated_alpn(provider.context)));
        // RFC 9113 §3.2, §9.2 and decision 88: the handshake is checked before any HTTP octet
        // moves.
        try tls_records.attach(session, provider);
        layer.attached = true;
    }
    const stepped = try layer.records.step(session, input[taken.consumed..], output[taken.written..]);
    taken.consumed += stepped.consumed;
    taken.written += stepped.written;
    taken.done = stepped.done;
    return taken;
}

const testing = std.testing;
const support = @import("records_test_support.zig");

/// A layer, a session and the provider the tests attach in place of a handshake, outside any
/// stack frame. Test-only.
var test_layer: Layer align(@alignOf(Layer)) = undefined;
var test_session: Session align(@alignOf(Session)) = undefined;
var test_provider: support.PlainProvider align(@alignOf(support.PlainProvider)) = undefined;
var test_input: [test_input_len]u8 = undefined;
var test_output: [constants.write_buffer_len]u8 = undefined;

/// Room for the records a test sends: 33 empty ones take 165 octets. Test-only.
const test_input_len: usize = 4096;

/// Attaches the session as `step` does once a handshake that selected `protocol` completes.
/// Test-only.
fn connect_test_layer(protocol: []const u8) !void {
    test_provider = .{ .alpn = protocol };
    test_layer.records.reset();
    test_session.init(session_module.protocol_of(protocol));
    try tls_records.attach(&test_session, test_provider.provider());
    test_layer.attached = true;
}

/// Writes `count` records that carry nothing into the test input, and returns them. Test-only.
fn empty_records(count: usize) ![]u8 {
    var len: usize = 0;
    for (0..count) |_| len += (try support.seal(support.content_application_data, "", test_input[len..])).len;
    return test_input[0..len];
}

test "a record with no room in the byte stream waits for the session to read" {
    try connect_test_layer(&tls_provider.constants.alpn_h2);
    // Leave no room for the record's octet: the record stays in the socket's input.
    test_layer.records.plain_in_len = test_layer.records.plain_in.len;
    const input = try support.seal(support.content_application_data, "x", &test_input);
    const stepped = try step(&test_layer, &test_session, input, &test_output);
    try testing.expectEqual(0, stepped.consumed);
}

test "RFC 9113 §10.5: a run of records carrying nothing ends h2 with a GOAWAY, not the socket" {
    try connect_test_layer(&tls_provider.constants.alpn_h2);
    // One past `records_without_data_max` is ENHANCE_YOUR_CALM, an h2 connection error.
    const input = try empty_records(h2.core.constants.records_without_data_max + 1);
    const stepped = try step(&test_layer, &test_session, input, &test_output);
    try testing.expect(test_session.h2.finished);
    // The GOAWAY is sealed, then the close_notify, and the connection is done.
    try testing.expect(stepped.done);
}

test "RFC 9846 §6.1: after the peer's close_notify this side still writes, then closes once" {
    try connect_test_layer(&tls_provider.constants.alpn_h2);
    // The peer closes before the server has written anything. §6.1: its close_notify "does not
    // have any effect on" this side's writing, so the server's SETTINGS still go out.
    const input = try support.seal(support.content_alert, &support.close_notify, &test_input);
    const stepped = try step(&test_layer, &test_session, input, &test_output);
    try testing.expectEqual(input.len, stepped.consumed);
    try testing.expect(test_layer.records.peer_closed);
    try testing.expect(test_layer.records.close_sent);
    try testing.expect(stepped.done);
    // What went out is the SETTINGS record, then this side's close_notify.
    const settings = support.open(test_output[0..stepped.written]).?;
    try testing.expectEqual(support.content_application_data, settings.content_type);
    const close = support.open(test_output[tls_provider.constants.record_header_len + settings.content.len .. stepped.written]).?;
    try testing.expectEqual(support.content_alert, close.content_type);
    try testing.expectEqualSlices(u8, &support.close_notify, close.content);
    // The close goes out once.
    const again = try step(&test_layer, &test_session, &.{}, &test_output);
    try testing.expectEqual(0, again.written);
    try testing.expect(again.done);
}

test "RFC 9846 §4.7.3: a peer's KeyUpdate is answered before anything else is read or sealed" {
    try connect_test_layer(&tls_provider.constants.alpn_h2);
    // The server's SETTINGS go out first.
    _ = try step(&test_layer, &test_session, &.{}, &test_output);
    try testing.expectEqual(0, test_layer.records.plain_out_len);
    // The KeyUpdate, then a record the peer sent after it, which the layer does not open until
    // the reply is out.
    const update = try support.seal(support.content_handshake, &support.key_update_requested, &test_input);
    const update_len = update.len;
    const next = try support.seal(support.content_application_data, "later", test_input[update_len..]);
    const stepped = try step(&test_layer, &test_session, test_input[0 .. update_len + next.len], &test_output);
    try testing.expectEqual(update_len, stepped.consumed);
    // What went out is the reply alone.
    const reply = support.open(test_output[0..stepped.written]).?;
    try testing.expectEqual(support.content_handshake, reply.content_type);
    try testing.expectEqualSlices(u8, &support.key_update_not_requested, reply.content);
    try testing.expectEqual(stepped.written, tls_provider.constants.record_header_len + reply.content.len);
    try testing.expect(!stepped.done);
}

test "decision 88: a handshake that selected http/1.1 runs h11, and RFC 9112 §9.8's close follows" {
    try connect_test_layer(tls_provider.constants.alpn_http_1_1);
    try testing.expectEqual(.h11, std.meta.activeTag(test_session));
    const request = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    const input = try support.seal(support.content_application_data, request, &test_input);
    const stepped = try step(&test_layer, &test_session, input, &test_output);
    try testing.expectEqual(input.len, stepped.consumed);
    const written = test_output[0..stepped.written];
    const response = support.open(written).?;
    try testing.expectEqual(support.content_application_data, response.content_type);
    try testing.expect(std.mem.startsWith(u8, response.content, "HTTP/1.1 200 OK\r\n"));
    // RFC 9112 §9.8: a server attempts the exchange of closure alerts before it closes, so the
    // response is followed by this side's close_notify, and the connection is done.
    const alert = support.open(written[tls_provider.constants.record_header_len + response.content.len ..]).?;
    try testing.expectEqual(support.content_alert, alert.content_type);
    try testing.expectEqualSlices(u8, &support.close_notify, alert.content);
    try testing.expect(stepped.done);
}
