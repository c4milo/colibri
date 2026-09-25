//! The TLS layer of design §9's server, which `h2spec -t -k` runs against (design §8 step 5):
//! one connection's records in, the byte stream to its session (`session.zig`), and what the
//! session writes back out as records. `server.zig` reads and writes the socket around it.
//!
//! chapulin's server runs in record mode (https://github.com/c4milo/colibri/issues/20): the
//! handshake takes the octets the socket read and returns the flight, so no call here waits and
//! the connection stays one of the worker's loop's connections (decision 46). The server offers
//! `h2` and `http/1.1` through ALPN, or `http/1.1` alone, and once the handshake completes the
//! session speaks the protocol it selected (design §8 step 15d). That protocol's `attach_tls`
//! checks the handshake, and every octet after that crosses the record half the client shares,
//! `records.zig`.
//!
//! A handshake or a record that fails ends the connection without an alert: chapulin names the
//! alert (`alert`), and this test-only endpoint closes the socket instead of sending it.
const std = @import("std");
const h2 = @import("h2");
const tls = @import("tls");
const constants = @import("../constants.zig");
const chapulin = @import("chapulin.zig");
const chapulin_server = @import("chapulin_server.zig");
const session_module = @import("../session.zig");
const tls_records = @import("records.zig");
const zero_key_records = @import("zero_key_records.zig");
const chapulin_record = @import("chapulin_record.zig");

const Session = session_module.Session;

/// Whether the build linked chapulin's server. Without it `Layer` holds nothing, and the server
/// refuses `--tls`.
pub const available = chapulin.available;

/// Why a connection ends here. The socket around it closes it either way.
pub const Error = chapulin_server.Error || tls_records.AttachError || tls_records.Error;

/// What every connection's server shares, loaded once: the identity it proves, the cookie key,
/// and the protocols it offers through ALPN (`session.alpn_both` or `session.alpn_h11`).
pub const Shared = struct {
    identity: chapulin_server.Identity,
    cookie_key: []const u8,
    protocols: []const []const u8 = &session_module.alpn_both,
};

/// One connection's TLS state, in static storage `server.zig` places.
pub const Layer = if (available) struct {
    server: chapulin_server.Server,
    /// chapulin's receive buffer (`chapulin_server.Options.receive`).
    receive: [constants.tls_receive_len]u8,
    /// The protocol's byte stream in both directions, once the handshake completes.
    records: tls_records.Records,
    /// Whether `attach_tls` accepted the finished handshake.
    attached: bool,
} else struct {};

pub const Step = tls_records.Step;

/// Prepares a layer for a connection the listener just accepted.
pub fn start(layer: *Layer, shared: *const Shared) Error!void {
    layer.server.init(.{
        .identity = shared.identity,
        .cookie_key = shared.cookie_key,
        .receive = &layer.receive,
        .protocols = shared.protocols,
    });
    try layer.server.start();
    layer.records.reset();
    layer.attached = false;
}

/// Wipes what the layer's session still holds, once its connection is over, whether it closed or
/// failed (chapulin's `rec.h`).
pub fn finish(layer: *Layer) void {
    layer.server.close();
}

/// The state of the layer's session, and the one `finish` leaves, for the server's tests.
pub fn session_state(layer: *const Layer) u8 {
    return chapulin.c.ch_record_state(&layer.server.record);
}
pub const chapulin_closed = if (available) chapulin.c.CH_ST_CLOSED else 0;

/// Runs the handshake over what the socket read until it completes, then the record half.
pub fn step(layer: *Layer, session: *Session, input: []u8, output: []u8) Error!Step {
    var taken: Step = .{ .consumed = 0, .written = 0, .done = false };
    if (!layer.attached) {
        // chapulin writes a flight whole or fails the handshake (`srv_cfg.h`), so it runs only
        // once the socket has taken enough of the output for a whole one.
        if (output.len < constants.tls_flight_len_max) return taken;
        const progress = try layer.server.handshake(input, output);
        taken.consumed = progress.consumed;
        taken.written = progress.written;
        if (!progress.complete) return taken;
        // RFC 7301 §3.2: the protocol ALPN selected is definitive for the connection, and a
        // selection of none is h11 (decision 88).
        session.init(session_module.protocol_of(layer.server.negotiated_alpn()));
        // RFC 9113 §3.2, §9.2 and decision 88: the handshake is checked before any HTTP octet
        // moves.
        try tls_records.attach(session, layer.server.provider());
        layer.attached = true;
    }
    const stepped = try layer.records.step(session, input[taken.consumed..], output[taken.written..]);
    taken.consumed += stepped.consumed;
    taken.written += stepped.written;
    taken.done = stepped.done;
    return taken;
}

const testing = std.testing;

/// A layer and a session the tests drive, outside any stack frame. Test-only.
var test_layer: Layer = undefined;
var test_session: Session = undefined;
var test_input: [test_input_len]u8 = undefined;
var test_output: [constants.write_buffer_len]u8 = undefined;

/// Room for the records a test seals: 33 empty ones take 726 octets. Test-only.
const test_input_len: usize = 4096;

/// An identity of the right lengths. The tests connect the layer without a handshake, so nothing
/// signs with it: each certificate is an empty DER SEQUENCE. Test-only.
const test_der = [_]u8{ der_sequence_tag, 0 };
const der_sequence_tag: u8 = 0x30;
const test_scalar: [chapulin_server.private_scalar_len]u8 = @splat(1);
const test_point: [chapulin_server.public_point_len]u8 = @splat(1);
const test_cookie: [chapulin_server.cookie_key_len]u8 = @splat(1);

/// Connects the test layer as a finished handshake would, with both directions keyed with zeros
/// (`zero_key_records.zig`), and attaches the session as `step` does. The zeroed session selected
/// the first protocol offered, so offering `protocols` picks the protocol. Test-only.
fn connect_test_layer(protocols: []const []const u8) !void {
    test_layer.server.init(.{
        .identity = .{ .leaf = &test_der, .issuer = &test_der, .private_scalar = &test_scalar, .public_point = &test_point },
        .cookie_key = &test_cookie,
        .receive = &test_layer.receive,
        .protocols = protocols,
    });
    zero_key_records.connect(&test_layer.server.held, &test_layer.server.record.t, &test_layer.receive);
    test_layer.records.reset();
    test_session.init(session_module.protocol_of(test_layer.server.negotiated_alpn()));
    try tls_records.attach(&test_session, test_layer.server.provider());
    test_layer.attached = true;
}

/// Seals `count` records that carry nothing into the test input, and returns them. Test-only.
fn empty_records(count: usize) ![]u8 {
    var len: usize = 0;
    for (0..count) |sequence| {
        const sealed = try zero_key_records.seal(sequence, zero_key_records.content_application_data, "", test_input[len..]);
        len += sealed.len;
    }
    return test_input[0..len];
}

test "a record with no room in the byte stream waits for the session to read" {
    if (!available) return error.SkipZigTest;
    try connect_test_layer(&session_module.alpn_both);
    // Leave less room than a record's ciphertext: the record stays in the socket's input.
    test_layer.records.plain_in_len = test_layer.records.plain_in.len - 1;
    const input = try empty_records(1);
    const stepped = try step(&test_layer, &test_session, input, &test_output);
    try testing.expectEqual(0, stepped.consumed);
}

test "RFC 9113 §10.5: a run of records carrying nothing ends h2 with a GOAWAY, not the socket" {
    if (!available) return error.SkipZigTest;
    try connect_test_layer(&session_module.alpn_both);
    // One past `records_without_data_max` is ENHANCE_YOUR_CALM, an h2 connection error.
    const input = try empty_records(h2.core.constants.records_without_data_max + 1);
    const stepped = try step(&test_layer, &test_session, input, &test_output);
    try testing.expect(test_session.h2.finished);
    // The GOAWAY is sealed, then the close_notify, and the connection is done.
    try testing.expect(stepped.done);
}

test "RFC 9846 §6.1: after the peer's close_notify this side still writes, then closes once" {
    if (!available) return error.SkipZigTest;
    try connect_test_layer(&session_module.alpn_both);
    // The peer closes before the server has written anything. §6.1: its close_notify "does not
    // have any effect on" this side's writing, so the server's SETTINGS still go out.
    const input = try zero_key_records.seal(0, zero_key_records.content_alert, &zero_key_records.close_notify, &test_input);
    const stepped = try step(&test_layer, &test_session, @constCast(input), &test_output);
    try testing.expectEqual(input.len, stepped.consumed);
    try testing.expect(test_layer.records.peer_closed);
    try testing.expect(test_layer.records.close_sent);
    try testing.expect(stepped.done);
    // What went out is the SETTINGS record, then this side's close_notify: a record whose
    // plaintext is the alert's two octets.
    const close_len = tls.constants.record_header_len + zero_key_records.close_notify.len + record_overhead_after_header;
    try testing.expect(stepped.written > close_len);
    const last_header = test_output[stepped.written - close_len ..][0..tls.constants.record_header_len];
    try testing.expectEqual(zero_key_records.content_application_data, last_header[0]);
    // The close goes out once.
    const again = try step(&test_layer, &test_session, &.{}, &test_output);
    try testing.expectEqual(0, again.written);
    try testing.expect(again.done);
}

/// What a sealed record adds after its header: the inner content type and the AEAD tag, which is
/// chapulin's `REC_OVERHEAD` less the header. Test-only.
const record_overhead_after_header: usize = chapulin.c.REC_OVERHEAD - tls.constants.record_header_len;

/// RFC 9846 §4.7.3's KeyUpdate asking for one back, as a handshake message. Test-only.
const key_update_requested = [_]u8{ handshake_key_update, 0, 0, 1, 1 };
const handshake_key_update: u8 = 24;

test "RFC 9846 §4.7.3: a peer's KeyUpdate is answered before anything else is read or sealed" {
    if (!available) return error.SkipZigTest;
    try connect_test_layer(&session_module.alpn_both);
    // The server's SETTINGS go out first, as this side's record 0.
    _ = try step(&test_layer, &test_session, &.{}, &test_output);
    try testing.expectEqual(0, test_layer.records.plain_out_len);
    // The KeyUpdate, then a record the peer sealed after it, which the layer does not open until
    // the reply is out.
    const update = try zero_key_records.seal(0, zero_key_records.content_handshake, &key_update_requested, &test_input);
    const update_len = update.len;
    const next = try zero_key_records.seal(1, zero_key_records.content_application_data, "later", test_input[update_len..]);
    const stepped = try step(&test_layer, &test_session, test_input[0 .. update_len + next.len], &test_output);
    try testing.expectEqual(update_len, stepped.consumed);
    // What went out is the reply alone, this side's record 1 under the keys it replaced.
    var inner: [16]u8 = undefined;
    const reply = zero_key_records.open(1, test_output[0..stepped.written], &inner).?;
    try testing.expectEqual(zero_key_records.content_handshake, reply.content_type);
    try testing.expectEqual(handshake_key_update, reply.content[0]);
    try testing.expect(!stepped.done);
}

test "decision 88: a handshake that selected http/1.1 runs h11, and RFC 9112 §9.8's close follows" {
    if (!available) return error.SkipZigTest;
    try connect_test_layer(&session_module.alpn_h11);
    try testing.expectEqual(.h11, std.meta.activeTag(test_session));
    const request = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    const input = try zero_key_records.seal(0, zero_key_records.content_application_data, request, &test_input);
    const stepped = try step(&test_layer, &test_session, @constCast(input), &test_output);
    try testing.expectEqual(input.len, stepped.consumed);
    const written = test_output[0..stepped.written];
    const first_len = chapulin_record.whole_record_len(written) orelse return error.TestUnexpectedResult;
    var inner: [tls.constants.record_plaintext_len_max + 1]u8 = undefined;
    const response = zero_key_records.open(0, written[0..first_len], &inner) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(zero_key_records.content_application_data, response.content_type);
    try testing.expect(std.mem.startsWith(u8, response.content, "HTTP/1.1 200 OK\r\n"));
    // RFC 9112 §9.8: a server attempts the exchange of closure alerts before it closes, so the
    // response is followed by this side's close_notify, and the connection is done.
    const alert = zero_key_records.open(1, written[first_len..], &inner) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(zero_key_records.content_alert, alert.content_type);
    try testing.expectEqualSlices(u8, &zero_key_records.close_notify, alert.content);
    try testing.expect(stepped.done);
}
