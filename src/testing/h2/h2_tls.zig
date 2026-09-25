//! The TLS layer of design §9's h2 server, which `h2spec -t -k` runs against (design §8 step 5):
//! one connection's records in, h2's byte stream to `h2_session.zig`, and its frames back out as
//! records. `h2_server.zig` reads and writes the socket around it.
//!
//! chapulin's server runs in record mode (https://github.com/c4milo/colibri/issues/20): the
//! handshake takes the octets the socket read and returns the flight, so no call here waits and
//! the connection stays one of the worker's loop's connections (decision 46). Once the handshake
//! completes, `attach_tls` checks what RFC 9113 §3.2 and §9.2 require of it, and every octet
//! after that crosses `connection_tls`'s `decrypt` and `encrypt`.
//!
//! `step` does four things in order, each bounded by the buffers:
//!   1. runs the handshake over what the socket read, until it completes;
//!   2. opens whole records into h2's byte stream while there is room for one;
//!   3. steps the session over the byte stream, as the cleartext server does;
//!   4. seals what the session wrote, as much as the socket's output holds, and once the session
//!      is done and every octet is sealed, the `close_notify` RFC 9846 §6.1 requires.
//!
//! A handshake or a record that fails ends the connection without an alert: chapulin names the
//! alert (`alert`), and this test-only endpoint closes the socket instead of sending it.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const tls = @import("tls");
const constants = @import("../constants.zig");
const chapulin = @import("../tls/chapulin.zig");
const chapulin_server = @import("../tls/chapulin_server.zig");
const h2_session = @import("h2_session.zig");
const zero_key_records = @import("../tls/zero_key_records.zig");

const Session = h2_session.Session;
const connection_tls = h2.connection_tls;

/// Whether the build linked chapulin's server. Without it `Layer` holds nothing, and the server
/// refuses `--tls`.
pub const available = chapulin.available;

/// Why a connection ends here. The socket around it closes it either way.
pub const Error = chapulin_server.Error || connection_tls.AttachError || error{
    /// A record did not open or did not seal (RFC 9846 §6).
    TlsFailed,
};

/// What every connection's server shares: the identity it proves and the cookie key, loaded once.
pub const Shared = struct {
    identity: chapulin_server.Identity,
    cookie_key: []const u8,
};

/// One connection's TLS state, in static storage `h2_server.zig` places.
pub const Layer = if (available) struct {
    server: chapulin_server.Server,
    /// chapulin's receive buffer (`chapulin_server.Options.receive`).
    receive: [constants.tls_receive_len]u8,
    /// h2's byte stream, opened from records and not yet consumed by the session.
    plain_in: [constants.tls_plaintext_in_len]u8,
    plain_in_len: usize,
    /// What the session wrote that the seal has not taken yet.
    plain_out: [constants.write_buffer_len]u8,
    plain_out_len: usize,
    /// Whether `attach_tls` accepted the finished handshake.
    attached: bool,
    /// Whether the peer's `close_notify` ended its data (RFC 9846 §6.1).
    peer_closed: bool,
    /// Whether this side's `close_notify` has been sealed.
    close_sent: bool,
} else struct {};

/// What one step did to the socket's buffers.
pub const Step = struct {
    /// Octets of the socket's input taken.
    consumed: usize,
    /// Octets written into the socket's output, to be sent in order.
    written: usize,
    /// Whether the connection is finished and everything it owes is written.
    done: bool,
};

/// Prepares a layer for a connection the listener just accepted.
pub fn start(layer: *Layer, shared: *const Shared) Error!void {
    layer.server.init(.{ .identity = shared.identity, .cookie_key = shared.cookie_key, .receive = &layer.receive });
    try layer.server.start();
    layer.plain_in_len = 0;
    layer.plain_out_len = 0;
    layer.attached = false;
    layer.peer_closed = false;
    layer.close_sent = false;
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

/// Runs the four parts of the header over what the socket read, writing into its output.
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
        // RFC 9113 §3.2, §9.2: the handshake is checked before any h2 octet moves.
        try session.connection.attach_tls(layer.server.provider());
        layer.attached = true;
    }
    taken.consumed += try open_records(layer, session, input[taken.consumed..]);
    step_session(layer, session);
    taken.written += try seal(layer, session, output[taken.written..]);
    taken.done = finished(layer, session) and layer.plain_out_len == 0 and layer.close_sent;
    return taken;
}

/// Whether the connection has nothing more to read: the session failed, or the peer closed.
fn finished(layer: *const Layer, session: *const Session) bool {
    return session.finished or layer.peer_closed;
}

/// Opens whole records into the byte stream while one fits, and returns the octets taken.
fn open_records(layer: *Layer, session: *Session, input: []const u8) Error!usize {
    var consumed: usize = 0;
    // Bounded: every pass takes a whole record, or stops.
    for (0..input.len + 1) |_| {
        if (finished(layer, session)) return consumed;
        const opened = connection_tls.decrypt(
            &session.connection,
            input[consumed..],
            layer.plain_in[layer.plain_in_len..],
            session.now_ns,
        ) catch |failure| switch (failure) {
            // The byte stream has no room for another record until the session reads it.
            error.NoSpaceLeft => return consumed,
            // RFC 9113 §5.4.1: an h2 connection error. The session's next step reads the failure
            // from the connection and writes the GOAWAY it queued.
            error.ConnectionFailed => return consumed,
            error.TlsFailed, error.HandshakeIncomplete, error.NoProvider => return error.TlsFailed,
        };
        // No whole record is left.
        if (opened.consumed == 0) return consumed;
        consumed += opened.consumed;
        layer.plain_in_len += opened.plaintext_len;
        // RFC 9846 §6.1: the peer's close_notify ends its data.
        if (opened.end_of_data) layer.peer_closed = true;
    }
    unreachable; // Each record takes at least its header, so the input ends first.
}

/// Steps the session over the byte stream until it stops moving, as `h2_server.zig`'s cleartext
/// path does, appending what it writes to the plaintext output.
fn step_session(layer: *Layer, session: *Session) void {
    for (0..constants.steps_per_read_max) |_| {
        const room = layer.plain_out[layer.plain_out_len..];
        if (room.len == 0) return;
        const stepped = session.step(layer.plain_in[0..layer.plain_in_len], room);
        layer.plain_out_len += stepped.written;
        take_plain_in(layer, stepped.consumed);
        if (stepped.done) return;
        if (stepped.consumed == 0 and stepped.written == 0) return;
    }
}

/// Seals as much of the plaintext output as the socket's output holds, then the `close_notify`
/// once the connection is finished and nothing is left to seal.
fn seal(layer: *Layer, session: *Session, output: []u8) Error!usize {
    var written: usize = 0;
    if (layer.plain_out_len > 0) {
        const sealed = connection_tls.encrypt(&session.connection, layer.plain_out[0..layer.plain_out_len], output) catch |failure| switch (failure) {
            // The socket has not taken what it holds; the rest waits.
            error.NoSpaceLeft => return 0,
            else => return error.TlsFailed,
        };
        take_plain_out(layer, sealed.consumed);
        written = sealed.written;
    }
    if (!finished(layer, session) or layer.plain_out_len > 0 or layer.close_sent) return written;
    if (output.len - written < close_notify_len_max) return written;
    // RFC 9846 §6.1: "Each party MUST send a "close_notify" alert before closing its write side
    // of the connection".
    written += connection_tls.close_notify(&session.connection, output[written..]) catch return written;
    layer.close_sent = true;
    return written;
}

/// The most octets a sealed `close_notify` takes: a record header (RFC 9846 §5.1), the alert's two
/// octets (§6), and the content type and AEAD expansion, which §5.2 bounds by what a ciphertext
/// may add to a plaintext.
const close_notify_len_max: usize = tls.constants.record_header_len + alert_len +
    (tls.constants.record_ciphertext_len_max - tls.constants.record_plaintext_len_max);

/// RFC 9846 §6: an alert is a level and a description, one octet each.
const alert_len: usize = 2;

fn take_plain_in(layer: *Layer, consumed: usize) void {
    assert(consumed <= layer.plain_in_len);
    std.mem.copyForwards(u8, &layer.plain_in, layer.plain_in[consumed..layer.plain_in_len]);
    layer.plain_in_len -= consumed;
}

fn take_plain_out(layer: *Layer, consumed: usize) void {
    assert(consumed <= layer.plain_out_len);
    std.mem.copyForwards(u8, &layer.plain_out, layer.plain_out[consumed..layer.plain_out_len]);
    layer.plain_out_len -= consumed;
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
/// (`zero_key_records.zig`), and attaches the session. Test-only.
fn connect_test_layer() !void {
    test_session.init();
    test_layer.server.init(.{
        .identity = .{ .leaf = &test_der, .issuer = &test_der, .private_scalar = &test_scalar, .public_point = &test_point },
        .cookie_key = &test_cookie,
        .receive = &test_layer.receive,
    });
    zero_key_records.connect(&test_layer.server.held, &test_layer.server.record.t, &test_layer.receive);
    test_layer.plain_in_len = 0;
    test_layer.plain_out_len = 0;
    test_layer.peer_closed = false;
    test_layer.close_sent = false;
    try test_session.connection.attach_tls(test_layer.server.provider());
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
    try connect_test_layer();
    // Leave less room than a record's ciphertext: the record stays in the socket's input.
    test_layer.plain_in_len = test_layer.plain_in.len - 1;
    const input = try empty_records(1);
    const stepped = try step(&test_layer, &test_session, input, &test_output);
    try testing.expectEqual(0, stepped.consumed);
}

test "RFC 9113 §10.5: a run of records carrying nothing ends h2 with a GOAWAY, not the socket" {
    if (!available) return error.SkipZigTest;
    try connect_test_layer();
    // One past `records_without_data_max` is ENHANCE_YOUR_CALM, an h2 connection error.
    const input = try empty_records(h2.constants.records_without_data_max + 1);
    const stepped = try step(&test_layer, &test_session, input, &test_output);
    try testing.expect(test_session.finished);
    // The GOAWAY is sealed, then the close_notify, and the connection is done.
    try testing.expect(stepped.done);
}

test "RFC 9846 §6.1: after the peer's close_notify this side still writes, then closes once" {
    if (!available) return error.SkipZigTest;
    try connect_test_layer();
    // The peer closes before the server has written anything. §6.1: its close_notify "does not
    // have any effect on" this side's writing, so the server's SETTINGS still go out.
    const input = try zero_key_records.seal(0, zero_key_records.content_alert, &zero_key_records.close_notify, &test_input);
    const stepped = try step(&test_layer, &test_session, @constCast(input), &test_output);
    try testing.expectEqual(input.len, stepped.consumed);
    try testing.expect(test_layer.peer_closed);
    try testing.expect(test_layer.close_sent);
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
