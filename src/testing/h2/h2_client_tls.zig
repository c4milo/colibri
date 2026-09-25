//! The TLS layer of design §9's h2 client, which `tools/h2_interop.sh` runs against other
//! implementations' servers over TLS (design §8 step 5): the handshake over chapulin's
//! record-mode client, then the record half the server shares, `h2_tls_records.zig`.
//! `client/client_loop.zig` reads and writes the socket around it.
//!
//! No call here waits: `handshake` takes the octets the socket read and writes what the client
//! owes the server, so the connection stays one of the loop's connections (decision 46).
//!
//! The session is stepped only once `attach_tls` accepts the finished handshake. RFC 9113 §3.4
//! makes the connection preface the first h2 octet a client sends, and over TLS it follows the
//! handshake.
const std = @import("std");
const h2 = @import("h2");
const constants = @import("../constants.zig");
const chapulin = @import("../tls/chapulin.zig");
const chapulin_client = @import("../tls/chapulin_client.zig");
const check_file = @import("../tls/check_file.zig");
const h2_client_session = @import("h2_client_session.zig");
const h2_tls_records = @import("h2_tls_records.zig");

const c = chapulin.c;
const Session = h2_client_session.Session;
const connection_tls = h2.connection_tls;

/// Whether the build linked chapulin's client. Without it `Layer` holds nothing, and the client
/// refuses `--tls`.
pub const available = chapulin.available;

/// Why a connection ends here. The socket around it closes it either way.
pub const Error = chapulin_client.Error || connection_tls.AttachError || h2_tls_records.Error;

/// chapulin's trust anchor, which `Shared` holds: a root's Subject Name and SubjectPublicKeyInfo.
pub const Anchor = if (available) c.ch_trust_anchor else struct {};

/// What every connection of a run shares, loaded once: the one root the client trusts, the name
/// the server's certificate must carry, and the instant chapulin judges the chain at.
pub const Shared = if (available) struct {
    anchors: []const Anchor,
    hostname: []const u8,
    now_seconds: u64,
} else struct {};

/// The root the client trusts, read once from the files `tools/h2_interop/tls_identity.go` wrote:
/// its Subject Name and its SubjectPublicKeyInfo, each a whole DER TLV, and the anchor that points
/// at them.
pub const Anchors = if (available) struct {
    name: [constants.tls_der_len_max]u8,
    spki: [constants.tls_der_len_max]u8,
    anchors: [1]c.ch_trust_anchor,
} else struct {};

/// What a run does once before its first connection: checks the linked object, seeds chapulin's
/// generator, and reads the root `prefix` names into `storage`.
pub fn load(storage: *Anchors, prefix: []const u8, hostname: []const u8, now_seconds: u64) !Shared {
    try chapulin.check_build();
    try chapulin.seed_from_entropy();
    const name = try check_file.read_part(prefix, ".name", &storage.name);
    const spki = try check_file.read_part(prefix, ".spki", &storage.spki);
    storage.anchors[0] = .{ .name = name.ptr, .name_len = name.len, .spki = spki.ptr, .spki_len = spki.len };
    return .{ .anchors = &storage.anchors, .hostname = hostname, .now_seconds = now_seconds };
}

/// One connection's TLS state, in static storage `client/client_loop.zig` places.
pub const Layer = if (available) struct {
    client: chapulin_client.Client,
    /// chapulin's receive buffer (`chapulin_client.Options.receive`).
    receive: [constants.tls_receive_len]u8,
    /// h2's byte stream in both directions, once the handshake completes.
    records: h2_tls_records.Records,
    /// Whether `attach_tls` accepted the finished handshake.
    attached: bool,
} else struct {};

pub const Step = h2_tls_records.Step;

/// Prepares a layer for a connection whose connect is in flight, with its ClientHello staged.
pub fn start(layer: *Layer, shared: *const Shared) Error!void {
    layer.client.init(.{
        .anchors = shared.anchors,
        .hostname = shared.hostname,
        .now_seconds = shared.now_seconds,
        .receive = &layer.receive,
    });
    try layer.client.start();
    layer.records.reset();
    layer.attached = false;
}

/// Wipes what the layer's session still holds, once its connection is over, whether it closed or
/// failed (chapulin's `rec.h`).
pub fn finish(layer: *Layer) void {
    layer.client.close();
}

/// The state of the layer's session, and the one `finish` leaves, for the client's tests.
pub fn session_state(layer: *const Layer) u8 {
    return c.ch_record_state(&layer.client.record);
}
pub const chapulin_closed = if (available) c.CH_ST_CLOSED else 0;

/// Prints why a connection's TLS failed: chapulin's code, and the alert it chose. It runs once for
/// a failed connection, never for each record.
pub fn print_failure(layer: *const Layer, index: usize, failure: Error) void {
    std.debug.print("connection={d} tls_error={t} chapulin={s} alert={d}\n", .{
        index,
        failure,
        chapulin_client.reason(layer.client.code),
        layer.client.alert(),
    });
}

/// Runs the handshake over what the socket read until it completes, then the record half.
pub fn step(layer: *Layer, session: *Session, input: []u8, output: []u8) Error!Step {
    var taken: Step = .{ .consumed = 0, .written = 0, .done = false };
    if (!layer.attached) {
        const progress = try layer.client.handshake(input, output);
        taken.consumed = progress.consumed;
        taken.written = progress.written;
        if (!progress.complete) return taken;
        // RFC 9113 §3.2, §9.2: the handshake is checked before any h2 octet moves.
        try session.connection.attach_tls(layer.client.provider());
        layer.attached = true;
    }
    const stepped = try layer.records.step(session, input[taken.consumed..], output[taken.written..]);
    taken.consumed += stepped.consumed;
    taken.written += stepped.written;
    taken.done = stepped.done;
    return taken;
}

const testing = std.testing;
const tls = @import("tls");
const zero_key_records = @import("../tls/zero_key_records.zig");
const chapulin_record = @import("../tls/chapulin_record.zig");
const client_exchange = @import("../client/client_exchange.zig");

/// A layer and a session the tests drive, outside any stack frame. Test-only.
var test_layer: Layer = undefined;
var test_session: Session = undefined;
var test_output: [constants.write_buffer_len]u8 = undefined;
const test_plans = [_]client_exchange.Plan{.{ .method = "GET", .path = "/", .content_len = 0 }};

/// One anchor whose name and key are each an empty DER SEQUENCE. chapulin refuses a configuration
/// with no anchor, and no test here reaches a certificate. Test-only.
const test_der = [_]u8{ der_sequence_tag, 0 };
const der_sequence_tag: u8 = 0x30;
const test_anchors = [_]c.ch_trust_anchor{.{
    .name = &test_der,
    .name_len = test_der.len,
    .spki = &test_der,
    .spki_len = test_der.len,
}};
const test_shared: Shared = .{ .anchors = &test_anchors, .hostname = "localhost", .now_seconds = test_now_seconds };
/// An instant chapulin accepts. A constant because no file under `src/` may read a clock.
/// Test-only.
const test_now_seconds: u64 = 1_780_000_000;

/// RFC 9846 §4: the HandshakeType of a ClientHello. Test-only.
const handshake_client_hello: u8 = 1;

test "RFC 9113 §3.4: the ClientHello goes out first, and no h2 octet before the handshake ends" {
    if (!available) return error.SkipZigTest;
    test_session.init("https", "localhost", &test_plans);
    try start(&test_layer, &test_shared);
    const stepped = try step(&test_layer, &test_session, &.{}, &test_output);
    // RFC 9846 §5.1: one plaintext handshake record carrying the ClientHello.
    try testing.expectEqual(zero_key_records.content_handshake, test_output[0]);
    try testing.expectEqual(handshake_client_hello, test_output[tls.constants.record_header_len]);
    try testing.expect(stepped.written > tls.constants.record_header_len);
    try testing.expect(!stepped.done);
    // The session has not been stepped, so its preface waits for the handshake.
    try testing.expect(!test_layer.attached);
    try testing.expectEqual(0, test_session.now_ns);
    finish(&test_layer);
}

test "RFC 9846 §6: a server flight chapulin refuses ends the connection" {
    if (!available) return error.SkipZigTest;
    test_session.init("https", "localhost", &test_plans);
    try start(&test_layer, &test_shared);
    _ = try step(&test_layer, &test_session, &.{}, &test_output);
    // RFC 9846 §4.1.3: a handshake record holding a ServerHello whose body is empty.
    var hello = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00 };
    try testing.expectError(error.HandshakeFailed, step(&test_layer, &test_session, &hello, &test_output));
    try testing.expect(!test_layer.attached);
    finish(&test_layer);
}

test "RFC 9113 §3.4: once connected, the client's preface is the first record it seals" {
    if (!available) return error.SkipZigTest;
    test_session.init("https", "localhost", &test_plans);
    try start(&test_layer, &test_shared);
    // What a finished handshake leaves, keyed with zeros (`zero_key_records.zig`).
    zero_key_records.connect(&test_layer.client.held, &test_layer.client.record.t, &test_layer.receive);
    try test_session.connection.attach_tls(test_layer.client.provider());
    test_layer.attached = true;
    const stepped = try step(&test_layer, &test_session, &.{}, &test_output);
    const record_len = chapulin_record.whole_record_len(test_output[0..stepped.written]) orelse
        return error.TestUnexpectedResult;
    var inner: [tls.constants.record_plaintext_len_max + 1]u8 = undefined;
    const first = zero_key_records.open(0, test_output[0..record_len], &inner) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(zero_key_records.content_application_data, first.content_type);
    try testing.expect(std.mem.startsWith(u8, first.content, h2.constants.client_preface));
}
