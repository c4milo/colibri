//! The TLS layer of design §9's client, which `tools/h2_interop.sh` runs against other
//! implementations' servers over TLS (design §8 step 5): the handshake over colibri's
//! `tls.record.Client` (design §8 step 16b), then the record half the server shares,
//! `records.zig`. `client/client_loop.zig` reads and writes the socket around it.
//!
//! The client offers `h2` and then `http/1.1` through ALPN, or `http/1.1` alone, as decision 88
//! orders them, and once the handshake completes the session speaks what the server selected
//! (design §8 step 15d).
//!
//! No call here waits: `handshake` takes the octets the socket read and writes what the client
//! owes the server, so the connection stays one of the loop's connections (decision 46).
//!
//! The session is stepped only once `attach_tls` accepts the finished handshake. RFC 9113 §3.4
//! makes the connection preface the first h2 octet a client sends, and RFC 9112 §9.7 has an h11
//! client send its first request once the handshake has finished.
const std = @import("std");
const tls = @import("tls");
const constants = @import("../constants.zig");
const check_file = @import("check_file.zig");
const session_module = @import("../session.zig");
const client_session = @import("../client/client_session.zig");
const tls_records = @import("records.zig");

const Session = client_session.Session;

/// Why a connection ends here. The socket around it closes it either way.
pub const Error = tls.record.Error || tls_records.AttachError || tls_records.Error;

/// What every connection of a run shares, loaded once: the configuration its sessions borrow, and
/// the instant the server's chain is judged at, which the run was given.
pub const Shared = struct {
    config: *const tls.record.ClientConfig,
    now_seconds: u64,
};

/// The root the client trusts, read once from the files `tools/h2_interop/tls_identity.go` wrote:
/// its Subject Name and its SubjectPublicKeyInfo, each a whole DER TLV, and the configuration
/// converted from them.
pub const Anchors = struct {
    name: [constants.tls_der_len_max]u8,
    spki: [constants.tls_der_len_max]u8,
    anchors: [1]tls.Anchor,
    config: tls.record.ClientConfig,
};

/// What a run does once before its first connection: reads the root `prefix` names into `storage`,
/// and converts it, the name the server's certificate must carry and the protocols to offer.
pub fn load(storage: *Anchors, prefix: []const u8, hostname: []const u8, now_seconds: u64, protocols: []const []const u8) !Shared {
    const name = try check_file.read_part(prefix, ".name", &storage.name);
    const spki = try check_file.read_part(prefix, ".spki", &storage.spki);
    storage.anchors[0] = .{ .subject = name, .spki = spki };
    try storage.config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &storage.anchors, .server_name = hostname } },
        .alpn = protocols,
    });
    return .{ .config = &storage.config, .now_seconds = now_seconds };
}

/// One connection's TLS state, in static storage `client/client_loop.zig` places.
pub const Layer = struct {
    client: tls.record.Client,
    /// The protocol's byte stream in both directions, once the handshake completes.
    records: tls_records.Records,
    /// Whether `attach_tls` accepted the finished handshake.
    attached: bool,
};

pub const Step = tls_records.Step;

/// Prepares a layer for a connection whose connect is in flight, with its ClientHello staged.
pub fn start(layer: *Layer, shared: *const Shared) Error!void {
    try layer.client.start(shared.config, shared.now_seconds, null);
    layer.records.reset();
    layer.attached = false;
}

/// Wipes what the layer's session still holds, once its connection is over, whether it closed or
/// failed.
pub fn finish(layer: *Layer) void {
    layer.client.close();
}

/// Whether `finish` has wiped the layer's session, for the client's tests.
pub fn wiped(layer: *const Layer) bool {
    return layer.client.session.recordState() == .closed;
}

/// Prints why a connection's TLS failed, and the alert the session chose. It runs once for a
/// failed connection, never for each record.
pub fn print_failure(layer: *const Layer, index: usize, failure: Error) void {
    std.debug.print("connection={d} tls_error={t} alert={?d}\n", .{ index, failure, layer.client.alert() });
}

/// Runs the handshake over what the socket read until it completes, then the record half.
pub fn step(layer: *Layer, session: *Session, input: []u8, output: []u8) Error!Step {
    var taken: Step = .{ .consumed = 0, .written = 0, .done = false };
    if (!layer.attached) {
        const progress = try layer.client.handshake(input, output);
        taken.consumed = progress.consumed;
        taken.written = progress.written;
        if (!progress.complete) return taken;
        const provider = layer.client.provider();
        // RFC 7301 §3.2: the protocol the server selected is definitive for the connection, and a
        // selection of none is h11 (decision 88). Over TLS the scheme is "https" (RFC 9110
        // §4.2.2).
        session.choose(session_module.protocol_of(provider.vtable.negotiated_alpn(provider.context)), "https");
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
const h2 = @import("h2");
const tls_provider = @import("tls_provider");
const client_exchange = @import("../client/client_exchange.zig");
const support = @import("records_test_support.zig");

/// A layer, a session and the configuration the tests drive, outside any stack frame. Test-only.
var test_layer: Layer align(@alignOf(Layer)) = undefined;
var test_session: Session align(@alignOf(Session)) = undefined;
var test_config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var test_provider: support.PlainProvider align(@alignOf(support.PlainProvider)) = undefined;
var test_output: [constants.write_buffer_len]u8 = undefined;
const test_plans = [_]client_exchange.Plan{.{ .method = "GET", .path = "/", .content_len = 0 }};

/// One anchor whose name and key are each an empty DER SEQUENCE. No test here reaches a
/// certificate. Test-only.
const test_der = [_]u8{ der_sequence_tag, 0 };
const der_sequence_tag: u8 = 0x30;
const test_anchors = [_]tls.Anchor{.{ .subject = &test_der, .spki = &test_der }};
/// An instant chapulin accepts. A constant because no file under `src/` may read a clock.
/// Test-only.
const test_now_seconds: u64 = 1_780_000_000;

fn test_shared() !Shared {
    try test_config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &test_anchors, .server_name = "localhost" } },
        .alpn = &session_module.alpn_both,
    });
    return .{ .config = &test_config, .now_seconds = test_now_seconds };
}

/// RFC 9846 §4: the HandshakeType of a ClientHello. Test-only.
const handshake_client_hello: u8 = 1;

test "RFC 9113 §3.4: the ClientHello goes out first, and no h2 octet before the handshake ends" {
    test_session.init(.h2, "https", "localhost", &test_plans);
    const shared = try test_shared();
    try start(&test_layer, &shared);
    const stepped = try step(&test_layer, &test_session, &.{}, &test_output);
    // RFC 9846 §5.1: one plaintext handshake record carrying the ClientHello.
    try testing.expectEqual(support.content_handshake, test_output[0]);
    try testing.expectEqual(handshake_client_hello, test_output[tls_provider.constants.record_header_len]);
    try testing.expect(stepped.written > tls_provider.constants.record_header_len);
    try testing.expect(!stepped.done);
    // The session has not been stepped, so its preface waits for the handshake.
    try testing.expect(!test_layer.attached);
    try testing.expectEqual(0, test_session.h2.now_ns);
    finish(&test_layer);
    try testing.expect(wiped(&test_layer));
}

test "RFC 9846 §6: a server flight the client refuses ends the connection" {
    test_session.init(.h2, "https", "localhost", &test_plans);
    const shared = try test_shared();
    try start(&test_layer, &shared);
    _ = try step(&test_layer, &test_session, &.{}, &test_output);
    // RFC 9846 §4.1.3: a handshake record holding a ServerHello whose body is empty.
    var hello = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00 };
    try testing.expectError(error.HandshakeFailed, step(&test_layer, &test_session, &hello, &test_output));
    try testing.expect(!test_layer.attached);
    finish(&test_layer);
}

test "RFC 9113 §3.4: once connected, the client's preface is the first record it seals" {
    test_session.init(.h2, "https", "localhost", &test_plans);
    test_layer.records.reset();
    test_provider = .{ .alpn = &tls_provider.constants.alpn_h2 };
    try tls_records.attach(&test_session, test_provider.provider());
    test_layer.attached = true;
    const stepped = try step(&test_layer, &test_session, &.{}, &test_output);
    const first = support.open(test_output[0..stepped.written]).?;
    try testing.expectEqual(support.content_application_data, first.content_type);
    try testing.expect(std.mem.startsWith(u8, first.content, h2.constants.client_preface));
}
