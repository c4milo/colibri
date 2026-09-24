//! The tests of `connection_datagram.zig`: each step decision 60 runs for one datagram, read back
//! off the connection that received it. The datagrams come from the other endpoint's send path,
//! so what is received is what colibri writes.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const tls = @import("tls");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const transport_parameters = @import("../transport_parameters.zig");
const header_write = @import("../packet/packet_header_write.zig");
const invariant = @import("../packet/invariant.zig");
const StreamProvider = @import("../stream/stream_provider.zig").StreamProvider;
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const send = @import("connection_send.zig");
const close_module = @import("connection_close.zig");
const datagram_module = @import("connection_datagram.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const testing = std.testing;

var client: Connection = undefined;
var server: Connection = undefined;
var suite_holder: build_test.RoundTrip = undefined;
var provider_holder: build_test.Fake = undefined;
var send_scratch: send.DefaultScratch = .{};
var scratch: datagram_module.Scratch = undefined;
var datagram: [constants.datagram_len_min]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
/// A later instant, which the idle timer is seen to restart from. Test-only.
const later_ns: u64 = 5_000_000;
const test_max_data: u64 = 1_048_576;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
const flight_octet: u8 = 0x6d;
const flight_len: usize = 40;
const flight: [flight_len]u8 = @splat(flight_octet);
/// A packet number the server never sent, which a client made to acknowledge it. Test-only.
const unsent_number: u64 = 5;
/// A Retry's new connection ID and token. Test-only.
const retry_octet: u8 = 0x2e;
const retry_id: [id_len]u8 = @splat(retry_octet);
const token_octet: u8 = 0x7b;
const token_len: usize = 8;
const retry_token: [token_len]u8 = @splat(token_octet);
const tag_octet: u8 = 0x11;
const tag: [crypto.constants.aead_tag_len]u8 = @splat(tag_octet);
/// A version other than 1, which a Version Negotiation packet can list alone (RFC 9000 §6.2).
const other_version: u32 = 0xff00_001d;
/// The seven bits of a Version Negotiation packet's first octet RFC 8999 §6 leaves free.
const unused_bits: u7 = 0x2a;

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// Two endpoints with the keys of every level in `levels`, in both directions.
fn open_pair(levels: []const Level) void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client, levels);
    open_one(&server, .server, levels);
    // RFC 9000 §8.1: a server sends only after it has received.
    server.path.on_datagram_received(constants.datagram_len_min);
}

fn open_one(connection: *Connection, role: connection_module.Role, levels: []const Level) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for (levels) |level| {
        keys.on_keys_installed(connection, level, .read);
        keys.on_keys_installed(connection, level, .write);
    }
}

fn send_from(connection: *Connection) !send.Sent {
    return try send.send(connection, suite_holder.suite(), provider_holder.provider(), StreamProvider.none(), &send_scratch, &datagram, test_now_ns) orelse error.NothingSent;
}

fn receive_at(connection: *Connection, provider: tls.QuicProvider, len: usize, now_ns: u64) datagram_module.Error!datagram_module.Received {
    return datagram_module.receive(connection, suite_holder.suite(), provider, .{ .octets = datagram[0..len], .now_ns = now_ns, .ecn = .not_ect }, &scratch);
}

fn receive(connection: *Connection, len: usize) datagram_module.Error!datagram_module.Received {
    return receive_at(connection, provider_holder.provider(), len, test_now_ns);
}

test "RFC 9000 §8.1: every datagram counts toward the limit, even one nothing in opens" {
    open_pair(&.{.handshake});
    const received_before = server.path.received;
    // Octets whose first says a short header of a connection ID nothing issued, so nothing opens.
    const garbage_len: usize = 50;
    @memset(datagram[0..garbage_len], 0);
    const received = try receive(&server, garbage_len);
    try testing.expectEqual(0, received.processed);
    try testing.expectEqual(received_before + garbage_len, server.path.received);
}

test "RFC 9000 §13.1, §10.1: a processed packet is recorded and restarts the idle timer" {
    open_pair(&.{.handshake});
    send.owe_probes(&client, .handshake, 1);
    const sent = try send_from(&client);
    const received = try receive_at(&server, provider_holder.provider(), sent.len, later_ns);
    try testing.expectEqual(1, received.processed);
    try testing.expectEqual(sent.packets[0].packet_number, server.space_at(.handshake).received.largest().?);
    try testing.expectEqual(later_ns, server.termination.idle_since_ns);
}

test "RFC 9000 §8.1: a processed Handshake packet validates the client's address" {
    open_pair(&.{ .initial, .handshake });
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    const initial = try send_from(&client);
    try testing.expectEqual(1, (try receive(&server, initial.len)).processed);
    // A server that has read only Initial packets is held to three times what arrived: anyone
    // can send one from an address it does not hold.
    try testing.expect(server.path.send_allowance() < std.math.maxInt(u64));
    provider_holder = .{};
    send.owe_probes(&client, .handshake, 1);
    const sent = try send_from(&client);
    _ = try receive(&server, sent.len);
    // "Once an endpoint has successfully processed a Handshake packet from the peer, it can
    // consider the peer address to have been validated."
    try testing.expectEqual(std.math.maxInt(u64), server.path.send_allowance());
}

test "decision 65: a client's padded Initial PING has the server send its CRYPTO octets again" {
    open_pair(&.{.initial});
    // The server's first flight, which the path loses.
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    _ = try send_from(&server);
    try testing.expectEqual(0, server.crypto_at(.initial).unsent().len);
    // RFC 9002 §6.2.2.1: a client whose PTO fires with no Handshake keys sends an Initial.
    provider_holder = .{};
    send.owe_probes(&client, .initial, 1);
    const probe = try send_from(&client);
    _ = try receive(&server, probe.len);
    try testing.expectEqual(flight_len, server.crypto_at(.initial).unsent().len);
    try testing.expectEqual(1, server.early_crypto_resends);
}

test "RFC 9000 §13.1: a packet whose frames close the connection is not recorded" {
    open_pair(&.{.handshake});
    // The client acknowledges a packet the server never sent (RFC 9000 §13.1).
    _ = client.space_at(.handshake).receive(unsent_number, test_now_ns, true, .not_ect);
    const sent = try send_from(&client);
    try testing.expectError(error.AcknowledgedUnsentPacket, receive(&server, sent.len));
    try testing.expectEqual(null, server.space_at(.handshake).received.largest());
    try testing.expectEqual(test_now_ns, server.termination.idle_since_ns);
}

test "RFC 9001 §4.9.2: HANDSHAKE_DONE confirms a client and discards its Handshake keys" {
    open_pair(&.{ .handshake, .application });
    for ([_]*Connection{ &client, &server }) |connection| connection.handshake_complete = true;
    server.confirm_handshake();
    server.handshake_done.owed = true;
    const sent = try send_from(&server);
    _ = try receive(&client, sent.len);
    try testing.expect(client.handshake_confirmed);
    try testing.expectEqual(keys.State.discarded, client.keys.at(.handshake, .read));
    try testing.expectEqual(1, suite_holder.discards[@intFromEnum(Level.handshake)]);
}

test "RFC 9000 §10.2.2: a CONNECTION_CLOSE ends the walk, and the rest of the datagram is unread" {
    open_pair(&.{ .handshake, .application });
    server.handshake_complete = true;
    // RFC 9000 §10.2.3: before the handshake is confirmed the close goes at both levels.
    close_module.owe(&client, close_module.transport(error_code.internal_error, null));
    const sent = try send_from(&client);
    try testing.expectEqual(2, sent.count);
    const received = try receive(&server, sent.len);
    try testing.expectEqual(1, received.processed);
    try testing.expectEqual(error_code.internal_error, received.close.?.error_code);
    try testing.expectEqual(.draining, server.termination.state);
}

test "RFC 9000 §10.2: a closing endpoint counts a datagram, and a draining one ignores it" {
    open_pair(&.{.handshake});
    send.owe_probes(&client, .handshake, 1);
    const sent = try send_from(&client);
    const received_before = server.path.received;
    server.termination.on_close_sent(test_now_ns, later_ns);
    // RFC 9000 §10.2.1: what arrives is counted, and "not required to process any received frame".
    const closing = try receive(&server, sent.len);
    try testing.expectEqual(0, closing.processed);
    try testing.expectEqual(1, server.termination.packets_received_closing);
    try testing.expectEqual(received_before, server.path.received);
    // RFC 9000 §10.2.2: a draining endpoint changes nothing.
    open_pair(&.{.handshake});
    server.termination.on_close_received(test_now_ns, later_ns);
    const draining = try receive(&server, sent.len);
    try testing.expectEqual(0, draining.processed);
    try testing.expectEqual(0, server.termination.packets_received_closing);
}

/// A provider that records what it was handed and answers the parameters and completion a test
/// sets. Test-only.
const Recorder = struct {
    taken: [flight_len]u8 = @splat(0),
    taken_len: usize = 0,
    peer_body: []const u8 = "",
    done: bool = false,
    /// A level whose keys the octets it is handed produce, which it gives the suite at once, as a
    /// caller's code moves TLS's secrets to its suite (decision 48).
    makes_available: ?Level = null,

    fn provider(self: *Recorder) tls.QuicProvider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }
    fn set_params(_: *anyopaque, _: []const u8) tls.quic_provider.TransportParamsError!void {}
    fn peer_params(context: *const anyopaque) ?[]const u8 {
        const self: *const Recorder = @ptrCast(@alignCast(context));
        return if (self.peer_body.len == 0) null else self.peer_body;
    }
    fn provide(context: *anyopaque, _: Level, data: []const u8) tls.quic_provider.ProvideError!void {
        const self: *Recorder = @ptrCast(@alignCast(context));
        @memcpy(self.taken[self.taken_len..][0..data.len], data);
        self.taken_len += data.len;
        if (self.makes_available) |level| suite_holder.available[@intFromEnum(level)] = @splat(true);
    }
    fn write(_: *anyopaque, _: Level, _: []u8) tls.quic_provider.WriteError!usize {
        return 0;
    }
    fn alpn(_: *const anyopaque) ?[]const u8 {
        return null;
    }
    fn complete(context: *const anyopaque) bool {
        const self: *const Recorder = @ptrCast(@alignCast(context));
        return self.done;
    }
    fn alert_of(_: *anyopaque) ?tls.Alert {
        return null;
    }
    fn exported(_: *anyopaque, _: []const u8, _: ?[]const u8, _: []u8) tls.quic_provider.ExportError!void {
        // RFC 9846 §7.5 standardises the exporter without obliging a stack to offer one.
        return error.Unsupported;
    }
    const table: tls.QuicVTable = .{
        .set_transport_params = set_params,
        .peer_transport_params = peer_params,
        .provide_handshake = provide,
        .write_handshake = write,
        .negotiated_alpn = alpn,
        .handshake_complete = complete,
        .take_alert = alert_of,
        .export_keying_material = exported,
    };
};

var recorder: Recorder = .{};
/// The client's transport parameters as its ClientHello would carry them (RFC 9001 §8.2).
var client_body: [constants.datagram_len_min]u8 = undefined;

test "RFC 9001 §4.1.3, §8.2, §4.1.1: the provider takes what arrived and the handshake completes" {
    open_pair(&.{.initial});
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    const sent = try send_from(&client);
    var writer = Writer.init(&client_body);
    try transport_parameters.write(&writer, &client.local_parameters, .client);
    recorder = .{ .peer_body = writer.written(), .done = true };
    const received = try receive_at(&server, recorder.provider(), sent.len, test_now_ns);
    try testing.expectEqualSlices(u8, &flight, recorder.taken[0..recorder.taken_len]);
    try testing.expect(server.peer_parameters != null);
    // RFC 9001 §4.1.2: a server confirms when it completes, and owes the client HANDSHAKE_DONE.
    try testing.expect(received.handshake_completed);
    try testing.expect(server.handshake_confirmed);
    try testing.expect(server.handshake_done.owed);
}

test "decision 62: a Handshake packet behind the Initial that made its keys opens in one call" {
    open_pair(&.{.initial});
    keys.on_keys_installed(&client, .handshake, .read);
    keys.on_keys_installed(&client, .handshake, .write);
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    send.owe_probes(&client, .handshake, 1);
    const sent = try send_from(&client);
    try testing.expectEqual(2, sent.count);
    // RFC 9001 §4.1.4: the server has no Handshake keys until TLS has read the Initial's octets.
    recorder = .{ .makes_available = .handshake };
    const received = try receive_at(&server, recorder.provider(), sent.len, test_now_ns);
    try testing.expectEqual(2, received.processed);
    try testing.expectEqual(sent.packets[1].packet_number, server.space_at(.handshake).received.largest().?);
}

test "decision 62: a 1-RTT packet behind the packet that completes the handshake opens" {
    open_pair(&.{ .initial, .handshake, .application });
    client.handshake_complete = true;
    send.owe_probes(&client, .handshake, 1);
    send.owe_probes(&client, .application, 1);
    const sent = try send_from(&client);
    try testing.expectEqual(2, sent.count);
    var writer = Writer.init(&client_body);
    try transport_parameters.write(&writer, &client.local_parameters, .client);
    recorder = .{ .peer_body = writer.written(), .done = true };
    // RFC 9001 §5.7: no 1-RTT packet is opened before the handshake completes, and here it
    // completes with the packet ahead of it.
    const received = try receive_at(&server, recorder.provider(), sent.len, test_now_ns);
    try testing.expect(received.handshake_completed);
    try testing.expectEqual(2, received.processed);
    try testing.expectEqual(sent.packets[1].packet_number, server.space_at(.application).received.largest().?);
}

test "decision 62: receive marks the Initial keys the caller gave the suite before it" {
    open_pair(&.{});
    keys.on_keys_installed(&client, .initial, .write);
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    const sent = try send_from(&client);
    // RFC 9001 §5.2: the server's caller derived the Initial keys from the client's connection
    // ID before it handed colibri the datagram.
    suite_holder.available[@intFromEnum(Level.initial)] = @splat(true);
    recorder = .{};
    const received = try receive_at(&server, recorder.provider(), sent.len, test_now_ns);
    try testing.expectEqual(1, received.processed);
}

test "decision 62: send marks the keys the suite holds, and never a level colibri discarded" {
    open_pair(&.{.initial});
    client.keys.mark_discarded(.application);
    suite_holder.available = @splat(@splat(true));
    // RFC 9001 §4.1.4: "TLS indicates to QUIC that reading or writing keys at that encryption
    // level are available", one direction at a time.
    suite_holder.available[@intFromEnum(Level.handshake)][@intFromEnum(crypto.suite.Direction.read)] = false;
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    _ = try send_from(&client);
    try testing.expectEqual(keys.State.none, client.keys.at(.handshake, .read));
    try testing.expectEqual(keys.State.available, client.keys.at(.handshake, .write));
    // RFC 9001 §4.9: a discarded level stays discarded whatever the suite answers.
    try testing.expectEqual(keys.State.discarded, client.keys.at(.application, .write));
}

test "RFC 9000 §6.2: a Version Negotiation packet is the whole datagram and goes to its function" {
    open_pair(&.{.initial});
    var writer = Writer.init(&datagram);
    // The answer to the client's Initial, whose connection IDs RFC 8999 §6 swaps.
    const answered: invariant.Long = .{ .first_octet = 0xc0, .version = constants.version_1, .dcid = &peer_id, .scid = &local_id, .rest = &.{} };
    try invariant.write_version_negotiation(&writer, unused_bits, answered, &.{other_version});
    const received = try receive(&client, writer.written().len);
    try testing.expectEqual(.abandon, received.version_negotiation.?);
    try testing.expectEqual(0, received.processed);
}

/// A suite that takes any Retry tag and records the Initial keys it is told to derive. Only the
/// two calls a Retry makes are reachable. Test-only.
const RetrySuite = struct {
    installed: [id_len]u8 = @splat(0),
    installs: usize = 0,
    refuses: bool = false,

    fn suite(self: *RetrySuite) crypto.Suite {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }
    fn install(context: *anyopaque, _: crypto.suite.Role, dcid: []const u8) crypto.suite.InstallError!void {
        const self: *RetrySuite = @ptrCast(@alignCast(context));
        // RFC 9001 §5: "Initial packets use AEAD_AES_128_GCM", which a suite without it cannot
        // derive keys for (invariant 25).
        if (self.refuses) return error.Unsupported;
        @memcpy(self.installed[0..dcid.len], dcid);
        self.installs += 1;
    }
    fn tag_valid(_: *const anyopaque, _: []const u8, _: *const [crypto.constants.aead_tag_len]u8) bool {
        return true;
    }
    /// The test marks the client's levels itself, so the suite reports holding none.
    fn none_available(_: *const anyopaque, _: Level, _: crypto.suite.Direction) bool {
        return false;
    }
    fn unreached_seal(_: *anyopaque, _: crypto.suite.Sealing, _: []u8) crypto.suite.SealError!usize {
        unreachable;
    }
    fn unreached_open(_: *anyopaque, _: crypto.suite.Opening) crypto.suite.OpenError!crypto.suite.Opened {
        unreachable;
    }
    fn unreached_tag_write(_: *const anyopaque, _: []const u8, _: *[crypto.constants.aead_tag_len]u8) crypto.suite.RetryTagError!void {
        unreachable;
    }
    fn unreached_token_write(_: *anyopaque, _: []const u8, _: u64, _: []u8) crypto.suite.TokenError!usize {
        unreachable;
    }
    fn unreached_token_valid(_: *const anyopaque, _: []const u8, _: []const u8, _: u64) bool {
        unreachable;
    }
    fn unreached_update(_: *anyopaque) crypto.suite.UpdateError!void {
        unreachable;
    }
    fn unreached_phase(_: *const anyopaque) bool {
        unreachable;
    }
    fn unreached_discard_previous(_: *anyopaque) void {
        unreachable;
    }
    fn unreached_discard(_: *anyopaque, _: Level) void {
        unreachable;
    }
    const table: crypto.suite.VTable = .{
        .install_initial_keys = install,
        .keys_available = none_available,
        .seal = unreached_seal,
        .open = unreached_open,
        .retry_tag_valid = tag_valid,
        .retry_tag_write = unreached_tag_write,
        .retry_token_write = unreached_token_write,
        .retry_token_valid = unreached_token_valid,
        .update_keys = unreached_update,
        .key_phase = unreached_phase,
        .discard_previous_keys = unreached_discard_previous,
        .discard_keys = unreached_discard,
    };
};

var retry_suite: RetrySuite = .{};

/// A Retry answering the client's first Initial (RFC 9000 §17.2.5.1), written into `datagram`.
fn write_retry() !usize {
    var writer = Writer.init(&datagram);
    try header_write.write_retry(&writer, .{ .unused_bits = 0, .dcid = &local_id, .scid = &retry_id, .token = &retry_token });
    try writer.write_bytes(&tag);
    return writer.written().len;
}

fn receive_retry(len: usize) datagram_module.Error!datagram_module.Received {
    return datagram_module.receive(&client, retry_suite.suite(), provider_holder.provider(), .{ .octets = datagram[0..len], .now_ns = test_now_ns, .ecn = .not_ect }, &scratch);
}

test "RFC 9001 §5.2: a Retry the client takes derives the Initial keys from its connection ID" {
    open_pair(&.{.initial});
    retry_suite = .{};
    const received = try receive_retry(try write_retry());
    try testing.expect(received.retry.? == .taken);
    try testing.expectEqualSlices(u8, &retry_id, &retry_suite.installed);
    // A suite that will not derive them leaves no Initial packet to send, which closes.
    open_pair(&.{.initial});
    retry_suite = .{ .refuses = true };
    try testing.expectError(error.InitialKeysRefused, receive_retry(try write_retry()));
    try testing.expectEqual(error_code.internal_error, datagram_module.connection_error_code(&client, error.InitialKeysRefused));
    // A Retry to a server is discarded by §17.2.5's own rules, and derives nothing.
    retry_suite = .{};
    const refused = try datagram_module.receive(&server, retry_suite.suite(), provider_holder.provider(), .{ .octets = datagram[0..try write_retry()], .now_ns = test_now_ns, .ecn = .not_ect }, &scratch);
    try testing.expect(refused.retry.? == .discarded);
    try testing.expectEqual(0, retry_suite.installs);
}

test "RFC 9000 §20.1: each refusal closes with the code its piece names" {
    open_pair(&.{.initial});
    // RFC 9001 §6.6: past the integrity limit the close is AEAD_LIMIT_REACHED.
    try testing.expectEqual(error_code.aead_limit_reached, datagram_module.connection_error_code(&client, error.AeadLimitReached));
    // RFC 9000 §4.1's FLOW_CONTROL_ERROR, through the frame layer.
    try testing.expectEqual(error_code.flow_control_error, datagram_module.connection_error_code(&client, error.FlowControl));
    // RFC 9001 §4.8: an alert's description added to 0x0100, which is 0x0128 for
    // handshake_failure (40).
    client.tls_alert = .handshake_failure;
    try testing.expectEqual(0x0128, datagram_module.connection_error_code(&client, error.TlsAlert));
}
