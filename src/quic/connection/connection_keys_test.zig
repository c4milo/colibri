//! The tests of `connection_keys.zig`, split out so a hand-written file stays under 500 lines.
//!
//! What they pin is RFC 9001 §4.9's timing and §5.7's refusal, read against a suite that records
//! what colibri told it to forget. `quic` cannot import `sim` (design §3), so the recording suite
//! is here rather than `src/sim/null_suite.zig`.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const identity_module = @import("connection_identity.zig");
const keys = @import("connection_keys.zig");

const testing = std.testing;
const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

var test_connection: Connection = undefined;
var recorder: Recorder = undefined;

const test_now_ns: u64 = 1_000_000;
const local_id_octet: u8 = 0xc1;
const original_id_octet: u8 = 0x51;
const test_id_len: usize = 8;
const local_id: [test_id_len]u8 = @splat(local_id_octet);
const original_id: [test_id_len]u8 = @splat(original_id_octet);
const test_identity: identity_module.Options = .{
    .local_initial_source = &local_id,
    .original_destination = &original_id,
};

/// A `crypto.Suite` that holds no key and records which levels colibri discarded. Decision 48
/// leaves the keys with the caller, so what a test of timing needs is only the call.
const Recorder = struct {
    discarded: [core.levels_count]usize,

    fn init(held: *Recorder) void {
        held.discarded = @splat(0);
    }

    fn suite(held: *Recorder) crypto.Suite {
        return .{ .context = held, .vtable = &vtable };
    }

    fn count(held: *const Recorder, level: Level) usize {
        return held.discarded[@intFromEnum(level)];
    }

    fn discard_keys(context: *anyopaque, level: Level) void {
        const held: *Recorder = @ptrCast(@alignCast(context));
        held.discarded[@intFromEnum(level)] += 1;
    }

    const vtable: crypto.suite.VTable = .{
        .install_initial_keys = unreachable_install,
        .keys_available = unreachable_available,
        .seal = unreachable_seal,
        .open = unreachable_open,
        .retry_tag_valid = unreachable_tag_valid,
        .retry_tag_write = unreachable_tag_write,
        .update_keys = unreachable_update,
        .key_phase = unreachable_phase,
        .discard_previous_keys = unreachable_discard_previous,
        .discard_keys = discard_keys,
    };
};

/// Every member but `discard_keys` is unreached: this file tests when colibri discards a level,
/// and a call to any other member would mean the test drove something it does not cover.
fn unreachable_install(_: *anyopaque, _: crypto.suite.Role, _: []const u8) crypto.suite.InstallError!void {
    unreachable;
}
fn unreachable_available(_: *const anyopaque, _: Level, _: crypto.suite.Direction) bool {
    unreachable;
}
fn unreachable_seal(_: *anyopaque, _: crypto.suite.Sealing, _: []u8) crypto.suite.SealError!usize {
    unreachable;
}
fn unreachable_open(_: *anyopaque, _: crypto.suite.Opening) crypto.suite.OpenError!crypto.suite.Opened {
    unreachable;
}
fn unreachable_tag_valid(
    _: *const anyopaque,
    _: []const u8,
    _: *const [crypto.constants.retry_integrity_tag_len]u8,
) bool {
    unreachable;
}
fn unreachable_tag_write(
    _: *const anyopaque,
    _: []const u8,
    _: *[crypto.constants.retry_integrity_tag_len]u8,
) crypto.suite.RetryTagError!void {
    unreachable;
}
fn unreachable_update(_: *anyopaque) crypto.suite.UpdateError!void {
    unreachable;
}
fn unreachable_phase(_: *const anyopaque) bool {
    unreachable;
}
fn unreachable_discard_previous(_: *anyopaque) void {
    unreachable;
}

/// Enough connection-level credit that `flow.Receiver` has a window, which it asserts is above
/// zero. Nothing here is bounded by it: these tests are about keys.
const test_max_data: u64 = 1_048_576;

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// A connection with the Initial keys installed in both directions, which is where RFC 9001 §5.2
/// leaves an endpoint that derived them from the Destination Connection ID.
fn open_as(role: crypto.suite.Role) void {
    recorder.init();
    test_connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = test_identity,
    });
    keys.on_keys_installed(&test_connection, .initial, .read);
    keys.on_keys_installed(&test_connection, .initial, .write);
}

test "invariant 21: a connection begins knowing no level at all" {
    open_as(.client);
    // The Initial level is the one `install_initial_keys` produced; the others are not yet the
    // provider's to give (RFC 9001 §4.1.4).
    try testing.expectEqual(keys.State.available, test_connection.keys.at(.initial, .write));
    try testing.expectEqual(keys.State.none, test_connection.keys.at(.handshake, .write));
    try testing.expectEqual(keys.State.none, test_connection.keys.at(.application, .read));
    try testing.expect(!keys.can_seal(&test_connection, .handshake));
}

test "RFC 9001 §4.9.1: a client discards Initial keys when it first sends a Handshake packet" {
    open_as(.client);
    keys.on_keys_installed(&test_connection, .handshake, .write);
    try testing.expect(keys.can_seal(&test_connection, .initial));
    keys.on_handshake_packet_sent(&test_connection, recorder.suite());
    // §4.9.1: "Endpoints MUST NOT send Initial packets after this point."
    try testing.expect(!keys.can_seal(&test_connection, .initial));
    try testing.expectEqual(keys.State.discarded, test_connection.keys.at(.initial, .read));
    try testing.expectEqual(1, recorder.count(.initial));
    // A client sends many Handshake packets and the suite is told once.
    keys.on_handshake_packet_sent(&test_connection, recorder.suite());
    try testing.expectEqual(1, recorder.count(.initial));
}

test "RFC 9001 §4.9.1: a client processing a Handshake packet discards nothing" {
    open_as(.client);
    keys.on_keys_installed(&test_connection, .handshake, .read);
    // §4.9.1 gives each role one trigger and they are not the same one. A client that has read a
    // Handshake packet still owes its own, and §4.9 says keys for a lower level "are needed for a
    // short time after keys for a newer encryption level are available".
    keys.on_handshake_packet_processed(&test_connection, recorder.suite());
    try testing.expectEqual(0, recorder.count(.initial));
    try testing.expect(keys.can_seal(&test_connection, .initial));
    // Its own trigger is what ends the Initial level.
    keys.on_handshake_packet_sent(&test_connection, recorder.suite());
    try testing.expectEqual(1, recorder.count(.initial));
}

test "RFC 9001 §4.9.1: a server discards Initial keys when it first processes one" {
    open_as(.server);
    // The client's trigger is sending; a server sending a Handshake packet discards nothing,
    // because it has no assurance the client can read that level yet.
    keys.on_handshake_packet_sent(&test_connection, recorder.suite());
    try testing.expectEqual(0, recorder.count(.initial));
    try testing.expect(keys.can_seal(&test_connection, .initial));

    keys.on_handshake_packet_processed(&test_connection, recorder.suite());
    try testing.expectEqual(1, recorder.count(.initial));
    try testing.expect(!keys.can_seal(&test_connection, .initial));
}

test "RFC 9001 §4.9.2: the Handshake keys go when the handshake is confirmed" {
    open_as(.server);
    keys.on_keys_installed(&test_connection, .handshake, .read);
    keys.on_keys_installed(&test_connection, .handshake, .write);
    try testing.expect(keys.can_seal(&test_connection, .handshake));
    keys.on_handshake_confirmed(&test_connection, recorder.suite());
    try testing.expect(!keys.can_seal(&test_connection, .handshake));
    try testing.expectEqual(1, recorder.count(.handshake));
    // §4.9.2 names the Handshake keys and no other level.
    try testing.expectEqual(0, recorder.count(.application));
    keys.on_handshake_confirmed(&test_connection, recorder.suite());
    try testing.expectEqual(1, recorder.count(.handshake));
}

test "RFC 9001 §5.7: 1-RTT keys are not permission to read before the handshake completes" {
    open_as(.server);
    keys.on_keys_installed(&test_connection, .application, .read);
    keys.on_keys_installed(&test_connection, .application, .write);
    // §5.7: "the server's use of 1-RTT keys before the handshake is complete is limited to
    // sending data", so the write side is open and the read side is not.
    try testing.expect(keys.can_seal(&test_connection, .application));
    try testing.expect(!keys.can_open(&test_connection, .application, false));
    try testing.expect(keys.can_open(&test_connection, .application, true));
    // The rule is the application level's alone: a Handshake packet is read whenever its keys are
    // there, which is what lets the handshake complete at all.
    keys.on_keys_installed(&test_connection, .handshake, .read);
    try testing.expect(keys.can_open(&test_connection, .handshake, false));
}

test "RFC 9001 §4.9: new data goes out at the highest level that has keys" {
    open_as(.client);
    try testing.expectEqual(Level.initial, keys.highest_sendable(&test_connection).?);
    keys.on_keys_installed(&test_connection, .handshake, .write);
    try testing.expectEqual(Level.handshake, keys.highest_sendable(&test_connection).?);
    keys.on_keys_installed(&test_connection, .application, .write);
    try testing.expectEqual(Level.application, keys.highest_sendable(&test_connection).?);
    // A discarded level is not a level to send at, even though it was the highest before.
    keys.on_handshake_confirmed(&test_connection, recorder.suite());
    try testing.expectEqual(Level.application, keys.highest_sendable(&test_connection).?);
}

test "RFC 9001 §4.9: with every level discarded there is nowhere to send" {
    open_as(.client);
    keys.on_keys_installed(&test_connection, .handshake, .write);
    keys.on_handshake_packet_sent(&test_connection, recorder.suite());
    keys.on_handshake_confirmed(&test_connection, recorder.suite());
    // Both handshake levels are gone and the application level never arrived, which is the state
    // a connection that failed before 1-RTT is left in.
    try testing.expectEqual(null, keys.highest_sendable(&test_connection));
}
