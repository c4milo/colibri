//! A QUIC chapulin session behind colibri's `tls_provider.QuicProvider` (decision 94): the
//! handshake half of one session, whose packet protection half is `quic_suite.zig`. One chapulin
//! session is both: RFC 9001 §4.1.4 has TLS produce the secrets packet protection uses, and
//! decision 48 keeps them inside the object that derived them.
//!
//! The two roles hand out handshake octets differently. A chapulin client stages one message at a
//! level and the caller pulls it with `cryptoOut`; a server pushes its flight through
//! `on_crypto_out` as it writes it, because one Certificate message is larger than a staging
//! buffer. Both land in `State.outgoing`, one buffer per level, and `write_handshake` hands colibri
//! what waits there. A client's message is pulled the moment chapulin stages it, because chapulin
//! takes no more octets while one is staged.
//!
//! Each vtable member is a one-line call into a function below that takes the role's session as
//! `anytype`: a `Client` or a `Server` of `quic.zig`, each with `session`, `chosen` and `state`.
const std = @import("std");
const assert = std.debug.assert;
const tls_provider = @import("tls_provider");
const chapulin = @import("chapulin_quic");
const constants = @import("../constants.zig");

const c = chapulin.c;
const provider_module = tls_provider.quic_provider;
const Level = tls_provider.Level;
const level_count = chapulin.quic.level_count;

comptime {
    // RFC 9001 §4.1.4: colibri's levels are chapulin's, value for value.
    assert(level_count == tls_provider.core.levels_count);
    for ([_]Level{ .initial, .handshake, .application }) |level| {
        assert(@intFromEnum(level) == @intFromEnum(@field(chapulin.quic.Level, @tagName(level))));
    }
}

/// chapulin's name for a level colibri names.
pub fn level_of(level: Level) chapulin.quic.Level {
    return @enumFromInt(@intFromEnum(level));
}

/// What the provider keeps beside chapulin's session.
pub const State = struct {
    /// This endpoint's transport parameters, which chapulin borrows for the session (RFC 9001
    /// §8.2).
    local_parameters: [c.CH_TRANSPORT_PARAMS_MAX]u8 = undefined,
    /// The peer's, which chapulin copies here as they arrive.
    peer_parameters: [constants.transport_parameters_len_max]u8 = undefined,
    /// The handshake octets at each level that colibri has not taken yet, and how many it took.
    outgoing: [level_count][constants.crypto_out_len]u8 = undefined,
    outgoing_len: [level_count]usize = @splat(0),
    outgoing_taken: [level_count]usize = @splat(0),
    /// Whether chapulin's session started, which it does when it is given the parameters.
    started: bool = false,
    /// Whether colibri has been told of the alert that ended the session.
    alert_taken: bool = false,
    /// Whether a level's buffer could not hold what chapulin wrote, which fails the handshake.
    overflowed: bool = false,
    /// What a `KEYLOG=on` object's `ch_keylog` reads back through `chapulin.hookContext`.
    keylog_context: ?*anyopaque = null,
};

/// The vtable for a role's session type `Held`.
pub fn Provider(comptime Held: type) type {
    return struct {
        pub const vtable: provider_module.VTable = .{
            .set_transport_params = set_transport_params,
            .peer_transport_params = peer_transport_params,
            .provide_handshake = provide_handshake,
            .write_handshake = write_handshake,
            .negotiated_alpn = negotiated_alpn,
            .handshake_complete = handshake_complete,
            .take_alert = take_alert,
            .export_keying_material = export_keying_material,
        };

        fn held(context: *anyopaque) *Held {
            return @ptrCast(@alignCast(context));
        }

        fn held_const(context: *const anyopaque) *const Held {
            return @ptrCast(@alignCast(context));
        }

        fn set_transport_params(context: *anyopaque, body: []const u8) provider_module.TransportParamsError!void {
            return start_session(held(context), body);
        }

        fn peer_transport_params(context: *const anyopaque) ?[]const u8 {
            const role = held_const(context);
            if (!role.state.started) return null;
            // A body longer than the session keeps is reported as none, which colibri refuses
            // (RFC 9001 §8.2).
            return role.session.peerTransportParams() catch null;
        }

        fn provide_handshake(context: *anyopaque, level: Level, data: []const u8) provider_module.ProvideError!void {
            return provide(held(context), level, data);
        }

        fn write_handshake(context: *anyopaque, level: Level, output: []u8) provider_module.WriteError!usize {
            return hand_over(&held(context).state, level, output);
        }

        fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
            const role = held_const(context);
            if (!role.state.started) return null;
            return role.session.alpnSelected();
        }

        /// RFC 9001 §4.1.1: chapulin reports connected once it has sent its Finished and verified
        /// the peer's.
        fn handshake_complete(context: *const anyopaque) bool {
            const role = held_const(context);
            return role.state.started and role.session.state() == .connected;
        }

        fn take_alert(context: *anyopaque) ?tls_provider.Alert {
            return failure_alert(held(context));
        }
    };
}

/// RFC 9001 §8.2: the parameters travel in the first message each side writes, so chapulin's
/// session starts when it is given them.
fn start_session(role: anytype, body: []const u8) provider_module.TransportParamsError!void {
    const state = &role.state;
    // RFC 9001 §4.1.3: the parameters come before the handshake starts.
    if (state.started) return error.HandshakeStarted;
    // RFC 9001 §8.2: parameters longer than chapulin's `CH_TRANSPORT_PARAMS_MAX` fit no message.
    if (body.len > state.local_parameters.len) return error.TlsFailed;
    @memcpy(state.local_parameters[0..body.len], body);
    const local = state.local_parameters[0..body.len];
    state.started = true;
    const started = if (@TypeOf(role.*).is_client)
        role.session.init(role.chosen, local, &state.peer_parameters)
    else
        role.session.init(role.chosen, local, &state.peer_parameters, &role.server_name);
    // RFC 9001 §4.8: chapulin refused the values, which fails the handshake before it starts.
    started catch return error.TlsFailed;
    // chapulin's `init` clears the hook, and a `KEYLOG=on` object reads it from here on.
    role.session.hook.context = state.keylog_context;
    // RFC 9001 §4.1.3: a client's ClientHello is staged now.
    if (@TypeOf(role.*).is_client) pull_staged(role);
}

/// Hands chapulin what colibri reassembled at `level`.
fn provide(role: anytype, level: Level, data: []const u8) provider_module.ProvideError!void {
    const state = &role.state;
    // RFC 9001 §4.1.3: nothing is read before the session starts.
    if (!state.started) return error.WrongLevel;
    const result = if (@TypeOf(role.*).is_client) client_in(role, level, data) else server_in(role, level, data);
    // RFC 9001 §4.1.3: a message larger than a level's buffer is the provider's limit.
    if (state.overflowed) return error.NoSpaceLeft;
    // chapulin refuses a message longer than 2^14 octets as the peer's error, and answers a
    // capacity error only for one its buffer could not hold, which `receive_len` rules out.
    result catch |failure| switch (failure) {
        // chapulin answers Invalid and changes nothing for octets at a level it is not reading
        // yet (RFC 9001 §4.1.3), and fails the session for every other refusal.
        error.Invalid => if (role.session.state() != .failed) return error.WrongLevel else return error.TlsFailed,
        // RFC 9001 §4.8: every other refusal is a TLS alert.
        else => return error.TlsFailed,
    };
}

fn client_in(role: anytype, level: Level, data: []const u8) !void {
    defer pull_staged(role);
    return role.session.cryptoIn(level_of(level), data);
}

fn server_in(role: anytype, level: Level, data: []const u8) !void {
    const state = &role.state;
    var outgoing: chapulin.quic.Outgoing = .{ .buffers = undefined };
    for (&outgoing.buffers, &state.outgoing, state.outgoing_len) |*buffer, *storage, len| buffer.* = storage[len..];
    defer for (&state.outgoing_len, outgoing.written) |*len, written| {
        len.* += written;
    };
    role.session.cryptoIn(level_of(level), data, &outgoing) catch |failure| {
        // chapulin fails a flight that does not fit the buffers it was given (`on_crypto_out`).
        if (failure == error.Io) state.overflowed = true;
        return failure;
    };
}

/// Pulls the message a client staged, at whichever level it is owed.
fn pull_staged(role: anytype) void {
    const state = &role.state;
    // Bounded by the levels, of which RFC 9001 §4.1.4 names three.
    for (&state.outgoing, &state.outgoing_len, 0..) |*storage, *len, level| {
        const room = storage[len.*..];
        // chapulin refuses a capacity of 0, and nothing is staged at a level that owes nothing.
        const written = role.session.cryptoOut(@enumFromInt(level), room) catch |failure| {
            if (failure == error.Cap) state.overflowed = true;
            continue;
        };
        assert(written <= room.len);
        len.* += written;
    }
}

/// Hands colibri what waits at `level`, as much as `output` holds.
fn hand_over(state: *State, level: Level, output: []u8) provider_module.WriteError!usize {
    // RFC 9001 §4.1.3: a flight that did not fit was not written whole.
    if (state.overflowed) return error.NoSpaceLeft;
    const index = @intFromEnum(level);
    const waiting = state.outgoing[index][state.outgoing_taken[index]..state.outgoing_len[index]];
    const len = @min(waiting.len, output.len);
    @memcpy(output[0..len], waiting[0..len]);
    state.outgoing_taken[index] += len;
    if (state.outgoing_taken[index] == state.outgoing_len[index]) {
        state.outgoing_len[index] = 0;
        state.outgoing_taken[index] = 0;
    }
    return len;
}

/// RFC 9001 §4.8: the alert behind a failed session, once.
fn failure_alert(role: anytype) ?tls_provider.Alert {
    const state = &role.state;
    if (state.alert_taken or !state.started or role.session.state() != .failed) return null;
    const description = role.session.alert() orelse return null;
    state.alert_taken = true;
    return @enumFromInt(description);
}

/// chapulin's exporter is a record-layer call, and its build refuses `EXPORTER=on` with
/// `TRANSPORT=quic-nonblocking`.
fn export_keying_material(context: *anyopaque, label: []const u8, context_value: ?[]const u8, output: []u8) provider_module.ExportError!void {
    _ = .{ context, label, context_value, output };
    // RFC 9846 §7.5: an exporter this object does not offer.
    return error.Unsupported;
}
