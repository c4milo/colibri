//! A `tls.QuicVTable` that performs no cryptography (decisions 8, 10 and 48, design §8 step 9e).
//! It is test-only, lives in `src/sim/` and is never packaged: colibri's library carries no
//! implementation of either vtable and never will (CLAUDE.md non-negotiable 2).
//!
//! `null_provider.zig` is the record-mode sibling, which serves h2. This one is QUIC mode, where
//! RFC 9001 §4.1.3 replaces the record layer with one flow of handshake octets per encryption
//! level. What it is for is the shape, not the secrecy: a client and a server carry made-up
//! handshake messages at the three levels of RFC 9001 §4.1.4, in the order §4.1.5's Figure 5 puts
//! them, so a check sees colibri move a flight over CRYPTO frames, put back together a message cut
//! in two, and reach §4.1.1's completion. None of it is a real TLS message and none of it is
//! protected.
//!
//! Each message is framed the way RFC 9846 §4 frames one: a one-octet HandshakeType, a uint24
//! length, and the body. The ClientHello and the EncryptedExtensions carry the
//! `quic_transport_parameters` body as their whole content, which is where RFC 9001 §8.2 puts the
//! extension, so a pair exchanges parameters by exchanging those two messages.
//!
//! A test drives the failures. `fails_with` makes the next call raise the alert it names, and a
//! message whose HandshakeType is not the one the script expects raises `unexpected_message` on
//! its own (RFC 9846 §4). Everything else it answers is a state it reached.
//!
//! It reads no clock, draws no random number and allocates nothing, so one seed replays byte for
//! byte (invariants 4, 5 and 6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const tls = @import("tls");
const crypto = @import("crypto");
const constants = @import("constants.zig");

const NullSuite = @import("null_suite.zig").NullSuite;

const Crc32 = std.hash.Crc32;
const Alert = tls.Alert;
const Level = tls.Level;

/// Which endpoint of the connection this is. It is `crypto.suite`'s, so the null provider and the
/// null suite of one endpoint are told apart by the same value.
pub const Role = crypto.suite.Role;

/// The HandshakeType of the messages the null handshake carries (RFC 9846 §4). The four are the
/// ones §4.1.5's Figure 5 moves; the null provider sends no certificate and no session ticket.
pub const MessageType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 8,
    finished = 20,
};

/// One step of a role's handshake: the message, the encryption level it moves at, and whether this
/// endpoint writes it or reads it.
const Step = struct {
    writes: bool,
    level: Level,
    message: MessageType,
};

/// The client's handshake, in the order RFC 9001 §4.1.5's Figure 5 puts it: the ClientHello at the
/// Initial level, the server's flight, and the client's Finished at the Handshake level. §4.1.1
/// makes the last step the one that completes it, because by then the client has sent its own
/// Finished and verified the server's.
const client_script = [_]Step{
    .{ .writes = true, .level = .initial, .message = .client_hello },
    .{ .writes = false, .level = .initial, .message = .server_hello },
    .{ .writes = false, .level = .handshake, .message = .encrypted_extensions },
    .{ .writes = false, .level = .handshake, .message = .finished },
    .{ .writes = true, .level = .handshake, .message = .finished },
};

/// The server's handshake, the same exchange from the other side (RFC 9001 §4.1.5, Figure 5).
const server_script = [_]Step{
    .{ .writes = false, .level = .initial, .message = .client_hello },
    .{ .writes = true, .level = .initial, .message = .server_hello },
    .{ .writes = true, .level = .handshake, .message = .encrypted_extensions },
    .{ .writes = true, .level = .handshake, .message = .finished },
    .{ .writes = false, .level = .handshake, .message = .finished },
};

comptime {
    // The drain loop is bounded by this, so neither script may outgrow it (non-negotiable 4).
    assert(client_script.len <= constants.null_quic_steps_max);
    assert(server_script.len <= constants.null_quic_steps_max);
}

/// The steps of either script whose completion makes a level's secrets (RFC 9001 §4.1.5's Figure
/// 5): the Handshake level's once the ServerHello has been written or read, and the application
/// level's once the server's Finished has.
const handshake_keys_step: u8 = 2;
const application_keys_step: u8 = 4;

/// What one endpoint of the null QUIC provider answers. A test places the struct and fills what it
/// wants before the run; everything else is a state the handshake reaches.
pub const NullQuicProvider = struct {
    /// Which side this endpoint is, which picks the script it follows.
    role: Role = .client,
    /// How many steps of that script are done. The last one done is RFC 9001 §4.1.1's completion.
    step: u8 = 0,
    /// Whether the handshake has started, which RFC 9001 §4.1.3 makes the point after which the
    /// transport parameters can no longer be set.
    started: bool = false,
    /// The `quic_transport_parameters` body colibri encoded (RFC 9001 §8.2), and its length. A
    /// length of zero means colibri gave the provider none.
    params: [constants.null_quic_params_len_max]u8 = @splat(0),
    params_len: usize = 0,
    /// The peer's body, copied into the provider's own storage so the slice `peer_transport_params`
    /// answers stays valid for the life of the connection.
    peer_params: [constants.null_quic_params_len_max]u8 = @splat(0),
    peer_params_len: usize = 0,
    /// Octets received at each level that no step has read yet. RFC 9001 §4.1.3: "TLS is
    /// responsible for buffering handshake bytes that have arrived in order."
    pending: [core.levels_count][constants.null_quic_pending_len_max]u8 = @splat(@splat(0)),
    pending_len: [core.levels_count]usize = @splat(0),
    /// Whether the handshake has selected a protocol yet (RFC 9001 §8.1).
    alpn_selected: bool = false,
    /// The alert held for the next `take_alert`, which the call clears (RFC 9001 §4.8).
    alert_held: ?Alert = null,
    /// The alert a test makes the next `provide_handshake` or `write_handshake` raise, so a check
    /// can drive RFC 9001 §4.8's path. Null runs the handshake.
    fails_with: ?Alert = null,
    /// The suite this endpoint's keys go to, or null when a test moves them itself. A caller's
    /// code gives its suite each level's secrets inside the call that made TLS produce them (RFC
    /// 9001 §4.1.4, decision 48), and colibri asks the suite before the next packet (decision
    /// 62). This field is that code for the null pair.
    suite: ?*NullSuite = null,

    /// The vtable-shaped view colibri holds.
    pub fn provider(self: *NullQuicProvider) tls.QuicProvider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }

    fn of(context: *anyopaque) *NullQuicProvider {
        return @ptrCast(@alignCast(context));
    }

    fn of_const(context: *const anyopaque) *const NullQuicProvider {
        return @ptrCast(@alignCast(context));
    }

    /// The steps this role follows (RFC 9001 §4.1.5, Figure 5).
    fn script(self: *const NullQuicProvider) []const Step {
        return switch (self.role) {
            .client => &client_script,
            .server => &server_script,
        };
    }

    /// The step the handshake is at, or null once every step is done.
    fn current(self: *const NullQuicProvider) ?Step {
        assert(self.step <= self.script().len);
        if (self.step == self.script().len) return null;
        return self.script()[self.step];
    }

    /// RFC 9001 §4.1.1: the handshake is complete once this endpoint has both sent its Finished
    /// and verified the peer's, which is the last step of either script.
    fn is_complete(self: *const NullQuicProvider) bool {
        return self.step == self.script().len;
    }

    /// Whether a step still to come reads at `level`. RFC 9001 §4.1.3 gives each level its own
    /// flow of octets, and a level this endpoint has moved past reads no more.
    fn reads_at(self: *const NullQuicProvider, level: Level) bool {
        for (self.script()[self.step..]) |step| {
            if (!step.writes and step.level == level) return true;
        }
        return false;
    }

    /// Marks the handshake started for the role that starts it there. RFC 9001 §4.1.3: "A QUIC
    /// client starts TLS by requesting TLS handshake bytes from TLS. ... A QUIC server starts the
    /// process by providing TLS with the client's handshake bytes."
    fn note_start(self: *NullQuicProvider, starter: Role) void {
        if (self.role == starter) self.started = true;
    }

    /// Holds `description` for `take_alert` and fails the call. RFC 9001 §4.8 makes every alert
    /// fatal in QUIC, so the description is the whole of what the provider reports.
    fn fail(self: *NullQuicProvider, description: Alert) error{TlsFailed} {
        self.fails_with = null;
        self.alert_held = description;
        return error.TlsFailed;
    }

    fn set_transport_params(
        context: *anyopaque,
        body: []const u8,
    ) tls.quic_provider.TransportParamsError!void {
        const self = of(context);
        // RFC 9001 §4.1.3: "Before starting the handshake, QUIC provides TLS with the transport
        // parameters that it wishes to carry."
        if (self.started) return error.HandshakeStarted;
        if (body.len > self.params.len) return self.fail(.internal_error);
        @memcpy(self.params[0..body.len], body);
        self.params_len = body.len;
        assert(self.params_len <= self.params.len);
    }

    fn peer_transport_params(context: *const anyopaque) ?[]const u8 {
        const self = of_const(context);
        // RFC 9001 §8.2 carries the extension in the ClientHello and in EncryptedExtensions, so a
        // client has none until it has read the server's EncryptedExtensions.
        if (self.peer_params_len == 0) return null;
        // The octets are the provider's own, which is what the vtable asks: the slice stays valid
        // for the life of the connection.
        return self.peer_params[0..self.peer_params_len];
    }

    fn provide_handshake(
        context: *anyopaque,
        level: Level,
        data: []const u8,
    ) tls.quic_provider.ProvideError!void {
        const self = of(context);
        self.note_start(.server);
        if (self.fails_with) |description| return self.fail(description);
        // RFC 9001 §4.1.3: octets at a level this endpoint has moved past "MUST NOT contain data
        // that extends past the end of previously received data in that flow", and a violation is
        // a connection error of type PROTOCOL_VIOLATION.
        if (!self.reads_at(level)) return error.WrongLevel;
        try self.buffer(level, data);
        try self.read_flight();
    }

    /// Adds `data` to the level's own flow (RFC 9001 §4.1.3).
    fn buffer(
        self: *NullQuicProvider,
        level: Level,
        data: []const u8,
    ) tls.quic_provider.ProvideError!void {
        const index = @intFromEnum(level);
        const held = self.pending_len[index];
        assert(held <= self.pending[index].len);
        if (data.len > self.pending[index].len - held) return error.NoSpaceLeft;
        @memcpy(self.pending[index][held..][0..data.len], data);
        self.pending_len[index] = held + data.len;
    }

    /// Reads every whole message the next steps call for. RFC 9001 §4.1.3 leaves TLS to buffer
    /// octets that arrived in order, so a message cut across calls waits here for the rest.
    fn read_flight(self: *NullQuicProvider) tls.quic_provider.ProvideError!void {
        for (0..constants.null_quic_steps_max) |_| {
            const step = self.current() orelse return;
            if (step.writes) return;
            if (!try self.read_message(step)) return;
        }
    }

    /// Reads one whole message of `step` out of its level's flow. False when no whole one is there.
    fn read_message(
        self: *NullQuicProvider,
        step: Step,
    ) tls.quic_provider.ProvideError!bool {
        const index = @intFromEnum(step.level);
        const held = self.pending[index][0..self.pending_len[index]];
        const message = read_framed(held) orelse return false;
        // RFC 9846 §4: "A peer which receives a handshake message in an unexpected order MUST
        // abort the handshake with an 'unexpected_message' alert."
        if (message.kind != @intFromEnum(step.message)) return self.fail(.unexpected_message);
        self.apply(step, message.body);
        self.consume(index, message.total_len);
        self.step += 1;
        self.hand_over_keys();
        return true;
    }

    /// Gives the suite each level's keys once the script has reached the step that makes them.
    fn hand_over_keys(self: *NullQuicProvider) void {
        const suite = self.suite orelse return;
        self.hand_over(suite, .handshake, handshake_keys_step);
        self.hand_over(suite, .application, application_keys_step);
    }

    fn hand_over(self: *const NullQuicProvider, suite: *NullSuite, level: Level, step: u8) void {
        if (self.step < step) return;
        // Once: every step after this one would hand the level over again. colibri discards a
        // level only after the script's last step, so a discarded one never reaches here.
        if (suite.state_of(level, .read) != .none) return;
        suite.install(level);
    }

    /// What reading a message changes besides the cursor.
    fn apply(self: *NullQuicProvider, step: Step, body: []const u8) void {
        // RFC 9001 §8.2: "The quic_transport_parameters extension is carried in the ClientHello
        // and the EncryptedExtensions messages during the handshake." RFC 9846 §4.3's table puts
        // ALPN in the same two, and RFC 9001 §8.1 makes ALPN mandatory in QUIC.
        const carries_extensions =
            step.message == .client_hello or step.message == .encrypted_extensions;
        if (!carries_extensions) return;
        self.alpn_selected = true;
        if (body.len == 0 or body.len > self.peer_params.len) return;
        @memcpy(self.peer_params[0..body.len], body);
        self.peer_params_len = body.len;
    }

    /// Drops the first `taken` octets of a level's flow and keeps the rest in order.
    fn consume(self: *NullQuicProvider, index: usize, taken: usize) void {
        const held = self.pending_len[index];
        assert(taken > 0 and taken <= held);
        const rest = self.pending[index][taken..held];
        std.mem.copyForwards(u8, self.pending[index][0..rest.len], rest);
        self.pending_len[index] = held - taken;
    }

    fn write_handshake(
        context: *anyopaque,
        level: Level,
        output: []u8,
    ) tls.quic_provider.WriteError!usize {
        const self = of(context);
        self.note_start(.client);
        if (self.fails_with) |description| return self.fail(description);
        const step = self.current() orelse return 0;
        // RFC 9001 §4.1.3: handshake octets are appended to the flow of the current sending
        // encryption level, so a level this endpoint owes nothing at writes nothing.
        if (!step.writes or step.level != level) return 0;
        const written = try write_framed(output, step.message, self.body_of(step.message));
        self.step += 1;
        self.hand_over_keys();
        assert(written > 0);
        return written;
    }

    /// What a message carries. RFC 9001 §8.2 puts the `quic_transport_parameters` body in the
    /// ClientHello and in EncryptedExtensions; every other message here carries nothing.
    fn body_of(self: *const NullQuicProvider, message: MessageType) []const u8 {
        return switch (message) {
            .client_hello, .encrypted_extensions => self.params[0..self.params_len],
            .server_hello, .finished => "",
        };
    }

    fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
        const self = of_const(context);
        // RFC 9846 §4.3's table carries ALPN in the ClientHello and in EncryptedExtensions, so
        // there is no selection to report before one of those has been read.
        if (!self.alpn_selected) return null;
        // RFC 9001 §8.1: "endpoints MUST use ALPN", and h3 is what QUIC carries here.
        return &tls.constants.alpn_h3;
    }

    fn handshake_complete(context: *const anyopaque) bool {
        return of_const(context).is_complete();
    }

    fn take_alert(context: *anyopaque) ?Alert {
        const self = of(context);
        // RFC 9001 §4.8: the description alone, because §4.8 makes every alert fatal in QUIC.
        defer self.alert_held = null;
        return self.alert_held;
    }

    fn export_keying_material(
        context: *anyopaque,
        label: []const u8,
        context_value: ?[]const u8,
        output: []u8,
    ) tls.quic_provider.ExportError!void {
        const self = of(context);
        // RFC 9846 §7.5 derives the exporter from exporter_secret, which exists once the handshake
        // has completed.
        if (!self.is_complete()) return error.HandshakeIncomplete;
        // RFC 9846 §7.5: "If no context is provided, the context_value is zero length.
        // Consequently, providing no context computes the same value as providing an empty
        // context."
        write_export(label, context_value orelse "", output);
    }
};

/// The vtable, filled once and shared. Every endpoint in a run uses the same one, which is what
/// `QuicProvider.vtable` being read-only is for.
const table: tls.QuicVTable = .{
    .set_transport_params = NullQuicProvider.set_transport_params,
    .peer_transport_params = NullQuicProvider.peer_transport_params,
    .provide_handshake = NullQuicProvider.provide_handshake,
    .write_handshake = NullQuicProvider.write_handshake,
    .negotiated_alpn = NullQuicProvider.negotiated_alpn,
    .handshake_complete = NullQuicProvider.handshake_complete,
    .take_alert = NullQuicProvider.take_alert,
    .export_keying_material = NullQuicProvider.export_keying_material,
};

/// The HandshakeType and the uint24 length RFC 9846 §4 puts before a message's body.
const header_len: usize = constants.null_quic_message_header_len;
const length_len: usize = constants.null_quic_message_length_len;

/// One framed message, as `read_framed` found it.
const Framed = struct {
    /// RFC 9846 §4's HandshakeType octet, whatever it holds. An octet naming no message of this
    /// handshake is compared against the expected one like any other and fails the same way.
    kind: u8,
    body: []const u8,
    total_len: usize,
};

/// Reads one message out of `held`, or null when `held` holds no whole one yet.
fn read_framed(held: []const u8) ?Framed {
    var reader = core.Reader.init(held);
    // RFC 9846 §4: the HandshakeType, then the uint24 length of what follows it.
    const kind = reader.read_byte() catch return null;
    const body_len = read_length(&reader) catch return null;
    const body = reader.take(body_len) catch return null;
    return .{ .kind = kind, .body = body, .total_len = header_len + body_len };
}

/// Writes one message as RFC 9846 §4 frames it, or refuses when `output` cannot hold all of it.
fn write_framed(output: []u8, kind: MessageType, body: []const u8) error{NoSpaceLeft}!usize {
    // The vtable's `WriteError.NoSpaceLeft` states that nothing was written, so the whole message
    // is measured before any of it goes out.
    if (output.len < header_len + body.len) return error.NoSpaceLeft;
    var writer = core.Writer.init(output);
    try writer.write_byte(@intFromEnum(kind));
    try write_length(&writer, body.len);
    try writer.write_bytes(body);
    return writer.written().len;
}

/// RFC 9846 §4's uint24 length, octet by octet in network byte order.
fn read_length(reader: *core.Reader) core.reader.Error!usize {
    var value: usize = 0;
    for (0..length_len) |_| {
        value = (value << @bitSizeOf(u8)) | try reader.read_byte();
    }
    return value;
}

/// The same field on the way out.
fn write_length(writer: *core.Writer, length: usize) core.writer.Error!void {
    for (0..length_len) |index| {
        const shift: u6 = @intCast((length_len - 1 - index) * @bitSizeOf(u8));
        try writer.write_byte(@truncate(length >> shift));
    }
}

/// RFC 9846 §7.5's exporter, as a checksum rather than the HKDF the section names: the null
/// provider holds no secret, so all it can answer is a function of the inputs. The offset and the
/// label's length are folded in, so two octets of `output` differ and ("ab", "c") is not ("a",
/// "bc"). Every integer goes in octet by octet in network order, so one host's octets are every
/// host's (invariant 5).
fn write_export(label: []const u8, context_value: []const u8, output: []u8) void {
    assert(label.len > 0 and output.len > 0);
    var offset: usize = 0;
    while (offset < output.len) : (offset += @sizeOf(u32)) {
        var crc = Crc32.init();
        crc.update(std.mem.asBytes(&std.mem.nativeToBig(u64, @as(u64, offset))));
        crc.update(std.mem.asBytes(&std.mem.nativeToBig(u64, @as(u64, label.len))));
        crc.update(label);
        crc.update(context_value);
        const word = std.mem.nativeToBig(u32, crc.final());
        const room = @min(@sizeOf(u32), output.len - offset);
        @memcpy(output[offset..][0..room], std.mem.asBytes(&word)[0..room]);
    }
}

test {
    _ = @import("null_quic_provider_test.zig");
}
