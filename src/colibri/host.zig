//! The contract between the driver of a `colibri.Server` or a `colibri.Client` and its host
//! (decision 159). The driver holds the sockets' octets, the engine or the pool, and the
//! program's handler. It does no I/O, reads no clock and imports no Rotor. Each turn it writes
//! the operations that it needs into storage that the host owns, and the host gives back one
//! completion for each. The host calls the driver again at the instant that `Wait` names.
//!
//! The driver never calls the host, so it holds no function pointer of the host. `.private`
//! runs the driver on colibri's own Rotor adapter (`rotor_host.zig`). With `.hosted` the program
//! is the host. The root exports the seven types of the contract, from `SocketId` to `Turn`, and
//! neither `ObjectKind` nor `Features`, which a program writes as literals.
const std = @import("std");
const server = @import("server");
const build_options = @import("build_options");

/// Whether this build gave the module Rotor: the build option `rotor` (decision 159). It is true
/// in colibri's own build, and false for a dependent that does not pass `.rotor = true`.
pub const rotor_present: bool = build_options.rotor;

/// Who runs the loop of a `colibri.Server` or a `colibri.Client`: colibri, on its own Rotor loop,
/// or the program. It is the second comptime argument of each, with no public name (decision 156
/// ruling 1 as amended by decision 159).
pub const ObjectKind = enum { private, hosted };

/// Stops the compile with `message` unless `kind` is `wanted`: the call of a function that the
/// kind does not have (decision 156 ruling 4 as amended by decision 159).
pub fn require(comptime kind: ObjectKind, comptime wanted: ObjectKind, comptime message: []const u8) void {
    if (kind != wanted) @compileError(message);
}

/// Stops the compile for a `.private` object in a build with no Rotor (decision 159). The build
/// fetches Rotor, a lazy package, only for a build that asks for it.
pub fn require_rotor(comptime kind: ObjectKind) void {
    if (kind == .private and !rotor_present) @compileError("colibri: .private runs on Rotor; pass .rotor = true to b.dependency(\"colibri\", ...)");
}

/// Halts when `call` comes from inside a `turn` or a `complete`, which `in_turn` records. The
/// program's handler or router runs inside each of them, so such a call comes from the handler,
/// and it breaks decision 159's rule 4.
pub fn refuse_inside(in_turn: bool, comptime call: []const u8) void {
    if (in_turn) std.debug.panic("colibri: " ++ call ++ " called inside turn() or complete() (decision 159, rule 4)", .{});
}

/// Marks the start of a `turn` or a `complete` in `in_turn`, after `refuse_inside`. The caller
/// clears it when the call returns.
pub fn enter(in_turn: *bool, comptime call: []const u8) void {
    refuse_inside(in_turn.*, call);
    in_turn.* = true;
}

/// Records `now_ns`, the instant of a call, in `latest_ns`. Halts when it is before the instant
/// of the call before it, or before the `now` of `init`: the host's instant went back, which
/// breaks decision 159's rule 6.
pub fn record_instant(latest_ns: *u64, now_ns: u64) void {
    if (now_ns < latest_ns.*) std.debug.panic("colibri: now_ns went back (decision 159, rule 6)", .{});
    latest_ns.* = now_ns;
}

/// What a host does on one UDP socket that it opened before `init` (decision 159).
pub const Features = struct {
    /// The host sends a batch of equal segments in one call (UDP_SEGMENT).
    segments: bool = false,
    /// The host reads and sets each datagram's ECN codepoint. When false, colibri sets the pool's
    /// or the engine's `ecn` to false, so a host that cannot read the codepoint never halts on
    /// ECT(0) (decision 68 as amended by decision 159).
    ecn: bool = false,
};

/// A socket in colibri's table. The host maps it to its own handle.
pub const SocketId = enum(u16) { _ };

/// Names one operation in flight. It uses the low 32 bits of a host's tag alone. The high byte
/// is a generation, so a completion with an id that colibri does not hold is a halt
/// (`operation_table.zig`).
pub const OperationId = enum(u32) { _ };

pub const Operation = struct {
    id: OperationId,
    kind: Kind,

    pub const Kind = union(enum) {
        /// Open a TCP socket of the address's family, set TCP_NODELAY, and connect it.
        connect: struct { socket: SocketId, address: server.Address },
        /// Take one connection from `listener` into `into`, and set TCP_NODELAY.
        accept: struct { listener: SocketId, into: SocketId },
        /// Read into colibri's buffer. A read of 0 bytes means that the peer closed its side.
        receive: struct { socket: SocketId, buffer: []u8 },
        send: struct { socket: SocketId, bytes: []const u8 },
        /// Datagrams into the host's own memory. The host may complete it many times.
        receive_datagram: struct { socket: SocketId },
        /// `segment_bytes` of 0 is one datagram. Otherwise each segment is one datagram, which
        /// the host may send in one call (UDP_SEGMENT, design §8 step 13f.6).
        send_datagram: struct {
            socket: SocketId,
            bytes: []const u8,
            to: server.Address,
            ecn: server.Ecn,
            segment_bytes: u16,
        },
        /// Close the write side of the socket, as shutdown(2) with SHUT_WR does. The receive on
        /// the socket goes on, and a `close` follows (RFC 9112 §9.6, decision 160).
        shutdown_send: struct { socket: SocketId },
        close: struct { socket: SocketId },
        /// Asks for the final completion of `target` to come early. A cancel has the id of its
        /// target and gets no completion of its own. A target that already ended names nothing,
        /// and the host does nothing.
        cancel: struct { target: OperationId },
    };
};

pub const Completion = struct {
    id: OperationId,
    /// True while a `receive_datagram` stays in flight. The last completion has false. Only a
    /// `.datagram` result may have true: a failure or a cancel is always the last completion.
    more: bool = false,
    result: Result,

    pub const Result = union(enum) {
        connected,
        accepted,
        received: u32,
        sent: u32,
        /// The host's bytes, which the host lends for the call alone. colibri keeps no pointer
        /// to them, and QUIC unprotects them in place (RFC 9001 §5), so they are writable.
        datagram: struct {
            bytes: []u8,
            from: server.Address,
            ecn: server.Ecn = .not_ect,
        },
        datagram_sent: u32,
        /// The write side of the socket is closed.
        shut_down,
        closed,
        canceled,
        failed: Failure,
    };
};

/// colibri's words for an I/O failure. The host maps its own errors onto them.
pub const Failure = enum {
    refused,
    reset,
    unreachable_address,
    family_unsupported,
    closed,
    other,
};

/// When the host calls `turn` next: at once, at an instant, or when a completion arrives.
pub const Wait = union(enum) { now, at_ns: u64, none };

/// What `turn` wrote and when the host calls it next.
pub const Turn = struct { operations: u32, wait: Wait };
