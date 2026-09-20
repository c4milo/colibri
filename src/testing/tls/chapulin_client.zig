//! chapulin's TLS 1.3 client behind colibri's `tls.Provider`, for `src/testing/` alone
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 5's TLS half.
//!
//! **Two phases, because the two sides meet the socket at different places.** colibri's vtable is
//! buffer in and buffer out: it never reads a descriptor, and `attach_tls` refuses a handshake
//! that has not already completed. chapulin's `ch_connect` is the opposite — it drives the whole
//! handshake itself through the `send` and `recv` callbacks of its config. The seam is those two
//! callbacks, and this file moves them:
//!
//!   1. **Handshake.** The callbacks read and write the socket, and `ch_connect` runs to
//!      completion. colibri is not involved and owns nothing yet.
//!   2. **Records.** The callbacks serve slices colibri passed in, so `ch_write` seals into
//!      colibri's output and `ch_read` opens from colibri's input. No descriptor is touched.
//!
//! Phase 2 is what lets a socket-owning TLS stack fill a vtable that owns no I/O. It works
//! because colibri hands over whole records: `decrypt_record` is called with a complete record,
//! so the `recv` callback never runs dry, which matters because chapulin's `io.c` turns any
//! `recv` of zero or less into `CH_EIO` and no callback of its can say "nothing yet"
//! ([decision 46](../../../docs/decisions.md)).
//!
//! The handshake blocks, so an endpoint using this drives **one connection at a time**. The
//! 64-connection poll loop stays cleartext until chapulin's callbacks can report "nothing yet".
const std = @import("std");
const tls = @import("tls");
const constants = @import("../constants.zig");
const chapulin = @import("chapulin.zig");

const c = chapulin.c;
const posix = std.posix;

pub const Error = error{
    /// chapulin refused the configuration before sending anything, which is a defect in how
    /// colibri built it rather than anything the peer did.
    ConfigRefused,
    /// The handshake did not complete (RFC 8446 §6). chapulin has raised its own alert.
    HandshakeFailed,
};

/// What the caller provides. The octets are the caller's and must outlive the session, which is
/// chapulin's rule for both lists and colibri's rule for every buffer (decision 35).
pub const Options = struct {
    /// The trust anchors, each an SPKI, as chapulin's `ch_trust_anchor` carries them.
    anchors: []const c.ch_trust_anchor,
    /// The name the certificate must carry (RFC 9110 §4.3.4).
    hostname: []const u8,
    /// The connected socket. It stays the caller's: this file never opens or closes one.
    socket: posix.socket_t,
};

/// Where chapulin's callbacks read and write. The phase moves once, when the handshake ends, and
/// never moves back.
const Io = union(enum) {
    /// Phase 1: the socket the caller connected.
    socket: posix.socket_t,
    /// Phase 2: the slices colibri passed into `encrypt_record` or `decrypt_record`.
    records: Records,
};

const Records = struct {
    /// What colibri gave to open, and how much of it chapulin has taken.
    input: []const u8 = &.{},
    taken: usize = 0,
    /// Where colibri wants the sealed octets, and how many are there.
    output: []u8 = &.{},
    written: usize = 0,
};

pub const Client = struct {
    session: c.ch_tls,
    config: c.ch_cfg,
    /// The one protocol colibri offers. RFC 9113 §3.1: "h2" identifies HTTP/2 over TLS.
    alpn: [1]c.ch_alpn_protocol,
    /// chapulin's receive buffer, whose size less record overhead it advertises as the peer's
    /// `record_size_limit`, so the peer can never overflow it.
    receive: [constants.tls_receive_len]u8,
    io: Io,

    /// Builds the configuration and checks it, without sending anything.
    pub fn init(client: *Client, options: Options) Error!void {
        // The two chapulin structs are zeroed field by field, because a union has no zero and
        // chapulin reads every field it declares.
        client.session = std.mem.zeroes(c.ch_tls);
        client.config = std.mem.zeroes(c.ch_cfg);
        client.receive = @splat(0);
        client.io = .{ .socket = options.socket };
        // RFC 9113 §3.1: h2 over TLS is selected by ALPN, and colibri offers that and nothing
        // else, so a server that will not speak h2 fails the handshake rather than the request.
        client.alpn[0] = .{ .name = alpn_h2.ptr, .name_len = alpn_h2.len };
        client.config = .{
            .buf = &client.receive,
            .buf_len = client.receive.len,
            .send = send,
            .recv = recv,
            .io = @ptrCast(&client.io),
            .anchors = options.anchors.ptr,
            .anchor_count = options.anchors.len,
            .hostname = options.hostname.ptr,
            .hostname_len = options.hostname.len,
            .alpn_protocols = &client.alpn,
            .alpn_count = client.alpn.len,
        };
    }

    /// Runs the handshake to completion (phase 1). It blocks, so one connection at a time.
    pub fn handshake(client: *Client) Error!void {
        if (c.ch_connect(&client.session, &client.config) != ok) return Error.HandshakeFailed;
        // Phase 2 from here: nothing below this line touches the descriptor again.
        client.io = .{ .records = .{} };
    }

    /// RFC 7301 §3.1: what the server selected, or null when it selected nothing. In TLS 1.3 the
    /// selection arrives in EncryptedExtensions, so null before that is an answer and not an error.
    pub fn negotiated_alpn(client: *const Client) ?[]const u8 {
        if (client.session.alpn_selected == c.CH_ALPN_NONE) return null;
        return alpn_h2;
    }
};

/// RFC 9113 §3.1's identifier, which is the two octets 0x68 0x32.
const alpn_h2 = "h2";

/// chapulin answers 0 for success and a negative `CH_E*` for everything else.
const ok: c_int = 0;

/// chapulin's `send`: in phase 1 the socket, in phase 2 colibri's output buffer.
fn send(io: ?*anyopaque, octets: [*c]const u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    switch (state.*) {
        .socket => |descriptor| {
            // Blocking, with no MSG_DONTWAIT: chapulin's callbacks cannot report "nothing yet",
            // so the handshake waits here rather than answering short (decision 46).
            const wrote = std.c.send(descriptor, octets, len, 0);
            if (wrote <= 0) return -1;
            return @intCast(wrote);
        },
        .records => |*records| {
            const room = records.output.len - records.written;
            // A short output is colibri's to widen, and chapulin cannot be told to wait, so this
            // fails the call rather than writing part of a record.
            if (len > room) return -1;
            @memcpy(records.output[records.written..][0..len], octets[0..len]);
            records.written += len;
            return @intCast(len);
        },
    }
}

/// chapulin's `recv`: in phase 1 the socket, in phase 2 the record colibri passed in.
fn recv(io: ?*anyopaque, out: [*c]u8, len: usize) callconv(.c) c_int {
    const state: *Io = @ptrCast(@alignCast(io.?));
    switch (state.*) {
        .socket => |descriptor| {
            const read = std.c.recv(descriptor, out, len, 0);
            if (read <= 0) return -1;
            return @intCast(read);
        },
        .records => |*records| {
            const left = records.input.len - records.taken;
            // colibri passes a whole record, so chapulin never asks past the end of one. Running
            // dry would reach chapulin as CH_EIO, which is why the caller must not call with a
            // partial record (decision 46).
            const take = @min(len, left);
            if (take == 0) return -1;
            @memcpy(out[0..take], records.input[records.taken..][0..take]);
            records.taken += take;
            return @intCast(take);
        },
    }
}

const testing = std.testing;

/// The client the tests drive, placed outside any stack frame: it carries chapulin's session and
/// its receive buffer, which are larger than a stack frame should hold. Test-only.
var test_client: Client = undefined;
const test_hostname = "localhost";

test "the configuration colibri builds is the one chapulin is given" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{ .anchors = &anchors, .hostname = test_hostname, .socket = 0 });
    // RFC 9113 §3.1: one protocol is offered, and it is "h2".
    try testing.expectEqual(1, test_client.config.alpn_count);
    try testing.expectEqual(alpn_h2.len, test_client.config.alpn_protocols[0].name_len);
    try testing.expectEqualSlices(u8, "h2", test_client.config.alpn_protocols[0].name[0..2]);
    // The receive buffer is colibri's storage, and chapulin advertises its size to the peer.
    try testing.expectEqual(constants.tls_receive_len, test_client.config.buf_len);
    try testing.expectEqual(@intFromPtr(&test_client.receive), @intFromPtr(test_client.config.buf));
    // The hostname is the one the certificate must carry.
    try testing.expectEqual(test_hostname.len, test_client.config.hostname_len);
    // The callbacks point at this file, and their state at the phase.
    try testing.expect(test_client.config.send != null);
    try testing.expect(test_client.config.recv != null);
    try testing.expectEqual(Io.socket, std.meta.activeTag(test_client.io));
}

test "the record phase serves colibri's buffers and never the socket" {
    if (!chapulin.available) return error.SkipZigTest;
    const anchors = [_]c.ch_trust_anchor{};
    try test_client.init(.{ .anchors = &anchors, .hostname = test_hostname, .socket = 0 });
    // Moving to phase 2 is what `handshake` does on success; the descriptor is never used again.
    var input = [_]u8{ 1, 2, 3, 4 };
    var output: [8]u8 = @splat(0);
    test_client.io = .{ .records = .{ .input = &input, .output = &output } };
    // `recv` hands chapulin the octets colibri passed, in order, and stops at the end of them.
    var taken: [4]u8 = @splat(0);
    try testing.expectEqual(2, recv(@ptrCast(&test_client.io), &taken, 2));
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, taken[0..2]);
    try testing.expectEqual(2, recv(@ptrCast(&test_client.io), &taken, 4));
    try testing.expectEqualSlices(u8, &.{ 3, 4 }, taken[0..2]);
    // Past the end it fails rather than blocking, because no callback of chapulin's can say
    // "nothing yet" and colibri only ever passes a whole record.
    try testing.expectEqual(-1, recv(@ptrCast(&test_client.io), &taken, 1));
    // `send` fills colibri's output and refuses to write part of a record into a short one.
    const sealed = [_]u8{ 9, 9, 9 };
    try testing.expectEqual(3, send(@ptrCast(&test_client.io), &sealed, 3));
    try testing.expectEqualSlices(u8, &.{ 9, 9, 9 }, output[0..3]);
    try testing.expectEqual(3, test_client.io.records.written);
    try testing.expectEqual(-1, send(@ptrCast(&test_client.io), &sealed, 6));
    try testing.expectEqual(3, test_client.io.records.written);
}
