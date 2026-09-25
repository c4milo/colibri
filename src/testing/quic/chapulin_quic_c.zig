//! The chapulin calls the QUIC check links, and the assertion hook its object imports
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 9e.
//!
//! `-Dchapulin-quic=<checkout>` names a checkout whose `bin/chapulin-quic.o` was built
//! `TRANSPORT=quic ROLE=both KEYLOG=on SUITE=aesgcm AES=hw`. The headers are read from it in place,
//! and `check_build` refuses an object built otherwise. Without the option `available` is false
//! and everything below compiles to nothing.
//!
//! **Three suites.** `SUITE=aesgcm` holds TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384
//! beside TLS_CHACHA20_POLY1305_SHA256. RFC 9846 §9.1 makes the first mandatory, and it is the only
//! kind of suite h3spec offers.
//!
//! **One object serves both roles.** `ROLE=both` compiles the client's `ch_quic_init` and the
//! server's `ch_srv_quic_init` into one object, and the packet calls of `quic.h` serve either.
//! The record-mode endpoints need two objects because both roles export `ch_read`; a QUIC object
//! exports neither.
const std = @import("std");
const build_options = @import("build_options");
const constants = @import("../constants.zig");
const check_file = @import("../tls/check_file.zig");

/// Whether a checkout was given.
pub const available: bool = build_options.chapulin;

/// chapulin's own declarations, read from its headers rather than copied.
pub const c = if (available) @cImport({
    // `quic.h` brings `cfg.h` and `session.h`, and `srv_quic.h` the server's two calls.
    @cInclude("quic.h");
    @cInclude("srv_quic.h");
    // `ch_srv_check`, the server's boot-time test of its signing key.
    @cInclude("srv.h");
    // `SRV_TICKET_KEY_LEN`, the length of the key a server seals its tickets under.
    @cInclude("srv_ticket.h");
    @cInclude("drbg.h");
    @cInclude("keylog.h");
    // The record of the defines the linked object was built with (`check_build`).
    @cInclude("build.h");
}) else struct {};

pub const BuildError = error{
    /// The linked object was built with other defines than the ones `build/modules.zig` reads
    /// the headers under, so the two disagree about struct sizes and bounds.
    ObjectMismatch,
};

/// Refuses an object built with other defines than `build/modules.zig` reads the headers under,
/// which a QUIC endpoint calls once before any other chapulin call (chapulin's `build.h`). The
/// link does not catch it: an object without the AES-GCM suites exports the same calls, and the
/// program would run with the wrong struct sizes.
pub fn check_build() BuildError!void {
    // chapulin names the record after the object's transport, so one image can link a QUIC object
    // beside a record one, and translate-c cannot follow `build.h`'s `ch_build` alias to it.
    if (c.ch_build_matches(&c.ch_build_quic) != 0) return;
    std.debug.print("chapulin: the linked QUIC object was built with other defines than colibri " ++
        "reads its headers under; CLAUDE.md's Commands section names the make line.\n", .{});
    return BuildError.ObjectMismatch;
}

/// The seed a `RAND=drbg` build takes, which chapulin's `drbg.h` fixes at 32 octets.
pub const seed_len: usize = 32;

/// chapulin routes every failed assertion here. A failed chapulin assertion is a defect in
/// chapulin or in how colibri configured it, and the check must not carry on past it.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

/// The NSS key log lines, which a check writes to the file SSLKEYLOGFILE names: the loopback
/// check once its run ends, a UDP endpoint after each step. chapulin hands each traffic secret to
/// `ch_keylog` inside the handshake step that derived it, and that call must not block, so the
/// line is kept here rather than written.
pub const Keylog = struct {
    octets: [constants.quic_keylog_len]u8 = undefined,
    len: usize = 0,
    /// Whether a line did not fit, which the check reports rather than writing a partial log.
    overflowed: bool = false,

    /// Appends `<label> <client_random> <secret>` in lowercase hex, as the format writes it.
    pub fn append(keylog: *Keylog, label: []const u8, client_random: []const u8, secret: []const u8) void {
        const separators: usize = 3;
        const line_len = label.len + hex_digits_per_octet * (client_random.len + secret.len) + separators;
        if (keylog.len + line_len > keylog.octets.len) {
            keylog.overflowed = true;
            return;
        }
        const line = keylog.octets[keylog.len..][0..line_len];
        const printed = std.fmt.bufPrint(line, "{s} {x} {x}\n", .{ label, client_random, secret }) catch unreachable;
        std.debug.assert(printed.len == line_len);
        keylog.len += line_len;
    }

    pub fn written(keylog: *const Keylog) []const u8 {
        return keylog.octets[0..keylog.len];
    }

    /// Forgets every line, once they have been written out.
    pub fn clear(keylog: *Keylog) void {
        keylog.len = 0;
        keylog.overflowed = false;
    }

    /// Appends the lines to the file at `path`, which SSLKEYLOGFILE names, and answers false when
    /// it cannot. The file holds secrets, so only its owner may read it.
    pub fn append_to_file(keylog: *const Keylog, path: []const u8) bool {
        var path_storage: [check_file.path_len_max:0]u8 = undefined;
        if (path.len >= path_storage.len or keylog.overflowed) return false;
        @memcpy(path_storage[0..path.len], path);
        path_storage[path.len] = 0;
        const descriptor = std.c.open(&path_storage, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, keylog_mode);
        if (descriptor < 0) return false;
        defer _ = std.c.close(descriptor);
        const lines = keylog.written();
        return std.c.write(descriptor, lines.ptr, lines.len) == lines.len;
    }
};

/// Owner read and write: the key log holds secrets.
const keylog_mode: std.c.mode_t = 0o600;

/// Hex writes each octet as two digits.
const hex_digits_per_octet: usize = 2;

comptime {
    // Only a build that links chapulin owes it the handler, and only that build defines it.
    // `ch_keylog`, the other hook, reads the session, so `chapulin_quic.zig` exports it.
    if (available) @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}

const testing = std.testing;

/// A client random and a secret whose hex is easy to tell apart. Test-only.
const random_octet: u8 = 0xab;
const secret_octet: u8 = 0x01;

test "a key log line is the label and two hex values, and a full log refuses rather than cuts" {
    var keylog: Keylog = .{};
    const random: [seed_len]u8 = @splat(random_octet);
    const secret: [seed_len]u8 = @splat(secret_octet);
    const label = "CLIENT_TRAFFIC_SECRET_0";
    keylog.append(label, &random, &secret);
    const separators: usize = 3;
    const line_len = label.len + hex_digits_per_octet * (random.len + secret.len) + separators;
    try testing.expectEqual(line_len, keylog.len);
    try testing.expect(std.mem.startsWith(u8, keylog.written(), label ++ " abab"));
    try testing.expect(std.mem.endsWith(u8, keylog.written(), "0101010101\n"));
    // Bounded by the log's size: every line is the same length.
    while (!keylog.overflowed) keylog.append(label, &random, &secret);
    try testing.expectEqual(0, keylog.len % line_len);
}

test "the linked QUIC object was built with the defines colibri reads the headers under" {
    if (!available) return error.SkipZigTest;
    try check_build();
    // RFC 9846 §9.1's mandatory suite, which h3spec offers, is in the object.
    try testing.expect(c.ch_build_quic.axes & c.CH_BUILD_SUITE_AES_GCM != 0);
}

test "the checkout the build was given links, and carries both roles" {
    if (!available) return error.SkipZigTest;
    const seed: [seed_len]u8 = @splat(0);
    c.ch_drbg_seed(&seed);
    try testing.expect(@hasDecl(c, "ch_srv_quic_init"));
    try testing.expect(@hasDecl(c, "ch_quic_init"));
}
