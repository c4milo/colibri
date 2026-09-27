//! The chapulin calls the QUIC checks link, and the assertion hook its object imports
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 9e.
//!
//! chapulin comes from the package `build.zig.zon` pins, compiled `TRANSPORT=quic-nonblocking
//! ROLE=both SUITE=aesgcm AES=hw KEYLOG=on RAND=extern` (design §8 step 16a). The package translates
//! its public headers under the defines its object compiled with, and that translation is the
//! module `chapulin`, so every declaration here is chapulin's own.
//!
//! **Three suites.** `SUITE=aesgcm` holds TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384
//! beside TLS_CHACHA20_POLY1305_SHA256. RFC 9846 §9.1 makes the first mandatory, and it is the only
//! kind of suite h3spec offers.
//!
//! **One object serves both roles.** `ROLE=both` compiles the client's `ch_quic_init` and the
//! server's `ch_srv_quic_init` into one object, and the packet calls of `quic.h` serve either.
//!
//! The image defines chapulin's three hooks: `ch_assert_fail` below, `ch_keylog` in
//! `chapulin_quic.zig`, and `ch_rand_bytes` in `entropy.zig`.
const std = @import("std");
const constants = @import("../constants.zig");
const check_file = @import("../tls/check_file.zig");
const entropy = @import("../entropy.zig");

/// chapulin's own declarations, translated from its headers by its package rather than copied.
pub const c = @import("chapulin").c;

pub const BuildError = error{
    /// The linked object was built with other defines than the ones its headers were translated
    /// under, so the two disagree about struct sizes and bounds.
    ObjectMismatch,
};

/// Refuses an object built with other defines than its headers were translated under, which a
/// QUIC endpoint calls once before any other chapulin call (chapulin's `build.h`). The package
/// builds both from one list, so this holds by construction; the call is what proves it for the
/// object that was actually linked.
pub fn check_build() BuildError!void {
    // chapulin names the record after the object's transport, so one image can link a QUIC object
    // beside a record one, and translate-c cannot follow `build.h`'s `ch_build` alias to it.
    if (c.ch_build_matches(&c.ch_build_info_quic_nonblocking) != 0) return;
    std.debug.print("chapulin: the linked QUIC object was built with other defines than its " ++
        "headers were translated under.\n", .{});
    return BuildError.ObjectMismatch;
}

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
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
    // `ch_keylog` reads the session, so `chapulin_quic.zig` exports it; `ch_rand_bytes` is
    // exported where `entropy.zig` is analysed.
    _ = entropy;
}

const testing = std.testing;

/// A client random and a secret whose hex is easy to tell apart, and their length. Test-only.
const random_octet: u8 = 0xab;
const secret_octet: u8 = 0x01;
const test_secret_len = 32;

test "a key log line is the label and two hex values, and a full log refuses rather than cuts" {
    var keylog: Keylog = .{};
    const random: [test_secret_len]u8 = @splat(random_octet);
    const secret: [test_secret_len]u8 = @splat(secret_octet);
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

test "the linked QUIC object was built with the defines its headers were translated under" {
    try check_build();
    // RFC 9846 §9.1's mandatory suite, which h3spec offers, is in the object.
    try testing.expect(c.ch_build_info_quic_nonblocking.axes & c.CH_BUILD_SUITE_AES_GCM != 0);
}

test "the linked QUIC object carries both roles" {
    try testing.expect(@hasDecl(c, "ch_srv_quic_init"));
    try testing.expect(@hasDecl(c, "ch_quic_init"));
}
