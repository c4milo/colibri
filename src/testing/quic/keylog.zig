//! The NSS key log of `src/testing/`'s QUIC endpoints, and the `ch_keylog` hook that fills it.
//! Their `tls` links chapulin's objects built `KEYLOG=on` (design §8 step 16b), which hand each
//! traffic secret to `ch_keylog` inside the handshake step that derived it, so a capture of a run
//! can be decrypted. The hook reads the session's context, which the endpoint sets to its log with
//! `set_keylog_context`, through `chapulin.hookContext`.
const std = @import("std");
const assert = std.debug.assert;
const chapulin = @import("chapulin");
const constants = @import("../constants.zig");
const check_file = @import("../tls/check_file.zig");

const c = chapulin.c;

/// The lines, which a check writes to the file SSLKEYLOGFILE names: the loopback check once its
/// run ends, a UDP endpoint after each step. `ch_keylog` must not block, so the line is kept here
/// rather than written.
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
        assert(printed.len == line_len);
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

/// SHA-384's length where the object holds a suite that hashes with it, and SHA-256's in an object
/// that holds ChaCha20 alone (decision 97).
const sha384_len: usize = if (@hasDecl(c, "SHA384_LEN")) c.SHA384_LEN else c.SHA256_LEN;

/// Hex writes each octet as two digits.
const hex_digits_per_octet: usize = 2;

/// chapulin's `keylog.h` hook: one traffic secret as it was derived. A session with no log set
/// drops it.
fn keylog_hook(io: ?*anyopaque, label: [*:0]const u8, client_random: [*]const u8, secret: [*]const u8, secret_len: usize) callconv(.c) void {
    const context = chapulin.hookContext(io) orelse return;
    const keylog: *Keylog = @ptrCast(@alignCast(context));
    // `keylog.h`: the secret is as long as the suite's hash, 32 octets, or 48 in an object that
    // holds TLS_AES_256_GCM_SHA384.
    assert(secret_len == c.SHA256_LEN or secret_len == sha384_len);
    keylog.append(std.mem.span(label), client_random[0..c.CH_KEYLOG_RANDOM_LEN], secret[0..secret_len]);
}

comptime {
    @export(&keylog_hook, .{ .name = "ch_keylog", .linkage = .strong });
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
