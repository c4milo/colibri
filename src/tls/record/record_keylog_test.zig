//! The record-mode tests that seal records chapulin never seals, such as a KeyUpdate: chapulin
//! starts none in record mode, and answers the peer's (RFC 9846 §4.7.3). The test takes the traffic
//! secrets from `ch_keylog`, which only an object built `KEYLOG=on` calls (chapulin's `keylog.h`),
//! and seals the peer's records here. `zig build test-tls-keylog` runs them; the library's object
//! logs nothing, so `record.zig` imports this file only for an object that does.
const std = @import("std");
const tls_provider = @import("tls_provider");
const chapulin = @import("chapulin_tcp");
const support = @import("record_test_support.zig");

const c = chapulin.c;
const testing = std.testing;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Writer = tls_provider.core.Writer;
const Reader = tls_provider.core.Reader;

/// The suite the tests' server selects, whose AEAD and hash this file seals with.
const chacha = tls_provider.constants.cipher_suite_chacha20_poly1305_sha256;
const secret_len = Hkdf.prk_length;

/// The application traffic secrets of the connection the tests ran last (RFC 9846 §7.1).
const Logged = struct {
    client: [secret_len]u8 = @splat(0),
    server: [secret_len]u8 = @splat(0),
};
threadlocal var logged: Logged align(@alignOf(Logged)) = .{};

/// chapulin's `ch_keylog`, which both sessions call with the same secrets.
fn keylog(io: ?*anyopaque, label: [*:0]const u8, client_random: [*]const u8, secret: [*]const u8, len: usize) callconv(.c) void {
    _ = .{ io, client_random };
    if (len != secret_len) return;
    const name = std.mem.span(label);
    if (std.mem.eql(u8, name, c.CH_KEYLOG_CLIENT_TRAFFIC)) @memcpy(&logged.client, secret[0..secret_len]);
    if (std.mem.eql(u8, name, c.CH_KEYLOG_SERVER_TRAFFIC)) @memcpy(&logged.server, secret[0..secret_len]);
}

comptime {
    @export(&keylog, .{ .name = "ch_keylog", .linkage = .strong });
}

/// One direction's key and IV (RFC 9846 §7.3).
const Keys = struct {
    key: [Aead.key_length]u8,
    iv: [Aead.nonce_length]u8,

    fn of(secret: [secret_len]u8) Keys {
        return .{
            .key = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "key", "", Aead.key_length),
            .iv = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "iv", "", Aead.nonce_length),
        };
    }

    /// RFC 9846 §5.3: the IV XORed with the sequence number, big-endian and padded on the left.
    fn nonce(keys: Keys, sequence: u64) [Aead.nonce_length]u8 {
        var result = keys.iv;
        var number: [@sizeOf(u64)]u8 = undefined;
        std.mem.writeInt(u64, &number, sequence, .big);
        for (result[Aead.nonce_length - number.len ..], number) |*octet, sequence_octet| octet.* ^= sequence_octet;
        return result;
    }
};

/// RFC 9846 §7.2: the next generation of a traffic secret.
fn next_secret(secret: [secret_len]u8) [secret_len]u8 {
    return std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "traffic upd", "", secret_len);
}

/// RFC 9846 §5.1's content types, and the legacy version every protected record carries.
const content_alert: u8 = 21;
const content_handshake: u8 = 22;
const content_application_data: u8 = 23;
const legacy_record_version: u16 = 0x0303;
/// The most content one test record carries.
const content_len_max: usize = 64;

/// RFC 9846 §4.7.3: a KeyUpdate as a handshake message, type 24 with a body of one octet.
const handshake_key_update: u8 = 24;
const update_not_requested: u8 = 0;
const update_requested: u8 = 1;
const key_update_requested = [_]u8{ handshake_key_update, 0, 0, 1, update_requested };
const key_update_not_requested = [_]u8{ handshake_key_update, 0, 0, 1, update_not_requested };

/// Seals `content` as one record of `content_type` (RFC 9846 §5.2) into the front of `output`.
fn seal(keys: Keys, sequence: u64, content_type: u8, content: []const u8, output: []u8) ![]u8 {
    var inner: [content_len_max + 1]u8 = undefined;
    @memcpy(inner[0..content.len], content);
    inner[content.len] = content_type;
    const inner_len = content.len + 1;
    var writer = Writer.init(output);
    try writer.write_byte(content_application_data);
    try writer.write_int(u16, legacy_record_version);
    try writer.write_int(u16, @intCast(inner_len + Aead.tag_length));
    const header_len = writer.written().len;
    var sealed: [content_len_max + 1]u8 = undefined;
    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(sealed[0..inner_len], &tag, inner[0..inner_len], output[0..header_len], keys.nonce(sequence), keys.key);
    try writer.write_bytes(sealed[0..inner_len]);
    try writer.write_bytes(&tag);
    return output[0..writer.written().len];
}

const Opened = struct { content_type: u8, content: []const u8 };

/// Opens `sealed`, or answers null when it does not authenticate under `keys` at `sequence`.
fn open(keys: Keys, sequence: u64, sealed: []const u8, output: []u8) ?Opened {
    var reader = Reader.init(sealed);
    const header = reader.take(tls_provider.constants.record_header_len) catch return null;
    const body = reader.take_rest();
    if (body.len < Aead.tag_length + 1 or body.len - Aead.tag_length > output.len) return null;
    const inner_len = body.len - Aead.tag_length;
    const tag = body[inner_len..][0..Aead.tag_length];
    Aead.decrypt(output[0..inner_len], body[0..inner_len], tag.*, header, keys.nonce(sequence), keys.key) catch return null;
    return .{ .content_type = output[inner_len - 1], .content = output[0 .. inner_len - 1] };
}

/// Runs a handshake whose server selects `chacha` and sends no ticket, so each side's first
/// record after it is its record 0 under its first application traffic secret.
fn connect() !void {
    try support.configure(support.web_pki, .{ .suites = support.order_of(&.{chacha}) });
    try support.handshake_both(null);
    try testing.expect(!std.mem.allEqual(u8, &logged.client, 0));
}

var sealed_storage: [support.wire_len]u8 = undefined;
var output_storage: [support.wire_len]u8 = undefined;

test "RFC 9846 §4.7.3: a KeyUpdate that asks for one is answered, under the keys it replaces" {
    try connect();
    const receiver = support.server.provider();
    const update = try seal(Keys.of(logged.client), 0, content_handshake, &key_update_requested, &sealed_storage);
    const opened = try receiver.vtable.decrypt_record(receiver.context, update, &support.scratch);
    try testing.expectEqual(update.len, opened.consumed);
    try testing.expectEqual(tls_provider.Content.key_update, opened.content);
    // An output too short for the reply takes none of it.
    var short: [1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, receiver.vtable.handshake_write(receiver.context, &short, 0));
    const reply_len = try receiver.vtable.handshake_write(receiver.context, &output_storage, 0);
    try testing.expectEqual(chapulin.record.key_update_record_len, reply_len);
    var inner: [content_len_max]u8 = undefined;
    const reply = open(Keys.of(logged.server), 0, output_storage[0..reply_len], &inner).?;
    try testing.expectEqual(content_handshake, reply.content_type);
    try testing.expectEqualSlices(u8, &key_update_not_requested, reply.content);
    try testing.expectEqual(0, try receiver.vtable.handshake_write(receiver.context, &output_storage, 0));
    // What the server seals next is under its next secret, and what it opens next is under the
    // client's.
    const sealed = try receiver.vtable.encrypt_record(receiver.context, "after", &output_storage);
    try testing.expectEqual(null, open(Keys.of(logged.server), 1, output_storage[0..sealed.written], &inner));
    const after = open(Keys.of(next_secret(logged.server)), 0, output_storage[0..sealed.written], &inner).?;
    try testing.expectEqualStrings("after", after.content);
    const hello = try seal(Keys.of(next_secret(logged.client)), 0, content_application_data, "hello", &sealed_storage);
    const read = try receiver.vtable.decrypt_record(receiver.context, hello, &support.scratch);
    try testing.expectEqualStrings("hello", support.scratch[0..read.plaintext_len]);
}

test "RFC 9846 §4.7.3: a KeyUpdate that asks for none is taken, and nothing is owed" {
    try connect();
    const receiver = support.server.provider();
    const update = try seal(Keys.of(logged.client), 0, content_handshake, &key_update_not_requested, &sealed_storage);
    const opened = try receiver.vtable.decrypt_record(receiver.context, update, &support.scratch);
    try testing.expectEqual(update.len, opened.consumed);
    try testing.expectEqual(0, opened.plaintext_len);
    try testing.expectEqual(0, try receiver.vtable.handshake_write(receiver.context, &output_storage, 0));
}

test "a record that carries no data is taken whole, and the partial one after it is left" {
    try connect();
    const receiver = support.server.provider();
    // RFC 9846 §5.1: application data may be empty. The next record has arrived in part.
    const empty = try seal(Keys.of(logged.client), 0, content_application_data, "", &sealed_storage);
    const partial = [_]u8{ content_application_data, 0x03, 0x03 };
    @memcpy(sealed_storage[empty.len..][0..partial.len], &partial);
    const opened = try receiver.vtable.decrypt_record(receiver.context, sealed_storage[0 .. empty.len + partial.len], &support.scratch);
    try testing.expectEqual(empty.len, opened.consumed);
    try testing.expectEqual(0, opened.plaintext_len);
    try testing.expectEqual(tls_provider.Content.new_session_ticket, opened.content);
    try testing.expectEqual(0, try receiver.vtable.handshake_write(receiver.context, &output_storage, 0));
}

test "replies owed past `key_update_replies_max` fail the read that would owe one more" {
    try connect();
    const receiver = support.server.provider();
    var secret = logged.client;
    // Two KeyUpdates, each in its own record, leave two replies owed when none is handed over.
    for (0..2) |_| {
        const update = try seal(Keys.of(secret), 0, content_handshake, &key_update_requested, &sealed_storage);
        _ = try receiver.vtable.decrypt_record(receiver.context, update, &support.scratch);
        secret = next_secret(secret);
    }
    const third = try seal(Keys.of(secret), 0, content_handshake, &key_update_requested, &sealed_storage);
    try testing.expectError(error.TlsFailed, receiver.vtable.decrypt_record(receiver.context, third, &support.scratch));
    // The two replies still go out, under the server's first and second secrets.
    const owed_len = try receiver.vtable.handshake_write(receiver.context, &output_storage, 0);
    try testing.expect(owed_len >= 2 * chapulin.record.key_update_record_len);
    var inner: [content_len_max]u8 = undefined;
    const first = output_storage[0..chapulin.record.key_update_record_len];
    try testing.expectEqualSlices(u8, &key_update_not_requested, open(Keys.of(logged.server), 0, first, &inner).?.content);
}
