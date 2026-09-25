//! The tests of `chapulin_record.zig`: the record bounds it checks before chapulin reads anything,
//! the flight sink of the record-mode server, and what `decrypt_record` and `encrypt_record` refuse
//! before they call chapulin. The ones that need chapulin linked skip without it.
const std = @import("std");
const tls = @import("tls");
const chapulin = @import("chapulin.zig");
const chapulin_record = @import("chapulin_record.zig");
const zero_key_records = @import("zero_key_records.zig");

const c = chapulin.c;
const testing = std.testing;
const Io = chapulin_record.Io;
const Held = chapulin_record.Held;
const ok = chapulin_record.ok;
const failed = chapulin_record.failed;

test "RFC 9846 §5.1: a record is whole once its header and the length it names have arrived" {
    // An application_data record whose header names 3 octets.
    const record = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc };
    try testing.expectEqual(record.len, chapulin_record.whole_record_len(&record).?);
    // A second record after it does not lengthen the first.
    try testing.expectEqual(record.len, chapulin_record.whole_record_len(&(record ++ record)).?);
    // One octet short of the body, and every cut of the header, is not whole.
    try testing.expectEqual(null, chapulin_record.whole_record_len(record[0 .. record.len - 1]));
    for (0..tls.constants.record_header_len) |cut| try testing.expectEqual(null, chapulin_record.whole_record_len(record[0..cut]));
    // RFC 9846 §3.1: the length is big-endian, so these two octets name 256.
    const long = [_]u8{ 0x17, 0x03, 0x03, 0x01, 0x00 };
    try testing.expectEqual(null, chapulin_record.whole_record_len(&long));
}

/// A record limit and a seal overhead of the shape chapulin's are. Test-only.
const test_limit: usize = 512;
const test_overhead: usize = 22;

test "the plaintext sealed is what fits the output as records of the limit" {
    // Room for exactly two whole records takes two limits of plaintext.
    try testing.expectEqual(2 * test_limit, chapulin_record.sealable_len(10_000, 2 * (test_limit + test_overhead), test_limit, test_overhead));
    // Room for a third record's overhead and one octet adds one octet.
    try testing.expectEqual(2 * test_limit + 1, chapulin_record.sealable_len(10_000, 2 * (test_limit + test_overhead) + test_overhead + 1, test_limit, test_overhead));
    // Room for only the overhead of a third adds nothing.
    try testing.expectEqual(2 * test_limit, chapulin_record.sealable_len(10_000, 2 * (test_limit + test_overhead) + test_overhead, test_limit, test_overhead));
    // Less plaintext than room takes all of it, and no room takes none.
    try testing.expectEqual(7, chapulin_record.sealable_len(7, 1000, test_limit, test_overhead));
    try testing.expectEqual(0, chapulin_record.sealable_len(7, test_overhead, test_limit, test_overhead));
}

test "a record-mode server's flight goes into the output whole, or the call fails" {
    var output: [8]u8 = undefined;
    var io: Io = .{ .handshake = .{ .output = &output } };
    try testing.expectEqual(ok, chapulin_record.flight_out(@ptrCast(&io), "abcde", 5));
    try testing.expectEqual(5, io.handshake.written);
    // chapulin's sink takes a whole record or none (`srv_cfg.h`).
    try testing.expectEqual(failed, chapulin_record.flight_out(@ptrCast(&io), "fghi", 4));
    try testing.expectEqual(5, io.handshake.written);
    try testing.expect(io.handshake.short);
    try testing.expectEqualStrings("abcde", output[0..5]);
    // Outside the handshake there is no flight to write.
    io = .{ .records = .{} };
    try testing.expectEqual(failed, chapulin_record.flight_out(@ptrCast(&io), "a", 1));
}

/// A zeroed session and the state around it, for the calls that refuse before chapulin reads the
/// session. Test-only.
var test_session: if (chapulin.available) c.ch_tls else void = undefined;
var test_held: Held = undefined;

fn test_provider() tls.Provider {
    test_session = std.mem.zeroes(c.ch_tls);
    test_held = .{ .session = &test_session, .io = .{ .records = .{} }, .closed = false, .pending_alert = null, .suite = 0 };
    return .{ .context = @ptrCast(&test_held), .vtable = &chapulin_record.vtable };
}

test "RFC 9846 §5.1: a record not yet whole is incomplete, and chapulin never reads it" {
    if (!chapulin.available) return error.SkipZigTest;
    const held = test_provider();
    const partial = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x11, 0x00 };
    var plaintext: [64]u8 = undefined;
    const opened = try held.vtable.decrypt_record(held.context, &partial, &plaintext);
    try testing.expectEqual(tls.Content.incomplete, opened.content);
    try testing.expectEqual(0, opened.consumed);
    // chapulin never ran, so the session's input was never set.
    try testing.expectEqual(0, test_held.io.records.input.len);
}

test "a plaintext buffer shorter than the record's ciphertext is refused before chapulin reads it" {
    if (!chapulin.available) return error.SkipZigTest;
    const held = test_provider();
    const record = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x11 } ++ [_]u8{0} ** 0x11;
    var plaintext: [0x10]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, held.vtable.decrypt_record(held.context, &record, &plaintext));
    try testing.expectEqual(0, test_held.io.records.input.len);
}

test "RFC 9846 §5.2: an output that cannot hold one sealed octet takes no plaintext" {
    if (!chapulin.available) return error.SkipZigTest;
    const held = test_provider();
    test_session.peer_limit = c.CH_TX_PT;
    var output: [c.REC_OVERHEAD]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, held.vtable.encrypt_record(held.context, "a", &output));
    // Nothing to seal takes nothing and writes nothing.
    const sealed = try held.vtable.encrypt_record(held.context, "", &output);
    try testing.expectEqual(0, sealed.consumed + sealed.written);
}

test "in record mode, `recv` answers 0 between records, which `ch_read` reads as no record yet" {
    if (!chapulin.available) return error.SkipZigTest;
    var io: Io = .{ .records = .{} };
    var into: [8]u8 = undefined;
    try testing.expectEqual(0, chapulin_record.recv(@ptrCast(&io), &into, into.len));
    try testing.expect(io.records.ran_dry);
    // A record-mode handshake calls neither callback (chapulin's INV-28).
    io = .{ .handshake = .{} };
    try testing.expectEqual(failed, chapulin_record.recv(@ptrCast(&io), &into, into.len));
    try testing.expectEqual(failed, chapulin_record.send(@ptrCast(&io), &into, into.len));
}

/// A session keyed with zeros (`zero_key_records.zig`), and records sealed for it. Test-only.
var keyed_session: if (chapulin.available) c.ch_tls else void = undefined;
var keyed_held: Held = undefined;
var keyed_receive: [tls.constants.record_write_len_min]u8 = undefined;
var keyed_input: [keyed_input_len]u8 = undefined;
/// Room for one empty record and part of the next. Test-only.
const keyed_input_len: usize = 256;

fn keyed_provider() tls.Provider {
    zero_key_records.connect(&keyed_held, &keyed_session, &keyed_receive);
    return .{ .context = @ptrCast(&keyed_held), .vtable = &chapulin_record.vtable };
}

test "a record that carries no data is taken whole, and chapulin never reads the partial one after it" {
    if (!chapulin.available) return error.SkipZigTest;
    const held = keyed_provider();
    // RFC 9846 §5.1: application data may be empty. The next record has arrived in part.
    const empty = try zero_key_records.seal(0, zero_key_records.content_application_data, "", &keyed_input);
    const empty_len = empty.len;
    const next = [_]u8{ 0x17, 0x03, 0x03 };
    @memcpy(keyed_input[empty_len..][0..next.len], &next);
    var plaintext: [tls.constants.record_ciphertext_len_max]u8 = undefined;
    const input = keyed_input[0 .. empty_len + next.len];
    const opened = try held.vtable.decrypt_record(held.context, input, &plaintext);
    try testing.expectEqual(empty_len, opened.consumed);
    try testing.expectEqual(0, opened.plaintext_len);
    try testing.expectEqual(tls.Content.new_session_ticket, opened.content);
    // chapulin sent nothing from inside the read, so nothing is owed.
    var output: [chapulin_record.owed_len_max]u8 = undefined;
    try testing.expectEqual(0, try held.vtable.handshake_write(held.context, &output, 0));
}

/// RFC 9846 §4 and §4.7.3: a KeyUpdate whose `request_update` is `update_requested`, as a
/// handshake message: type 24, a length of 1, and the one octet. Test-only.
const key_update_requested = [_]u8{ handshake_key_update, 0, 0, 1, update_requested };
const key_update_not_requested = [_]u8{ handshake_key_update, 0, 0, 1, update_not_requested };
const handshake_key_update: u8 = 24;
const update_not_requested: u8 = 0;
const update_requested: u8 = 1;

test "RFC 9846 §4.7.3: a KeyUpdate that asks for one is answered, under the keys it replaces" {
    if (!chapulin.available) return error.SkipZigTest;
    const held = keyed_provider();
    const update = try zero_key_records.seal(0, zero_key_records.content_handshake, &key_update_requested, &keyed_input);
    var plaintext: [tls.constants.record_ciphertext_len_max]u8 = undefined;
    const opened = try held.vtable.decrypt_record(held.context, update, &plaintext);
    try testing.expectEqual(update.len, opened.consumed);
    try testing.expectEqual(tls.Content.key_update, opened.content);
    // An output too short for the reply takes none of it.
    var short: [1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, held.vtable.handshake_write(held.context, &short, 0));
    // The reply is this side's first record, under the zero keys it held before the update.
    var output: [chapulin_record.owed_len_max]u8 = undefined;
    const reply_len = try held.vtable.handshake_write(held.context, &output, 0);
    var inner: [16]u8 = undefined;
    const reply = zero_key_records.open(0, output[0..reply_len], &inner).?;
    try testing.expectEqual(zero_key_records.content_handshake, reply.content_type);
    try testing.expectEqualSlices(u8, &key_update_not_requested, reply.content);
    // Nothing more is owed, and the next record is sealed under the new keys, which is why the
    // reply must go first.
    try testing.expectEqual(0, try held.vtable.handshake_write(held.context, &output, 0));
    const sealed = try held.vtable.encrypt_record(held.context, "after", &output);
    try testing.expectEqual(null, zero_key_records.open(1, output[0..sealed.written], &inner));
}

/// A record limit below chapulin's own, as a peer's record_size_limit sets it (RFC 8449 §4),
/// and chapulin's overhead on each record. Test-only.
const small_limit: u16 = 100;

test "a peer's lower record limit cuts the records, and the seal takes only what fits" {
    if (!chapulin.available) return error.SkipZigTest;
    const held = keyed_provider();
    keyed_session.peer_limit = small_limit;
    // Room for two records of the lower limit, and a plaintext longer than both.
    var output: [2 * (small_limit + c.REC_OVERHEAD)]u8 = undefined;
    const plaintext: [3 * small_limit]u8 = @splat('a');
    const sealed = try held.vtable.encrypt_record(held.context, &plaintext, &output);
    try testing.expectEqual(2 * small_limit, sealed.consumed);
    try testing.expectEqual(output.len, sealed.written);
}

test {
    _ = zero_key_records;
}
