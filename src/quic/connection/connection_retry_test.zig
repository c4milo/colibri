//! The tests of `connection_retry.zig`: RFC 9000 §17.2.5.2's rules about a Retry a client
//! receives, read against Retry packets `packet_header_write.zig` builds and `packet_header.zig`
//! reads back.
//!
//! `quic` cannot import `sim` (design §3), so the suite is test-local. It holds no key: what it
//! models is the one answer this file asks for, whether the Retry Integrity Tag validates, and
//! it records the pseudo-packet it was given so a test can check what RFC 9001 §5.8 covers.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const frame_module = @import("../frame/frame.zig");
const header = @import("../packet/packet_header.zig");
const header_write = @import("../packet/packet_header_write.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const identity_module = @import("connection_identity.zig");
const keys = @import("connection_keys.zig");
const retry = @import("connection_retry.zig");
const packet_build = @import("packet_build/packet_build.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const StreamProvider = @import("../stream/stream_provider.zig").StreamProvider;
const testing = std.testing;
const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

pub var test_connection: Connection = undefined;
pub var checker: TagChecker = undefined;
pub var pseudo: [constants.retry_pseudo_packet_len_max]u8 = undefined;

pub const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;

/// RFC 9000 §7.3's Figure 8: C1 is the client's own, S1 the connection ID it first addressed and
/// S2 the one the Retry carries. Fixed octets, because §5.1 wants them unpredictable and
/// invariant 5 forbids colibri a random number.
const c1_octet: u8 = 0xc1;
const s1_octet: u8 = 0x51;
const s2_octet: u8 = 0x52;
const id_len: usize = 8;
pub const c1: [id_len]u8 = @splat(c1_octet);
pub const s1: [id_len]u8 = @splat(s1_octet);
pub const s2: [id_len]u8 = @splat(s2_octet);

/// The Retry Token of §17.2.5, as octets nothing reads the value of.
const token_octet: u8 = 0x7c;
const token_len: usize = 24;
const test_token: [token_len]u8 = @splat(token_octet);

/// RFC 9000 §17.2.5: the four bits of byte 0 a server sets to anything and a client ignores.
const unused_bits: u8 = 0x0f;

const datagram_len: usize = 512;
var datagram: [datagram_len]u8 = undefined;
/// Where a built packet goes, apart from the Retry `datagram` holds.
pub var output: [datagram_len]u8 = undefined;
/// More handshake octets than a packet can hold, so what bounds a payload is the room the header
/// left rather than what the provider owes.
const filler_octet: u8 = 0x6d;
const filler: [datagram_len]u8 = @splat(filler_octet);

/// The last pseudo-packet the suite was handed, which RFC 9001 §5.8 defines. It is a file
/// variable and not a field because `retry_tag_valid` takes a `*const` context: a real suite
/// reads its keys there and writes nothing.
var seen: [constants.retry_pseudo_packet_len_max]u8 = @splat(0);
var seen_len: usize = 0;

/// How long a token this suite writes stays valid, which RFC 9000 §8.1.4 makes "a short time".
pub const token_lifetime_ns: u64 = 1_000_000_000;
/// The first octet of this suite's Retry tokens, which tells them from any other (§8.1.1).
pub const retry_token_type: u8 = 0x01;
/// Octets of a token before its connection IDs: the type, a checksum of the address it is bound
/// to, and when it expires. Each ID then follows its one-octet length (decision 55).
const token_head_len: usize = 1 + @sizeOf(u32) + @sizeOf(u64);

/// Octets of the token this suite writes for `ids`.
/// The most octets a token this suite writes can hold: two connection IDs of the longest length.
pub const token_bytes_max: usize = token_head_len + (1 + crypto.constants.connection_id_len_max) + (1 + crypto.constants.connection_id_len_max);

pub fn suite_token_len(ids: crypto.suite.RetryConnectionIds) usize {
    return token_head_len + 1 + ids.original_destination_len + 1 + ids.retry_source_len;
}
const tag_len: usize = crypto.constants.retry_integrity_tag_len;

/// A `crypto.Suite` that answers the Retry questions and nothing else. It holds no key: the tag
/// and the token are checksums, which detect a changed octet and prove nothing else.
pub const TagChecker = struct {
    /// Makes `retry_tag_write` refuse, as a suite written for clients alone would. Test-only.
    writes_tag: bool,
    /// Makes `retry_token_write` refuse, as a suite that offers no Retry would. Test-only.
    mints_token: bool,
    /// Makes it answer a zero-length token, which RFC 9000 §17.2.5.2 has a client discard.
    /// Test-only.
    writes_empty_token: bool,

    pub fn init(held: *TagChecker) void {
        held.* = .{ .writes_tag = true, .mints_token = true, .writes_empty_token = false };
        seen_len = 0;
    }

    pub fn suite(held: *TagChecker) crypto.Suite {
        return .{ .context = held, .vtable = &vtable };
    }

    fn tag_valid(context: *const anyopaque, pseudo_packet: []const u8, tag: *const [tag_len]u8) bool {
        _ = context;
        @memcpy(seen[0..pseudo_packet.len], pseudo_packet);
        seen_len = pseudo_packet.len;
        var expected: [tag_len]u8 = undefined;
        write_tag(pseudo_packet, &expected);
        return std.mem.eql(u8, &expected, tag);
    }

    fn tag_write(context: *const anyopaque, pseudo_packet: []const u8, tag: *[tag_len]u8) crypto.suite.RetryTagError!void {
        const held: *const TagChecker = @ptrCast(@alignCast(context));
        // RFC 9001 §5.8 gives the tag to the server that sends a Retry, so a suite written for
        // clients alone answers this, as `retry_token_write` does.
        if (!held.writes_tag) return error.Unsupported;
        write_tag(pseudo_packet, tag);
    }

    fn token_write(
        context: *anyopaque,
        address: []const u8,
        ids: *const crypto.suite.RetryConnectionIds,
        now_ns: u64,
        out: []u8,
    ) crypto.suite.TokenError!usize {
        const held: *TagChecker = @ptrCast(@alignCast(context));
        // RFC 9000 §8.1.2: a server "can request address validation by sending a Retry packet",
        // so a suite that mints no token is one whose server sends none.
        if (!held.mints_token) return error.Unsupported;
        if (held.writes_empty_token) return 0;
        var writer = Writer.init(out);
        write_token(&writer, address, ids, now_ns) catch return error.NoSpaceLeft;
        return writer.written().len;
    }

    fn token_check(context: *const anyopaque, address: []const u8, token: []const u8, now_ns: u64) crypto.suite.TokenCheck {
        _ = context;
        var reader = core.Reader.init(token);
        const kind = reader.read_byte() catch return .not_retry;
        if (kind != retry_token_type) return .not_retry;
        return read_token(&reader, address, now_ns) catch .invalid;
    }

    const vtable: crypto.suite.VTable = .{
        .install_initial_keys = unreachable_install,
        .keys_available = unreachable_available,
        .seal = unreachable_seal,
        .open = unreachable_open,
        .retry_tag_valid = tag_valid,
        .retry_tag_write = tag_write,
        .retry_token_write = token_write,
        .retry_token_check = token_check,
        .update_keys = unreachable_update,
        .key_phase = unreachable_phase,
        .discard_previous_keys = unreachable_discard_previous,
        .discard_keys = unreachable_discard,
    };
};

/// RFC 9001 §5.8's tag, as four checksums of the pseudo-packet. Network byte order, so one host's
/// octets are every host's (invariant 5).
fn write_tag(pseudo_packet: []const u8, tag: *[tag_len]u8) void {
    const words = tag_len / @sizeOf(u32);
    for (0..words) |index| {
        var crc = std.hash.Crc32.init();
        crc.update(&.{@intCast(index)});
        crc.update(pseudo_packet);
        const word = std.mem.nativeToBig(u32, crc.final());
        @memcpy(tag[index * @sizeOf(u32) ..][0..@sizeOf(u32)], std.mem.asBytes(&word));
    }
}

/// RFC 9000 §8.1.4's token, as a checksum of the address and the instant it expires at.
fn write_token(writer: *Writer, address: []const u8, ids: *const crypto.suite.RetryConnectionIds, now_ns: u64) core.writer.Error!void {
    try writer.write_byte(retry_token_type);
    try writer.write_int(u32, std.hash.Crc32.hash(address));
    try writer.write_int(u64, now_ns +| token_lifetime_ns);
    try writer.write_byte(ids.original_destination_len);
    try writer.write_bytes(ids.original_destination_slice());
    try writer.write_byte(ids.retry_source_len);
    try writer.write_bytes(ids.retry_source_slice());
}

/// A Retry token's rest, after its type octet. RFC 9000 §8.1.4 binds it to an address, so the
/// checksum must match, and accepts it "only for a short time", read back rather than recomputed.
fn read_token(reader: *core.Reader, address: []const u8, now_ns: u64) !crypto.suite.TokenCheck {
    const name = try reader.read_int(u32);
    const expires_ns = try reader.read_int(u64);
    const original_destination = try reader.take(try reader.read_byte());
    const retry_source = try reader.take(try reader.read_byte());
    if (reader.remaining_len() != 0 or name != std.hash.Crc32.hash(address) or now_ns >= expires_ns) return .invalid;
    return .{ .retry = crypto.suite.RetryConnectionIds.of(original_destination, retry_source) };
}

/// Every member the Retry cases do not ask for is unreached: a call to one would mean a test
/// drove something they do not cover.
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
fn unreachable_update(_: *anyopaque) crypto.suite.UpdateError!void {
    unreachable;
}
fn unreachable_phase(_: *const anyopaque) bool {
    unreachable;
}
fn unreachable_discard_previous(_: *anyopaque) void {
    unreachable;
}
fn unreachable_discard(_: *anyopaque, _: Level) void {
    unreachable;
}

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// A client that has sent its first Initial to S1 and heard nothing back, which is the state
/// RFC 9000 §17.2.5.2 has a Retry arrive in.
pub fn open_as(role: connection_module.Role) void {
    checker.init();
    test_connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &c1, .original_destination = &s1 },
    });
}

/// Builds one Retry packet into `datagram` and returns its length.
fn write_retry_into(scid: []const u8, token: []const u8) !usize {
    var writer = Writer.init(&datagram);
    try header_write.write_retry(&writer, .{
        .unused_bits = unused_bits,
        .dcid = &c1,
        .scid = scid,
        .token = token,
    });
    // RFC 9001 §5.8: the tag covers the Retry Pseudo-Packet, which is S1 and the packet so far.
    var pseudo_writer = Writer.init(&pseudo);
    try header_write.write_retry_pseudo_packet(&pseudo_writer, &s1, writer.written());
    var tag: [tag_len]u8 = undefined;
    write_tag(pseudo_writer.written(), &tag);
    try writer.write_bytes(&tag);
    return writer.written().len;
}

/// The same, read back, which is how a caller reaches `receive`.
fn retry_packet(scid: []const u8, token: []const u8) !header.Retry {
    const len = try write_retry_into(scid, token);
    return (try header.read(datagram[0..len], test_connection.identity.local_len())).retry;
}

/// One whose tag was changed after it was written, which is what a forged or corrupted Retry
/// looks like to the endpoint that receives it.
fn retry_packet_bad_tag(scid: []const u8, token: []const u8) !header.Retry {
    const len = try write_retry_into(scid, token);
    datagram[len - 1] ^= 1;
    return (try header.read(datagram[0..len], test_connection.identity.local_len())).retry;
}

fn receive(packet: header.Retry) retry.Outcome {
    return retry.receive(&test_connection, checker.suite(), packet, &pseudo);
}

test "RFC 9000 §17.2.5.2: a client takes a Retry and addresses its Source Connection ID" {
    open_as(.client);
    // Before it arrives the client addresses what it chose (§7.3's Figure 8).
    try testing.expectEqualSlices(u8, &s1, test_connection.identity.destination().slice());

    const outcome = receive(try retry_packet(&s2, &test_token));
    try testing.expectEqualSlices(u8, &s2, outcome.taken.destination);
    // "The client MUST use the value from the Source Connection ID field of the Retry packet in
    // the Destination Connection ID field of subsequent packets that it sends."
    try testing.expectEqualSlices(u8, &s2, test_connection.identity.destination().slice());
    // §8.1.2: the token is kept, to be repeated in every later Initial.
    try testing.expectEqualSlices(u8, &test_token, test_connection.retry_token.slice());
    // The client's own Source Connection ID never moves (§17.2.5.2).
    try testing.expectEqualSlices(u8, &c1, test_connection.identity.source().slice());
}

test "RFC 9001 §5.8: the tag covers the first Destination Connection ID and the Retry less its tag" {
    open_as(.client);
    const packet = try retry_packet(&s2, &test_token);
    _ = receive(packet);
    // "Retry Pseudo-Packet { ODCID Length (8), Original Destination Connection ID (0..160),
    // Retry Packet (..) }", where the Retry Packet is the one received less its tag.
    const covered = seen[0..seen_len];
    try testing.expectEqual(1 + s1.len + packet.without_tag.len, covered.len);
    try testing.expectEqual(s1.len, covered[0]);
    try testing.expectEqualSlices(u8, &s1, covered[1..][0..s1.len]);
    try testing.expectEqualSlices(u8, packet.without_tag, covered[1 + s1.len ..]);
}

test "RFC 9000 §17.2.5.2: a Retry whose Integrity Tag does not validate changes nothing" {
    open_as(.client);
    const outcome = receive(try retry_packet_bad_tag(&s2, &test_token));
    try testing.expectEqual(retry.Discarded.tag_invalid, outcome.discarded);
    try testing.expectEqual(null, test_connection.identity.retry_source);
    try testing.expectEqual(0, test_connection.retry_token.slice().len);
}

test "RFC 9000 §17.2.5.2: at most one Retry is acted on per connection attempt" {
    open_as(.client);
    _ = receive(try retry_packet(&s2, &test_token));
    // "After the client has received and processed an Initial or Retry packet from the server, it
    // MUST discard any subsequent Retry packets that it receives."
    const second = receive(try retry_packet(&s1, &test_token));
    try testing.expectEqual(retry.Discarded.already_answered, second.discarded);
    try testing.expectEqualSlices(u8, &s2, test_connection.identity.destination().slice());
}

test "RFC 9000 §17.2.5.2: a Retry after an Initial from the server is discarded" {
    open_as(.client);
    // §7.2: the server's first Initial carried its Source Connection ID, which the client took.
    test_connection.identity.on_peer_initial(&s2);
    const outcome = receive(try retry_packet(&s1, &test_token));
    try testing.expectEqual(retry.Discarded.already_answered, outcome.discarded);
}

test "RFC 9000 §17.2.5.1: a Retry that echoes the client's Destination Connection ID is discarded" {
    open_as(.client);
    // "This value MUST NOT be equal to the Destination Connection ID field of the packet sent by
    // the client", which is S1 until a Retry moves it.
    const outcome = receive(try retry_packet(&s1, &test_token));
    try testing.expectEqual(retry.Discarded.source_is_destination, outcome.discarded);
}

test "RFC 9000 §17.2.5: a server discards a Retry" {
    open_as(.server);
    const outcome = receive(try retry_packet(&s2, &test_token));
    try testing.expectEqual(retry.Discarded.not_a_client, outcome.discarded);
}

test "RFC 9000 §8.1.2: a token longer than colibri repeats is discarded" {
    open_as(.client);
    const long_token: [constants.token_len_max + 1]u8 = @splat(token_octet);
    const outcome = receive(try retry_packet(&s2, &long_token));
    try testing.expectEqual(retry.Discarded.token_too_long, outcome.discarded);
    // One octet shorter is held, so the refusal is the storage and not the Retry.
    const held: [constants.token_len_max]u8 = @splat(token_octet);
    const taken = receive(try retry_packet(&s2, &held));
    try testing.expectEqualSlices(u8, &s2, taken.taken.destination);
    try testing.expectEqualSlices(u8, &held, test_connection.retry_token.slice());
}

test "RFC 9000 §8.1.2: every Initial after a Retry carries the token" {
    open_as(.client);
    _ = receive(try retry_packet(&s2, &test_token));
    keys.on_keys_installed(&test_connection, .initial, .write);

    var suite_holder: build_test.RoundTrip = undefined;
    suite_holder.init();
    var provider_holder: build_test.Fake = .{ .owed = &test_token, .owed_level = .initial };
    var scratch: packet_build.DefaultScratch = .{};
    const built = (try packet_build.build(
        &test_connection,
        suite_holder.suite(),
        provider_holder.provider(),
        StreamProvider.none(),
        .initial,
        &scratch,
        &datagram,
        test_now_ns,
    )).?;

    // §17.2.2's Token Length and Token, read back off the header this build wrote.
    const parsed = (try header.read(datagram[0..built.len], test_connection.identity.local_len())).long;
    try testing.expectEqualSlices(u8, &test_token, parsed.token);
    // §17.2.5.3: the Destination Connection ID is the Retry's Source Connection ID.
    try testing.expectEqualSlices(u8, &s2, parsed.dcid);
}

test "RFC 9000 §17.2.2: the Token Length and Token are counted when the header is sized" {
    open_as(.client);
    _ = receive(try retry_packet(&s2, &test_token));
    keys.on_keys_installed(&test_connection, .initial, .write);

    var suite_holder: build_test.RoundTrip = undefined;
    suite_holder.init();
    var provider_holder: build_test.Fake = .{ .owed = &filler, .owed_level = .initial };
    var scratch: packet_build.DefaultScratch = .{};
    // A header sized without its Token leaves room for octets the packet cannot hold, so the
    // payload overruns the output and the suite refuses to seal. Building at all is the check.
    const built = (try packet_build.build(
        &test_connection,
        suite_holder.suite(),
        provider_holder.provider(),
        StreamProvider.none(),
        .initial,
        &scratch,
        &output,
        test_now_ns,
    )).?;
    try testing.expect(built.len <= output.len);
    const parsed = (try header.read(output[0..built.len], test_connection.identity.local_len())).long;
    try testing.expectEqualSlices(u8, &test_token, parsed.token);
}

/// The CRYPTO frame of a packet this file built, read back off the octets it wrote.
fn crypto_frame_of(built: packet_build.Built) !frame_module.Frame {
    const parsed = (try header.read(output[0..built.len], test_connection.identity.local_len())).long;
    // RFC 9000 §17.2: byte 0's low two bits are the Packet Number Length less one. `RoundTrip`
    // applies no header protection, so they are readable here.
    const number_len: usize = (output[0] & constants.packet_number_len_mask) + 1;
    const payload = output[parsed.packet_number_offset + number_len .. built.len - constants.aead_tag_len];
    var reader = core.Reader.init(payload);
    return frame_module.read(&reader);
}

fn build_initial(suite_holder: *build_test.RoundTrip, provider_holder: *build_test.Fake) !packet_build.Built {
    var scratch: packet_build.DefaultScratch = .{};
    return (try packet_build.build(
        &test_connection,
        suite_holder.suite(),
        provider_holder.provider(),
        StreamProvider.none(),
        .initial,
        &scratch,
        &output,
        test_now_ns,
    )).?;
}

test "RFC 9000 §17.2.5.3: the Initial after a Retry repeats the handshake message" {
    open_as(.client);
    keys.on_keys_installed(&test_connection, .initial, .write);
    var suite_holder: build_test.RoundTrip = undefined;
    suite_holder.init();
    var provider_holder: build_test.Fake = .{ .owed = &test_token, .owed_level = .initial };

    const first = try build_initial(&suite_holder, &provider_holder);
    const before = (try crypto_frame_of(first)).crypto;
    try testing.expectEqual(0, before.offset);
    var sent: [token_len]u8 = undefined;
    @memcpy(&sent, before.data);
    // The provider gave its octets up and owes nothing more, which is why colibri keeps them.
    try testing.expectEqual(0, provider_holder.owed.len);

    _ = receive(try retry_packet(&s2, &test_token));
    const second = try build_initial(&suite_holder, &provider_holder);
    const after = (try crypto_frame_of(second)).crypto;
    // "A client MUST use the same cryptographic handshake message it included in this packet",
    // and §19.6 starts each level's flow at offset 0, so the repeat starts there too.
    try testing.expectEqual(0, after.offset);
    try testing.expectEqualSlices(u8, &sent, after.data);
    // §17.2.5.3: "A client MUST NOT reset the packet number for any packet number space after
    // processing a Retry packet."
    try testing.expect(second.packet_number > first.packet_number);
}

test "RFC 9000 §17.2.5.3: a Retry is discarded when the first flight was forgotten" {
    open_as(.client);
    // A flight longer than the send window forgets the octets it already framed, which
    // `send_base` above zero is. colibri cannot repeat what it no longer holds.
    test_connection.crypto_at(.initial).send_base = 1;
    const outcome = receive(try retry_packet(&s2, &test_token));
    try testing.expectEqual(retry.Discarded.flight_forgotten, outcome.discarded);
    try testing.expectEqual(null, test_connection.identity.retry_source);
}
