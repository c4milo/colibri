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
const frame_module = @import("../frame/frame.zig");
const header = @import("../packet/packet_header.zig");
const header_write = @import("../packet/packet_header_write.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const identity_module = @import("connection_identity.zig");
const keys = @import("connection_keys.zig");
const retry = @import("connection_retry.zig");
const packet_build = @import("packet_build.zig");
const build_test = @import("packet_build_test.zig");

const testing = std.testing;
const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

var test_connection: Connection = undefined;
var checker: TagChecker = undefined;
var pseudo: [constants.retry_pseudo_packet_len_max]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;

/// RFC 9000 §7.3's Figure 8: C1 is the client's own, S1 the connection ID it first addressed and
/// S2 the one the Retry carries. Fixed octets, because §5.1 wants them unpredictable and
/// invariant 5 forbids colibri a random number.
const c1_octet: u8 = 0xc1;
const s1_octet: u8 = 0x51;
const s2_octet: u8 = 0x52;
const id_len: usize = 8;
const c1: [id_len]u8 = @splat(c1_octet);
const s1: [id_len]u8 = @splat(s1_octet);
const s2: [id_len]u8 = @splat(s2_octet);

/// The Retry Token of §17.2.5, as octets nothing reads the value of.
const token_octet: u8 = 0x7c;
const token_len: usize = 24;
const test_token: [token_len]u8 = @splat(token_octet);

/// RFC 9000 §17.2.5: the four bits of byte 0 a server sets to anything and a client ignores.
const unused_bits: u8 = 0x0f;

const datagram_len: usize = 512;
var datagram: [datagram_len]u8 = undefined;
/// Where a built packet goes, apart from the Retry `datagram` holds.
var output: [datagram_len]u8 = undefined;
/// More handshake octets than a packet can hold, so what bounds a payload is the room the header
/// left rather than what the provider owes.
const filler_octet: u8 = 0x6d;
const filler: [datagram_len]u8 = @splat(filler_octet);

/// The last pseudo-packet the suite was handed, which RFC 9001 §5.8 defines. It is a file
/// variable and not a field because `retry_tag_valid` takes a `*const` context: a real suite
/// reads its keys there and writes nothing.
var seen: [constants.retry_pseudo_packet_len_max]u8 = @splat(0);
var seen_len: usize = 0;

/// A `crypto.Suite` that answers RFC 9001 §5.8's question and nothing else.
const TagChecker = struct {
    /// What `retry_tag_valid` answers. Test-only.
    valid: bool,

    fn init(held: *TagChecker) void {
        held.* = .{ .valid = true };
        seen_len = 0;
    }

    fn suite(held: *TagChecker) crypto.Suite {
        return .{ .context = held, .vtable = &vtable };
    }

    fn tag_valid(
        context: *const anyopaque,
        pseudo_packet: []const u8,
        tag: *const [crypto.constants.retry_integrity_tag_len]u8,
    ) bool {
        _ = tag;
        const held: *const TagChecker = @ptrCast(@alignCast(context));
        @memcpy(seen[0..pseudo_packet.len], pseudo_packet);
        seen_len = pseudo_packet.len;
        return held.valid;
    }

    const vtable: crypto.suite.VTable = .{
        .install_initial_keys = unreachable_install,
        .keys_available = unreachable_available,
        .seal = unreachable_seal,
        .open = unreachable_open,
        .retry_tag_valid = tag_valid,
        .retry_tag_write = unreachable_tag_write,
        .update_keys = unreachable_update,
        .key_phase = unreachable_phase,
        .discard_previous_keys = unreachable_discard_previous,
        .discard_keys = unreachable_discard,
    };
};

/// Every member but `retry_tag_valid` is unreached: a call to one would mean a test drove
/// something these cases do not cover.
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
fn unreachable_tag_write(
    _: *const anyopaque,
    _: []const u8,
    _: *[crypto.constants.retry_integrity_tag_len]u8,
) crypto.suite.RetryTagError!void {
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
fn open_as(role: connection_module.Role) void {
    checker.init();
    test_connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &c1, .original_destination = &s1 },
    });
}

/// Builds one Retry packet and reads it back, which is how a caller reaches `receive`.
fn retry_packet(scid: []const u8, token: []const u8) !header.Retry {
    var writer = Writer.init(&datagram);
    try header_write.write_retry(&writer, .{
        .unused_bits = unused_bits,
        .dcid = &c1,
        .scid = scid,
        .token = token,
    });
    // RFC 9000 §17.2.5: the packet ends with a 16-octet Retry Integrity Tag. This suite does not
    // read its value, so any octets stand for one.
    const tag: [crypto.constants.retry_integrity_tag_len]u8 = @splat(0);
    try writer.write_bytes(&tag);
    const parsed = try header.read(writer.written(), test_connection.identity.local_len());
    return parsed.retry;
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
    checker.valid = false;
    const outcome = receive(try retry_packet(&s2, &test_token));
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
