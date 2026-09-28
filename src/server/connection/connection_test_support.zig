//! What the server's tests share: the connection they drive, the buffers it reads and writes, and
//! for the TLS tests a colibri client over the identity in `testdata/`, which
//! `tools/h2_interop/tls_identity.go` minted at `now_seconds`. The session sources are SplitMix64
//! from a seed, so every run draws the same octets. Test-only.
const std = @import("std");
const tls = @import("tls");
const tls_provider = @import("tls_provider");
const connection_module = @import("connection.zig");

const event = @import("../event.zig");

const Connection = connection_module.Connection;
const Config = connection_module.Config;
const Received = connection_module.Received;
pub const Field = connection_module.Field;
pub const server_constants = @import("../constants.zig");
pub const Request = event.Request;
pub const Trailers = event.Trailers;

pub const leaf = @embedFile("../testdata/identity.leaf.der");
pub const root = @embedFile("../testdata/identity.ca.der");
pub const root_name = @embedFile("../testdata/identity.name");
pub const root_spki = @embedFile("../testdata/identity.spki");
pub const private_key: *const [tls.constants.p256_private_key_len]u8 = @embedFile("../testdata/identity.priv");
pub const public_key: *const [tls.constants.p256_public_key_len]u8 = @embedFile("../testdata/identity.pub");

/// The instant the identity was minted, inside the 48 hours its certificates are valid for.
pub const now_seconds: u64 = 1_790_477_172;

/// The instant each call passes, in nanoseconds. The tests hold it still.
pub const now_ns: u64 = 1_000_000;

pub const chain = [_][]const u8{ leaf, root };
pub const anchors = [_]tls.Anchor{.{ .subject = root_name, .spki = root_spki }};
pub const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_key_octet);
const cookie_key_octet: u8 = 0x07;

/// The ALPN lists: the server's preference, h2 first (decision 88), and each a client offers.
pub const protocols_both = [_][]const u8{ "h2", "http/1.1" };
pub const protocols_h11 = [_][]const u8{"http/1.1"};
pub const protocols_h2 = [_][]const u8{"h2"};

/// The connection the tests drive, its configuration, and what it sends, outside any stack frame.
pub var connection: Connection align(@alignOf(Connection)) = undefined;
pub var config: Config align(@alignOf(Config)) = .{};
pub var output: [output_len]u8 = undefined;
pub var input: [input_len]u8 = undefined;

/// Room for everything one test's connection sends, and for what its peer sends.
pub const output_len: usize = 65_536;
pub const input_len: usize = 65_536;

/// A cleartext connection speaking `protocol`, with nothing read or written.
pub fn start_cleartext(protocol: connection_module.Protocol) !void {
    config = .{ .cleartext = protocol };
    try connection.init(&config, stream.random(), 0);
}

/// Copies `octets` into the test input and reads one event from it.
pub fn receive_copy(octets: []const u8) !Received {
    @memcpy(input[0..octets.len], octets);
    return connection.receive(input[0..octets.len], now_ns);
}

/// Reads the `done` event of request `id`, which comes before anything more is read (decision
/// 103).
pub fn expect_done(id: u64) !void {
    const received = try connection.receive(&.{}, now_ns);
    try std.testing.expectEqual(0, received.consumed);
    try std.testing.expectEqual(id, received.event.?.done.id);
}

/// Everything the connection owes, sent in one call.
pub fn drain() []const u8 {
    const written = connection.send(&output, now_ns);
    std.debug.assert(connection.output_len == 0);
    return output[0..written];
}

/// The source the sessions of the tests draw from.
pub var stream: Stream align(@alignOf(Stream)) = .{ .state = seed };

/// The seed the tests use.
pub const seed: u64 = 0x7365_7276_6572_2121;

pub const Stream = struct {
    state: u64,

    /// The source a session draws from, which points at this stream: the stream outlives the
    /// session.
    pub fn random(self: *Stream) tls.Random {
        return tls.Random.init(self, fill);
    }

    fn fill(self: *Stream, buffer: []u8) void {
        for (buffer) |*octet| {
            self.state +%= increment;
            var mixed = self.state;
            mixed = (mixed ^ (mixed >> shift_first)) *% multiplier_first;
            mixed = (mixed ^ (mixed >> shift_second)) *% multiplier_second;
            octet.* = @truncate(mixed ^ (mixed >> shift_third));
        }
    }
};

/// SplitMix64's increment, multipliers and shifts.
const increment: u64 = 0x9e37_79b9_7f4a_7c15;
const multiplier_first: u64 = 0xbf58_476d_1ce4_e5b9;
const multiplier_second: u64 = 0x94d0_49bb_1331_11eb;
const shift_first: u6 = 30;
const shift_second: u6 = 27;
const shift_third: u6 = 31;

/// The TLS configurations and the client the TLS tests run against the connection.
pub var server_config: tls.record.ServerConfig align(@alignOf(tls.record.ServerConfig)) = undefined;
pub var client_config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
pub var client: tls.record.Client align(@alignOf(tls.record.Client)) = undefined;

/// What the client has not read yet, and the plaintext it opened.
pub var to_client: [output_len]u8 = undefined;
pub var to_client_len: usize = 0;
pub var opened: [output_len]u8 = undefined;

/// Calls each side makes before a handshake in memory must have completed.
const handshake_rounds_max: usize = 8;

/// A TLS connection whose server offers `server_protocols` and whose client offers
/// `client_protocols`, with the handshake run until both sides complete it.
pub fn start_tls(server_protocols: []const []const u8, client_protocols: []const []const u8) !void {
    try server_config.init(.{
        .ecdsa_p256 = .{ .chain = &chain, .public_key = public_key, .private_key = private_key },
        .cookie_key = &cookie_key,
        .alpn = server_protocols,
    });
    try client_config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "localhost" } },
        .alpn = client_protocols,
    });
    config = .{ .tls = &server_config };
    try connection.init(&config, stream.random(), now_seconds);
    try client.start(&client_config, stream.random(), now_seconds, null);
    to_client_len = 0;
    client_saw_alert = false;
    try run_handshake();
}

/// Moves the flights between the client and the connection until the client completes.
fn run_handshake() !void {
    var to_server_len: usize = 0;
    for (0..handshake_rounds_max) |_| {
        if (!client.state.completed) {
            const progress = try client.handshake(to_client[0..to_client_len], input[to_server_len..]);
            take_to_client(progress.consumed);
            to_server_len += progress.written;
        }
        const received = connection.receive(input[0..to_server_len], now_ns) catch return error.TestUnexpectedResult;
        std.mem.copyForwards(u8, &input, input[received.consumed..to_server_len]);
        to_server_len -= received.consumed;
        to_client_len += connection.send(to_client[to_client_len..], now_ns);
        if (client.state.completed and connection.protocol() != null) return;
    }
    return error.TestUnexpectedResult;
}

fn take_to_client(consumed: usize) void {
    std.mem.copyForwards(u8, &to_client, to_client[consumed..to_client_len]);
    to_client_len -= consumed;
}

/// Seals `plaintext` into the test input from `offset` as the client's records, starting a
/// record, and returns the offset after them.
pub fn seal_all(offset: usize, plaintext: []const u8) !usize {
    const provider = client.provider();
    var sealed_len: usize = offset;
    var taken: usize = 0;
    // Bounded: each record takes at least one octet of plaintext.
    for (0..plaintext.len) |_| {
        if (taken == plaintext.len) break;
        const sealed = try provider.vtable.encrypt_record(provider.context, plaintext[taken..], input[sealed_len..]);
        taken += sealed.consumed;
        sealed_len += sealed.written;
    }
    return sealed_len;
}

/// Seals `plaintext` as the client's records and reads one event from them.
pub fn receive_sealed(plaintext: []const u8) !Received {
    const sealed_len = try seal_all(0, plaintext);
    return connection.receive(input[0..sealed_len], now_ns);
}

/// Sends what the connection owes to the client, and opens every whole record of it.
pub fn open_sent() ![]const u8 {
    to_client_len += connection.send(to_client[to_client_len..], now_ns);
    const provider = client.provider();
    var gathered: usize = 0;
    for (0..output_len) |_| {
        const record = provider.vtable.decrypt_record(provider.context, to_client[0..to_client_len], opened[gathered..]) catch |failure| {
            // The client reads a close_notify as the end of the data, and nothing after it.
            if (failure == error.TlsFailed) break;
            return failure;
        };
        if (record.content == .incomplete) break;
        take_to_client(record.consumed);
        gathered += record.plaintext_len;
        // RFC 9846 §6.1: the close_notify is the last record the connection sends.
        if (record.content == .alert) {
            client_saw_alert = true;
            break;
        }
    }
    return opened[0..gathered];
}

/// Whether the client opened an alert, such as the connection's close_notify.
pub var client_saw_alert: bool = false;

/// The content type of an alert record (RFC 9846 §5.1).
pub const content_alert: u8 = 21;
/// A TLS record's header: its content type, version and length (RFC 9846 §5.1).
pub const record_header_len: usize = tls_provider.constants.record_header_len;
