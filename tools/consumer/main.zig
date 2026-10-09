//! The program the consumer project builds: it reaches h11, h2, tls, server, client and stdx's
//! gzip through the modules colibri exports, writes a request, reads a response, starts a TLS
//! handshake, codes content and moves a request through the server and the client, which shows the
//! modules link and run for a project that depends on colibri.
const std = @import("std");
const h11 = @import("h11");
const h2 = @import("h2");
const tls = @import("tls");
const gzip = @import("gzip");
const server_module = @import("server");
const client_module = @import("client");
const platform = @import("platform");

var client: h11.Connection align(@alignOf(h11.Connection)) = undefined;
var h2_client: h2.Connection align(@alignOf(h2.Connection)) = undefined;
var tls_config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var tls_client: tls.record.Client align(@alignOf(tls.record.Client)) = undefined;
var output: [4096]u8 = undefined;
var gzip_encoder: gzip.Encoder(.{ .level = 6 }) align(@alignOf(gzip.Encoder(.{ .level = 6 }))) = undefined;
var gzip_decoder: gzip.Decoder align(@alignOf(gzip.Decoder)) = undefined;
var coded: [256]u8 = undefined;
// The server's and the client's connections hold hundreds of kilobytes, so they live outside the
// stack, as every connection does.
var served: server_module.Connection align(@alignOf(server_module.Connection)) = undefined;
var asked: client_module.Connection align(@alignOf(client_module.Connection)) = undefined;
var exchange: client_module.HttpExchange align(@alignOf(client_module.HttpExchange)) = .{ .method = "GET", .path = "/" };
var wire: [4096]u8 = undefined;

/// Rounds of moving octets between the client and the server before the exchange must have ended.
const exchange_rounds_max = 8;
/// Events one side reads in one round, at most.
const events_per_round_max = 16;

/// chapulin's one hook, which a program that links colibri's `tls` defines: its failed assertions
/// are the program's to report.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}

/// The source each TLS session draws from, which the program passes to `start`: here the operating
/// system's `getentropy`, which keeps no state.
extern "c" fn getentropy(buffer: [*]u8, len: usize) c_int;
const getentropy_len_max = 256;
var entropy_state: u8 = 0;
const entropy: std.Random = .{ .ptr = &entropy_state, .fillFn = fill_entropy };

fn fill_entropy(_: *anyopaque, buffer: []u8) void {
    var filled: usize = 0;
    while (filled < buffer.len) {
        const part = @min(buffer.len - filled, getentropy_len_max);
        if (getentropy(buffer[filled..].ptr, part) != 0) @panic("getentropy failed");
        filled += part;
    }
}

/// A root this client never meets a chain of: an empty DER SEQUENCE for its name and its key.
const empty_sequence = [_]u8{ 0x30, 0 };
/// Unix seconds, which a program reads from its clock; colibri reads none.
const now_seconds: u64 = 1_800_000_000;
/// RFC 9846 §5.1: a handshake record's content type.
const handshake_record: u8 = 22;

pub fn main() !void {
    client.init(.client, .{});
    const head_len = try client.write_request(&output, "GET", "/", &.{
        .{ .name = "Host", .value = "example.test" },
    });
    if (!std.mem.startsWith(u8, output[0..head_len], "GET / HTTP/1.1\r\n")) return error.RequestWrong;
    const step = try client.receive("HTTP/1.1 204 No Content\r\n\r\n", &.{});
    const status = step.event.?.response.line.status.code;
    if (status != 204) return error.ResponseWrong;

    // h2's client preface starts with the 24 octets of RFC 9113 §3.4.
    h2_client.init(.client);
    const preface_len = h2_client.write_pending(&output, 0);
    if (!std.mem.startsWith(u8, output[0..preface_len], "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) return error.PrefaceWrong;

    // tls converts the client's values once, and a session's first call writes its ClientHello. The
    // program probes its CPU once, through stdx's `platform`, and passes the result on.
    const cpu: tls.Cpu = .{ .probe = platform.probe(), .timing = .not_stated };
    const anchors = [_]tls.Anchor{.{ .subject = &empty_sequence, .spki = &empty_sequence }};
    try tls_config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "example.test" } },
        .alpn = &.{ "h2", "http/1.1" },
        .cpu = cpu,
    });
    try tls_client.start(&tls_config, entropy, now_seconds, null);
    const hello = try tls_client.handshake(&.{}, &output);
    if (hello.written == 0 or output[0] != handshake_record) return error.HelloWrong;
    tls_client.close();

    // stdx's gzip, which colibri's package exports (decision 101), codes content and decodes it.
    gzip_encoder.init(.target());
    const coded_len = try gzip_encoder.encode_all("colibri", &coded);
    gzip.init(&gzip_decoder, .target());
    const decoded = try gzip.decode_all(&gzip_decoder, coded[0..coded_len], &output);
    if (!std.mem.eql(u8, output[0..decoded.written], "colibri")) return error.CodingWrong;

    // The `server` and `client` modules (decision 100), in cleartext h2: the client's request and
    // the server's 204 move between the two in memory, at one instant. The client allows h2 alone,
    // so it speaks h2 with prior knowledge, and the server, which names no version, reads h2 from
    // the client's connection preface (decision 117).
    const server_config: server_module.Config = .{};
    const client_config: client_module.Config = .{ .versions = .{ .h11 = false }, .authority = "example.test" };
    try served.init(&server_config, entropy, 0, 0);
    try asked.init(&client_config, entropy, 0, null);
    _ = try asked.request(&exchange);
    for (0..exchange_rounds_max) |_| {
        try serve(asked.send(&wire, 0));
        hear(served.send(&wire, 0));
    }
    if (exchange.outcome != .response or exchange.status != 204) return error.ExchangeWrong;
    std.debug.print("consumer: h11, h2, tls, gzip, server and client link and run as a dependency\n", .{});
}

/// The server reads the first `len` octets of `wire` and answers each request with 204.
fn serve(len: usize) !void {
    var consumed: usize = 0;
    for (0..events_per_round_max) |_| {
        const received = try served.receive(wire[consumed..len], 0);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        if (event == .request) try served.respond(event.request.id.number, .{ .status = 204, .end = true });
    }
}

/// The client reads the first `len` octets of `wire`, and its exchange holds what they say.
fn hear(len: usize) void {
    var consumed: usize = 0;
    for (0..events_per_round_max) |_| {
        const received = asked.receive(wire[consumed..len], 0);
        consumed += received.consumed;
        if (received.event == null and received.consumed == 0) return;
    }
}
