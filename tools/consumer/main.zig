//! The program the consumer project builds: it reaches h11, h2, tls and stdx's gzip through the
//! modules colibri exports, writes a request, reads a response, starts a TLS handshake and codes
//! content, which shows the modules link and run for a project that depends on colibri.
const std = @import("std");
const h11 = @import("h11");
const h2 = @import("h2");
const tls = @import("tls");
const gzip = @import("gzip");
const platform = @import("platform");

var client: h11.connection.Connection align(@alignOf(h11.connection.Connection)) = undefined;
var h2_client: h2.connection.Connection align(@alignOf(h2.connection.Connection)) = undefined;
var tls_config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var tls_client: tls.record.Client align(@alignOf(tls.record.Client)) = undefined;
var output: [4096]u8 = undefined;
var gzip_encoder: gzip.Encoder(.{ .level = 6 }) align(@alignOf(gzip.Encoder(.{ .level = 6 }))) = undefined;
var gzip_decoder: gzip.Decoder align(@alignOf(gzip.Decoder)) = undefined;
var coded: [256]u8 = undefined;

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
    const cpu = platform.probe();
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
    std.debug.print("consumer: h11, h2, tls and gzip link and run as a dependency\n", .{});
}
