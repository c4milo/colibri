//! What the command line asked of the test-only server (`../server.zig`): `main` writes each value
//! once, before any worker starts, and the workers read them (`server_worker.zig`). They are here
//! so neither file imports the other for them. Split off `../server.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const constants = @import("../constants.zig");
const tls = @import("tls");
const server_identity = @import("../tls/server_identity.zig");
const server_options = @import("server_options.zig");

/// The versions the server speaks: h11 and h2, which a connection in cleartext chooses between by
/// its first octets, or one alone with `--h11` or `--h2` (decision 117).
pub var versions: server.Protocols align(@alignOf(server.Protocols)) = .{};
pub var listen_address: [server_options.ipv4_octets]u8 = server_options.loopback_octets;
pub var echo_mode: bool = false;
/// The route table whose router of `server_routes.zig` answers every request (`--routes`), or
/// none.
pub var routes_mode: server_options.Routes align(@alignOf(server_options.Routes)) = .none;
/// Whether responses are coded (`--coded`), in gzip or deflate, gzip first.
pub var coded_mode: bool = false;
pub const served_codings = [_]server.Coding{ .gzip, .deflate };
/// The Unix seconds the server starts at (`--seconds`), which its session tickets carry, or null
/// for none (decision 161).
pub var unix_seconds: ?u64 = null;
/// The h3 endpoint each TLS connection advertises (`--h3-port`), or null.
pub var h3_alternative: ?server.Alternative align(@alignOf(?server.Alternative)) = null;

/// The TLS mode's identity (`--tls`), or null in cleartext, and the storage it points into. It
/// names no protocol: each worker's engine builds its TLS configuration from it, checks that
/// its key signs, and offers through ALPN the protocols `versions` allows (decision 119).
pub var identity: ?tls.Server align(@alignOf(?tls.Server)) = null;
pub var identity_storage: server_identity.Storage align(@alignOf(server_identity.Storage)) = undefined;

/// The content of every answer the server writes, `constants.response_body`, or `--body`'s
/// octets, and its fields (RFC 9110 §8.3, §8.6, design §8 step 13n).
pub var answer_body: []const u8 = constants.response_body;
pub var answer_fields: [answer_field_count]server.Header align(@alignOf(server.Header)) = .{
    .{ .name = "content-type", .value = constants.response_content_type },
    .{ .name = "content-length", .value = constants.response_content_length },
};
var answer_length_digits: [constants.content_length_digits_max]u8 = undefined;
/// The fields of every answer: its media type and its length.
const answer_field_count = 2;

/// Makes every answer carry `len` octets of `constants.answer_body_octets` (`--body`).
pub fn set_answer_body(len: u32) void {
    assert(len > 0 and len <= constants.answer_body_len_max);
    answer_body = constants.answer_body_octets[0..len];
    answer_fields[answer_fields.len - 1].value = std.fmt.bufPrint(&answer_length_digits, "{d}", .{len}) catch unreachable;
}

/// Makes every answer carry `constants.response_body` again, for a test that set another.
pub fn reset_answer_body() void {
    answer_body = constants.response_body;
    answer_fields[answer_fields.len - 1].value = constants.response_content_length;
}
