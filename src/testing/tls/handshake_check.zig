//! Runs one TLS 1.3 handshake against a real server and reports what it negotiated. The first
//! half of design §8 step 5's check.
//!
//! What it proves: chapulin's client, behind colibri's `tls.Provider`, completes a handshake with
//! a server that is not colibri's, and the two agree on ALPN. RFC 9113 §3.1 makes that agreement
//! the thing h2 over TLS rests on.
//!
//! What it does not do is speak h2. That follows once the handshake is proved, because it is the
//! same session with `attach_tls` on top.
//!
//! The trust anchor is the SubjectPublicKeyInfo of the CA the peer minted, read from the file the
//! peer wrote. colibri pins that one root and nothing else, so a chain from any other root fails.
const std = @import("std");
const tls = @import("tls");
const constants = @import("../constants.zig");
const chapulin = @import("chapulin.zig");
const chapulin_client = @import("chapulin_client.zig");

const c = chapulin.c;
const Client = chapulin_client.Client;

/// The largest SubjectPublicKeyInfo the check reads. An RSA-4096 SPKI is about 550 octets, so
/// this holds any key the peer is likely to mint.
const spki_len_max: usize = 1024;

/// The client, placed outside any stack frame: it carries chapulin's session and its receive
/// buffer, which are larger than a stack frame should hold.
var client: Client = undefined;
var spki_storage: [spki_len_max]u8 = undefined;
/// chapulin's receive buffer, which the run may shrink to measure the smallest that works.
var receive_storage: [constants.tls_receive_len]u8 = undefined;
/// The root's Subject Name DER, which the anchor carries beside the key.
var name_storage: [spki_len_max]u8 = undefined;
/// A path, held null-terminated for libc. Long enough for any path a run uses.
const path_len_max: usize = 4096;
var path_storage: [path_len_max:0]u8 = undefined;

/// What the run was asked to do.
const Arguments = struct {
    port: u16,
    anchor_prefix: []const u8,
    hostname: []const u8,
    /// Seconds since 1970-01-01T00:00:00Z. A webpki chain is valid only at a time, and no file
    /// under `src/` may read a clock (non-negotiable 3), so the caller reads it and passes it in.
    /// `tools/tls_handshake.sh` passes `date +%s`.
    now_seconds: u64,
    /// How much of the receive buffer to lend chapulin, which a run shrinks to measure the
    /// smallest a real server's flight fits in.
    receive_len: usize,
};

fn parse(init: std.process.Init.Minimal) Arguments {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.next();
    const port_text = arguments.next() orelse usage();
    const anchor_prefix = arguments.next() orelse usage();
    const hostname = arguments.next() orelse usage();
    const now_text = arguments.next() orelse usage();
    const receive_len = if (arguments.next()) |text|
        std.fmt.parseUnsigned(usize, text, decimal) catch usage()
    else
        receive_storage.len;
    if (receive_len == 0 or receive_len > receive_storage.len) usage();
    return .{
        .port = std.fmt.parseUnsigned(u16, port_text, decimal) catch usage(),
        .anchor_prefix = anchor_prefix,
        .hostname = hostname,
        .now_seconds = std.fmt.parseUnsigned(u64, now_text, decimal) catch usage(),
        .receive_len = receive_len,
    };
}

/// Seeds chapulin's DRBG, which a `RAND=drbg` build requires before any handshake. This endpoint
/// may read the operating system's entropy; the library may not, and does not.
fn seed_chapulin() !void {
    var seed: [chapulin.seed_len]u8 = undefined;
    const drawn = try read_file("/dev/urandom", &seed);
    if (drawn.len != seed.len) {
        std.debug.print("tls-handshake: could not draw a seed\n", .{});
        std.process.exit(exit_failed);
    }
    c.ch_drbg_seed(&seed);
}

/// Reports what the handshake negotiated, and refuses anything but h2.
fn report(receive_len: usize) void {
    const held = client.provider();
    const alpn = held.vtable.negotiated_alpn(held.context) orelse {
        // RFC 9113 §3.1: without "h2" there is no HTTP/2 to speak, and colibri's `attach_tls`
        // refuses the session rather than guessing.
        std.debug.print("tls-handshake: the server selected no protocol\n", .{});
        std.process.exit(exit_failed);
    };
    const negotiated = held.vtable.negotiated_parameters(held.context).?;
    std.debug.print(
        "tls-handshake: complete alpn={s} version=0x{x:0>4} suite=0x{x:0>4} buf_len={d}\n",
        .{ alpn, negotiated.version, negotiated.cipher_suite, receive_len },
    );
    if (!std.mem.eql(u8, alpn, "h2")) std.process.exit(exit_failed);
}

pub fn main(init: std.process.Init.Minimal) !void {
    if (!chapulin.available) {
        std.debug.print("tls-handshake: built without chapulin; pass -Dchapulin-client=<checkout>\n", .{});
        std.process.exit(exit_usage);
    }
    const asked = parse(init);
    const anchor_name = try read_anchor_part(asked.anchor_prefix, ".name", &name_storage);
    const spki = try read_anchor_part(asked.anchor_prefix, ".spki", &spki_storage);
    try seed_chapulin();

    const socket = try connect(asked.port);
    defer _ = std.c.close(socket);

    // A chapulin anchor is the root's Subject Name and its SubjectPublicKeyInfo, each the whole
    // DER TLV. colibri pins this one root and nothing else, so a chain from any other fails.
    const anchors = [_]c.ch_trust_anchor{.{
        .name = anchor_name.ptr,
        .name_len = anchor_name.len,
        .spki = spki.ptr,
        .spki_len = spki.len,
    }};
    try client.init(.{
        .anchors = &anchors,
        .hostname = asked.hostname,
        .socket = socket,
        .now_seconds = asked.now_seconds,
        .receive = receive_storage[0..asked.receive_len],
    });
    client.handshake() catch {
        std.debug.print("tls-handshake: {s} (code {d})\n", .{
            chapulin_client.reason(client.code),
            client.code,
        });
        std.process.exit(exit_failed);
    };
    report(asked.receive_len);
}

/// Reads one half of the anchor the peer wrote, whose path is the prefix and the suffix. The
/// read goes through libc rather than a reader that allocates, because no source file under
/// `src/` takes an allocator (CLAUDE.md non-negotiable 4), test-only or not.
fn read_anchor_part(prefix: []const u8, suffix: []const u8, into: []u8) ![]const u8 {
    var joined: [path_len_max]u8 = undefined;
    if (prefix.len + suffix.len >= joined.len) std.process.exit(exit_usage);
    @memcpy(joined[0..prefix.len], prefix);
    @memcpy(joined[prefix.len..][0..suffix.len], suffix);
    return read_file(joined[0 .. prefix.len + suffix.len], into);
}

/// Reads up to `into.len` octets of `path`, and returns what it read.
fn read_file(path: []const u8, into: []u8) ![]const u8 {
    if (path.len >= path_storage.len) std.process.exit(exit_usage);
    @memcpy(path_storage[0..path.len], path);
    path_storage[path.len] = 0;
    const descriptor = std.c.open(&path_storage, .{});
    if (descriptor < 0) {
        std.debug.print("tls-handshake: cannot read {s}\n", .{path});
        std.process.exit(exit_usage);
    }
    defer _ = std.c.close(descriptor);
    var written: usize = 0;
    // Bounded by the caller's slice: a read of zero is the end of the file.
    while (written < into.len) {
        const read = std.c.read(descriptor, into[written..].ptr, into.len - written);
        if (read <= 0) break;
        written += @intCast(read);
    }
    return into[0..written];
}

/// Opens one connection to the peer. The socket stays blocking: chapulin drives the handshake
/// itself and none of its callbacks can report "nothing yet" (decision 46).
fn connect(port: u16) !std.c.fd_t {
    const socket = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
    if (socket < 0) return error.SocketFailed;
    const peer: std.c.sockaddr.in = .{
        // The wire is network byte order whatever the host's is.
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(loopback),
    };
    if (std.c.connect(socket, @ptrCast(&peer), @sizeOf(std.c.sockaddr.in)) < 0) {
        _ = std.c.close(socket);
        return error.ConnectRefused;
    }
    return socket;
}

fn usage() noreturn {
    std.debug.print("usage: tls-handshake <port> <anchor-prefix> <hostname> <unix-seconds> [buf-len]\n", .{});
    std.process.exit(exit_usage);
}

/// The address the peer listens on. The check runs against a peer on this machine.
const loopback: [ipv4_octets]u8 = .{ loopback_first, 0, 0, 1 };
/// How many octets an IPv4 address has (RFC 791 §3.1).
const ipv4_octets: usize = 4;
/// The first octet of 127.0.0.0/8, which RFC 1122 §3.2.1.3 reserves for the local host.
const loopback_first: u8 = 127;

/// The radix every number on the command line is written in.
const decimal: u8 = 10;

const exit_usage: u8 = 2;
const exit_failed: u8 = 1;
