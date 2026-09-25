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
const check_file = @import("check_file.zig");
const check_socket = @import("check_socket.zig");

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
/// What this run reads from the socket, the plaintext it opens it into, and the room chapulin
/// writes what it owes the server into.
var input: check_socket.Input = .{};
var plaintext_storage: [constants.tls_record_buffer_len]u8 = undefined;
var output_storage: [constants.tls_record_buffer_len]u8 = undefined;

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
    const drawn = try check_file.read_file("/dev/urandom", &seed);
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
    if (!admitted(negotiated.cipher_suite)) {
        std.debug.print("tls-handshake: colibri does not admit suite 0x{x:0>4}\n", .{negotiated.cipher_suite});
        std.process.exit(exit_failed);
    }
}

/// RFC 9846 §7.5: prints the keying material exported under the label and context the peer also
/// uses. `tools/tls_handshake.sh` compares it with the value the peer printed, and two ends that
/// disagree derived different secrets from one handshake.
fn report_exporter() void {
    const held = client.provider();
    var exported: [constants.tls_exporter_len]u8 = undefined;
    held.vtable.export_keying_material(
        held.context,
        constants.tls_exporter_label,
        constants.tls_exporter_context,
        &exported,
    ) catch |failure| {
        std.debug.print("tls-handshake: the exporter refused: {t}\n", .{failure});
        std.process.exit(exit_failed);
    };
    std.debug.print("tls-handshake: exporter {x}\n", .{exported[0..]});
}

/// RFC 9113 §9.2 and [decision 45](../../../docs/decisions.md): `attach_tls` refuses a suite
/// colibri does not admit, so a handshake that completed on one is not a session h2 could use.
/// Printing the codepoint is not enough; this is what makes the run fail on it.
fn admitted(suite: u16) bool {
    for (tls.constants.cipher_suites_admitted) |candidate| {
        if (suite == candidate) return true;
    }
    return false;
}

pub fn main(init: std.process.Init.Minimal) !void {
    if (!chapulin.available) {
        std.debug.print("tls-handshake: built without chapulin; pass -Dchapulin-client=<checkout>\n", .{});
        std.process.exit(exit_usage);
    }
    const asked = parse(init);
    const anchor_name = try check_file.read_part(asked.anchor_prefix, ".name", &name_storage);
    const spki = try check_file.read_part(asked.anchor_prefix, ".spki", &spki_storage);
    try chapulin.check_build();
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
    client.init(.{
        .anchors = &anchors,
        .hostname = asked.hostname,
        .now_seconds = asked.now_seconds,
        .receive = receive_storage[0..asked.receive_len],
    });
    client.start() catch {
        std.debug.print("tls-handshake: ch_record_init refused the configuration\n", .{});
        std.process.exit(exit_failed);
    };
    try run_handshake(socket);
    report(asked.receive_len);
    report_exporter();
    try read_until_data(socket);
}

/// Writes what chapulin owes the server and hands it what the server sends, until the handshake
/// completes. The socket blocks, which decision 46 permits here: this check serves one connection
/// and exits, and is not one of design §9's endpoints.
fn run_handshake(socket: std.c.fd_t) !void {
    // Bounded: each pass reads at least one octet after it writes, and a handshake is a few
    // records.
    for (0..check_socket.handshake_reads_max) |_| {
        const progress = client.handshake(input.unread(), &output_storage) catch |failure| {
            std.debug.print("tls-handshake: {t}: {s} (code {d}, alert {d})\n", .{
                failure,
                chapulin_client.reason(client.code),
                client.code,
                client.alert(),
            });
            std.process.exit(exit_failed);
        };
        try check_socket.write_all(socket, output_storage[0..progress.written]);
        input.take(progress.consumed);
        if (progress.complete) return;
        try input.read_more(socket);
    }
    std.debug.print("tls-handshake: the handshake did not complete in {d} reads\n", .{
        check_socket.handshake_reads_max,
    });
    std.process.exit(exit_failed);
}

/// Opens what the server sends after its handshake until a record carries application data. Go's
/// h2 server sends a NewSessionTicket (RFC 9846 §4.6.1) and then its SETTINGS. A record that
/// carries no data must leave the session live, which chapulin's `TRANSPORT=tls` client could not
/// (https://github.com/c4milo/colibri/issues/62).
fn read_until_data(socket: std.c.fd_t) !void {
    const held = client.provider();
    var messages: usize = 0;
    for (0..post_handshake_records_max) |_| {
        const record = try input.read_record(socket);
        const opened = held.vtable.decrypt_record(held.context, record, &plaintext_storage) catch |failure| {
            std.debug.print("tls-handshake: a record after the handshake did not open: {t}\n", .{failure});
            std.process.exit(exit_failed);
        };
        input.take(opened.consumed);
        switch (opened.content) {
            .new_session_ticket, .key_update => messages += 1,
            .application_data => {
                std.debug.print("tls-handshake: records ok, {d} carried no data, then {d} octets of data\n", .{
                    messages,
                    opened.plaintext_len,
                });
                return;
            },
            else => {
                std.debug.print("tls-handshake: a record after the handshake held {t}\n", .{opened.content});
                std.process.exit(exit_failed);
            },
        }
    }
    std.debug.print("tls-handshake: no data in the first {d} records\n", .{post_handshake_records_max});
    std.process.exit(exit_failed);
}

/// The records the check opens after the handshake before it expects data: a server's tickets,
/// with room to spare.
const post_handshake_records_max: usize = 8;

/// Opens one connection to the peer. The socket stays blocking: this check serves one connection
/// and exits.
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

const exit_usage = check_file.exit_usage;
const exit_failed = check_file.exit_failed;
