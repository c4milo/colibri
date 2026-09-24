//! Runs one TLS 1.3 handshake as the server, against a client that is not colibri's, and then
//! moves one record each way through the vtable. The second half of design §8 step 5's check.
//!
//! What it proves, which the client half cannot: chapulin's server behind colibri's
//! `tls.Provider` completes a handshake with Go's `crypto/tls`, the two agree on "h2"
//! (RFC 9113 §3.1), and the record phase works from the server side — `decrypt_record` opens what
//! the peer sealed, `encrypt_record` seals the answer, and the peer's `close_notify` arrives as
//! the end of its data rather than as a failure (RFC 9846 §6.1).
//!
//! What it does not do is speak h2. That follows once the handshake and the records are proved,
//! because it is the same session with `attach_tls` on top.
const std = @import("std");
const tls = @import("tls");
const constants = @import("../constants.zig");
const chapulin = @import("chapulin.zig");
const chapulin_record = @import("chapulin_record.zig");
const chapulin_server = @import("chapulin_server.zig");
const check_file = @import("check_file.zig");
const server_identity = @import("server_identity.zig");

const Server = chapulin_server.Server;
const exit_usage = check_file.exit_usage;
const exit_failed = check_file.exit_failed;

/// The server, placed outside any stack frame: it carries chapulin's session, which is larger
/// than a stack frame should hold.
var server: Server = undefined;
/// chapulin's receive buffer, which bounds the ClientHello this server will accept.
var receive_storage: [constants.tls_receive_len]u8 = undefined;
/// The identity and the cookie key the server loads once.
var identity_storage: server_identity.Storage = undefined;
/// The octets this run reads from the socket, of which the first `input_len` are not yet used, and
/// the plaintext it opens them into.
var input_storage: [constants.tls_record_buffer_len]u8 = undefined;
var input_len: usize = 0;
var plaintext_storage: [constants.tls_record_buffer_len]u8 = undefined;
var output_storage: [constants.tls_record_buffer_len]u8 = undefined;

/// What the run was asked to do.
const Arguments = struct {
    port: u16,
    /// The prefix of the files `tools/h2_interop/tls_identity.go` wrote.
    identity_prefix: []const u8,
};

fn parse(init: std.process.Init.Minimal) Arguments {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.next();
    const port_text = arguments.next() orelse usage();
    const identity_prefix = arguments.next() orelse usage();
    return .{
        .port = std.fmt.parseUnsigned(u16, port_text, decimal) catch usage(),
        .identity_prefix = identity_prefix,
    };
}

/// Reports what the handshake negotiated, and refuses anything but h2.
fn report() void {
    const held = server.provider();
    const alpn = held.vtable.negotiated_alpn(held.context) orelse {
        // RFC 9113 §3.1: without "h2" there is no HTTP/2 to speak, and colibri's `attach_tls`
        // refuses the session rather than guessing.
        std.debug.print("tls-accept: the client offered no protocol this server speaks\n", .{});
        std.process.exit(exit_failed);
    };
    const negotiated = held.vtable.negotiated_parameters(held.context).?;
    std.debug.print(
        "tls-accept: complete alpn={s} version=0x{x:0>4} suite=0x{x:0>4}\n",
        .{ alpn, negotiated.version, negotiated.cipher_suite },
    );
    if (!std.mem.eql(u8, alpn, "h2")) std.process.exit(exit_failed);
    if (!admitted(negotiated.cipher_suite)) {
        std.debug.print("tls-accept: colibri does not admit suite 0x{x:0>4}\n", .{negotiated.cipher_suite});
        std.process.exit(exit_failed);
    }
}

/// RFC 9846 §7.5: prints the keying material exported under the label and context the peer also
/// uses. `tools/tls_accept.sh` compares it with the value the peer printed, and two ends that
/// disagree derived different secrets from one handshake.
fn report_exporter() void {
    const held = server.provider();
    var exported: [constants.tls_exporter_len]u8 = undefined;
    held.vtable.export_keying_material(
        held.context,
        constants.tls_exporter_label,
        constants.tls_exporter_context,
        &exported,
    ) catch |failure| {
        std.debug.print("tls-accept: the exporter refused: {t}\n", .{failure});
        std.process.exit(exit_failed);
    };
    std.debug.print("tls-accept: exporter {x}\n", .{exported[0..]});
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
        std.debug.print("tls-accept: built without chapulin; pass -Dchapulin-server=<checkout>\n", .{});
        std.process.exit(exit_usage);
    }
    const asked = parse(init);
    try server_identity.seed(&identity_storage);
    const socket = try accept_one(asked.port);
    defer _ = std.c.close(socket);

    server.init(.{
        .identity = try server_identity.load(asked.identity_prefix, &identity_storage),
        .cookie_key = &identity_storage.cookie_key,
        .receive = &receive_storage,
    });
    // The boot-time self-test: every provisioned key signs and verifies under its own public key.
    server.check() catch {
        std.debug.print("tls-accept: ch_srv_check refused the identity\n", .{});
        std.process.exit(exit_failed);
    };
    server.start() catch {
        std.debug.print("tls-accept: ch_srv_record_init refused the configuration\n", .{});
        std.process.exit(exit_failed);
    };
    try run_handshake(socket);
    report();
    report_exporter();
    try echo_once(socket);
    try await_close(socket);
    std.debug.print("tls-accept: records ok, peer closed cleanly\n", .{});
}

/// Hands what the peer sends to chapulin's record-mode handshake and writes back the server's
/// flight, until the handshake completes. The socket blocks, which decision 46 permits here: this
/// check serves one connection and exits, and is not one of design §9's endpoints.
fn run_handshake(socket: std.c.fd_t) !void {
    // Bounded: each pass reads at least one octet, and a handshake is a few records.
    for (0..handshake_reads_max) |_| {
        try read_more(socket);
        const progress = server.handshake(input_storage[0..input_len], &output_storage) catch |failure| {
            std.debug.print("tls-accept: {t}: {s} (code {d}, alert {d})\n", .{
                failure,
                chapulin_server.reason(server.code),
                server.code,
                server.alert(),
            });
            std.process.exit(exit_failed);
        };
        try write_all(socket, output_storage[0..progress.written]);
        take_input(progress.consumed);
        if (progress.complete) return;
    }
    std.debug.print("tls-accept: the handshake did not complete in {d} reads\n", .{handshake_reads_max});
    std.process.exit(exit_failed);
}

/// The reads a handshake may take: a ClientHello, a second one after a HelloRetryRequest, and the
/// client's Finished, each possibly split across reads.
const handshake_reads_max: usize = 16;

/// Reads until the input holds one whole record, which is what `decrypt_record` opens.
fn read_record(socket: std.c.fd_t) ![]const u8 {
    // Bounded: each pass reads at least one octet, and a record fits the buffer.
    for (0..input_storage.len) |_| {
        if (chapulin_record.whole_record_len(input_storage[0..input_len]) != null) break;
        try read_more(socket);
    }
    return input_storage[0..input_len];
}

/// Opens one record the peer sealed and seals the same octets back (RFC 9846 §5.2). It is the
/// smallest exchange that drives both halves of the record phase.
fn echo_once(socket: std.c.fd_t) !void {
    const held = server.provider();
    const input = try read_record(socket);
    const opened = held.vtable.decrypt_record(held.context, input, &plaintext_storage) catch {
        std.debug.print("tls-accept: the peer's record did not open\n", .{});
        std.process.exit(exit_failed);
    };
    if (opened.content != .application_data or opened.plaintext_len == 0) {
        std.debug.print("tls-accept: the peer's record held no application data\n", .{});
        std.process.exit(exit_failed);
    }
    take_input(opened.consumed);
    const sealed = try held.vtable.encrypt_record(
        held.context,
        plaintext_storage[0..opened.plaintext_len],
        &output_storage,
    );
    try write_all(socket, output_storage[0..sealed.written]);
}

/// Reads what the peer sends next and requires it to be the `close_notify` RFC 9846 §6.1 makes
/// the end of its data. A provider that classified the record as an alert must name a
/// description, which is what colibri's `connection_tls.on_alert` relies on.
fn await_close(socket: std.c.fd_t) !void {
    const held = server.provider();
    const input = try read_record(socket);
    const opened = held.vtable.decrypt_record(held.context, input, &plaintext_storage) catch {
        std.debug.print("tls-accept: the peer's close did not open\n", .{});
        std.process.exit(exit_failed);
    };
    if (opened.content != .alert) {
        std.debug.print("tls-accept: expected an alert, got {s}\n", .{@tagName(opened.content)});
        std.process.exit(exit_failed);
    }
    const report_held = held.vtable.take_alert(held.context) orelse {
        std.debug.print("tls-accept: the alert carried no description\n", .{});
        std.process.exit(exit_failed);
    };
    // RFC 9846 §6.1: only close_notify ends the peer's data. A user_canceled would mean the peer
    // owes a close_notify still, which this run does not wait for.
    if (tls.alert.verdict(report_held) != .end_of_data) {
        std.debug.print("tls-accept: the peer closed with {s}, not close_notify\n", .{
            @tagName(report_held.description),
        });
        std.process.exit(exit_failed);
    }
}

/// Reads at least one octet after the ones not yet used, which is what a peer that owes a record
/// always sends.
fn read_more(socket: std.c.fd_t) !void {
    const room = input_storage[input_len..];
    if (room.len == 0) return error.RecordTooLong;
    const read = std.c.recv(socket, room.ptr, room.len, 0);
    if (read <= 0) return error.PeerClosed;
    input_len += @intCast(read);
}

/// Drops the `consumed` octets used, keeping what follows at the front.
fn take_input(consumed: usize) void {
    std.debug.assert(consumed <= input_len);
    std.mem.copyForwards(u8, &input_storage, input_storage[consumed..input_len]);
    input_len -= consumed;
}

/// Writes every octet, looping because a blocking send may still move fewer than it was asked.
fn write_all(socket: std.c.fd_t, octets: []const u8) !void {
    var sent: usize = 0;
    // Bounded by the slice, and every pass moves at least one octet or returns.
    while (sent < octets.len) {
        const wrote = std.c.send(socket, octets.ptr + sent, octets.len - sent, 0);
        if (wrote <= 0) return error.SendFailed;
        sent += @intCast(wrote);
    }
}

/// Listens on `port` and takes the one connection this run serves. The socket stays blocking,
/// because this check serves one connection and exits.
fn accept_one(port: u16) !std.c.fd_t {
    const listener = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
    if (listener < 0) return error.SocketFailed;
    defer _ = std.c.close(listener);
    var reuse: c_int = 1;
    _ = std.c.setsockopt(listener, std.c.SOL.SOCKET, std.c.SO.REUSEADDR, &reuse, @sizeOf(c_int));
    const address: std.c.sockaddr.in = .{
        // The wire is network byte order whatever the host's is.
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(loopback),
    };
    if (std.c.bind(listener, @ptrCast(&address), @sizeOf(std.c.sockaddr.in)) < 0) return error.BindFailed;
    if (std.c.listen(listener, 1) < 0) return error.ListenFailed;
    // The peer waits for this line before it connects, so the run never races the listener.
    std.debug.print("tls-accept: ready\n", .{});
    const accepted = std.c.accept(listener, null, null);
    if (accepted < 0) return error.AcceptFailed;
    return accepted;
}

fn usage() noreturn {
    std.debug.print("usage: tls-accept <port> <identity-prefix>\n", .{});
    std.process.exit(exit_usage);
}

/// The address the run listens on. The peer runs on this machine.
const loopback: [ipv4_octets]u8 = .{ loopback_first, 0, 0, 1 };
/// How many octets an IPv4 address has (RFC 791 §3.1).
const ipv4_octets: usize = 4;
/// The first octet of 127.0.0.0/8, which RFC 1122 §3.2.1.3 reserves for the local host.
const loopback_first: u8 = 127;

/// The radix every number on the command line is written in.
const decimal: u8 = 10;
