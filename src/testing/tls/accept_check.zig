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
const chapulin_server = @import("chapulin_server.zig");
const check_file = @import("check_file.zig");

const c = chapulin.c;
const Server = chapulin_server.Server;
const exit_usage = check_file.exit_usage;
const exit_failed = check_file.exit_failed;

/// The server, placed outside any stack frame: it carries chapulin's session, which is larger
/// than a stack frame should hold.
var server: Server = undefined;
/// chapulin's receive buffer, which bounds the ClientHello this server will accept.
var receive_storage: [constants.tls_receive_len]u8 = undefined;
var leaf_storage: [constants.tls_der_len_max]u8 = undefined;
var issuer_storage: [constants.tls_der_len_max]u8 = undefined;
var private_storage: [chapulin_server.private_scalar_len]u8 = undefined;
var public_storage: [chapulin_server.public_point_len]u8 = undefined;
var cookie_storage: [chapulin_server.cookie_key_len]u8 = undefined;
/// The octets this run moves over the socket, and the plaintext it opens them into.
var input_storage: [constants.tls_record_buffer_len]u8 = undefined;
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

/// Seeds chapulin's DRBG and draws the cookie key. A `RAND=drbg` build requires the seed before
/// any handshake, and `ch_srv_check` draws entropy of its own to salt an RSA signature. This
/// endpoint may read the operating system's entropy; the library may not, and does not.
fn seed_chapulin() !void {
    var seed: [chapulin.seed_len]u8 = undefined;
    const drawn = try check_file.read_file("/dev/urandom", &seed);
    if (drawn.len != seed.len) {
        std.debug.print("tls-accept: could not draw a seed\n", .{});
        std.process.exit(exit_failed);
    }
    c.ch_drbg_seed(&seed);
    // RFC 9846 §4.3.2: one key per deployment. A run is one deployment, so it draws its own.
    const cookie = try check_file.read_file("/dev/urandom", &cookie_storage);
    if (cookie.len != cookie_storage.len) {
        std.debug.print("tls-accept: could not draw a cookie key\n", .{});
        std.process.exit(exit_failed);
    }
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
    try seed_chapulin();
    const socket = try accept_one(asked.port);
    defer _ = std.c.close(socket);

    server.init(.{
        .identity = try read_identity(asked.identity_prefix),
        .cookie_key = &cookie_storage,
        .receive = &receive_storage,
        .socket = socket,
    });
    // The boot-time self-test: every provisioned key signs and verifies under its own public key.
    server.check() catch {
        std.debug.print("tls-accept: ch_srv_check refused the identity\n", .{});
        std.process.exit(exit_failed);
    };
    server.accept() catch {
        std.debug.print("tls-accept: {s} (code {d})\n", .{
            chapulin_server.reason(server.code),
            server.code,
        });
        std.process.exit(exit_failed);
    };
    report();
    report_exporter();
    try echo_once(socket);
    try await_close(socket);
    std.debug.print("tls-accept: records ok, peer closed cleanly\n", .{});
}

/// Reads the four parts of the identity the peer minted, each raw DER or raw octets.
fn read_identity(prefix: []const u8) !chapulin_server.Identity {
    return .{
        .leaf = try check_file.read_part(prefix, ".leaf.der", &leaf_storage),
        .issuer = try check_file.read_part(prefix, ".ca.der", &issuer_storage),
        .private_scalar = try check_file.read_part(prefix, ".priv", &private_storage),
        .public_point = try check_file.read_part(prefix, ".pub", &public_storage),
    };
}

/// Opens one record the peer sealed and seals the same octets back (RFC 9846 §5.2). It is the
/// smallest exchange that drives both halves of the record phase.
fn echo_once(socket: std.c.fd_t) !void {
    const held = server.provider();
    const input = try read_some(socket, &input_storage);
    const opened = held.vtable.decrypt_record(held.context, input, &plaintext_storage) catch {
        std.debug.print("tls-accept: the peer's record did not open\n", .{});
        std.process.exit(exit_failed);
    };
    if (opened.content != .application_data or opened.plaintext_len == 0) {
        std.debug.print("tls-accept: the peer's record held no application data\n", .{});
        std.process.exit(exit_failed);
    }
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
    const input = try read_some(socket, &input_storage);
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

/// Reads at least one octet, which is what a peer that owes a record always sends.
fn read_some(socket: std.c.fd_t, into: []u8) ![]const u8 {
    const read = std.c.recv(socket, into.ptr, into.len, 0);
    if (read <= 0) return error.PeerClosed;
    return into[0..@intCast(read)];
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

/// Listens on `port` and takes the one connection this run serves. The socket stays blocking:
/// chapulin drives the handshake itself and none of its callbacks can report "nothing yet"
/// (decision 46).
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
