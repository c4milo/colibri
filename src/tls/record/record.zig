//! Record-mode TLS sessions for h2 and h11 (decisions 94 and 97, design §8 step 16b): chapulin's
//! `TRANSPORT=tcp-nonblocking` client and server, driven from octets the caller read and into
//! buffers the caller owns, with no descriptor touched and no call that waits (decision 46).
//!
//! A program converts its values once into a `ClientConfig` or `ServerConfig`, then for each
//! connection places a session, calls `start` with the connection's clock, passes what it reads
//! to `handshake` until the handshake completes, and hands `provider()` to the connection's
//! `attach_tls`. The caller places each session and does not move it after `start`: chapulin keeps
//! pointers into it.
const std = @import("std");
const assert = std.debug.assert;
const tls_provider = @import("tls_provider");
const chapulin = @import("chapulin_tcp");
const constants = @import("../constants.zig");
const values = @import("../values.zig");
const config_module = @import("../config.zig");
const ticket = @import("../ticket.zig");
const record_provider = @import("record_provider.zig");

pub const ClientConfig = config_module.ClientConfig(chapulin);
pub const ServerConfig = config_module.ServerConfig(chapulin);
pub const ConfigError = config_module.Error;
pub const State = record_provider.State;

/// Octets of a sealed alert record, chapulin's `alert_record_len` (RFC 9846 §5.2, §6). A client's
/// `handshake` reads the server's flight only into an output with this much room left, so the
/// alert a refused flight owes fits the call that fails.
pub const alert_record_len: usize = chapulin.record.alert_record_len;

pub const Error = error{
    /// chapulin refused the values: a configuration it does not accept, or a ticket past its
    /// lifetime or seven days old (RFC 9846 §4.7.1). Nothing was sent.
    Refused,
    /// The handshake did not complete (RFC 9846 §6). `alert` names what chapulin chose, and
    /// `failure_written` counts the octets of the output to send before closing.
    HandshakeFailed,
    /// The output could not hold a record of a server's flight, which fails the handshake.
    /// `failure_written` counts the octets of the output to send before closing.
    OutputTooSmall,
};

/// What one call to `handshake` did.
pub const Progress = struct {
    /// Octets of the input taken: whole records only, and a partial one is left for the next call.
    consumed: usize,
    /// Octets written into the output, to be sent in order.
    written: usize,
    /// Whether the handshake completed, so `provider()` is ready for `attach_tls`.
    complete: bool,
};

pub const Client = struct {
    session: chapulin.record.Client(constants.receive_len),
    /// The ticket this connection offers, in chapulin's form; the session points at its PSK.
    offered: chapulin.Ticket,
    state: State,
    /// Whether chapulin may hold octets the client owes the server. chapulin reads no record while
    /// it does (`tcp_nonblocking.h`), and it cannot say so, so `handshake` asks by collecting.
    owed: bool,

    /// Octets of the largest record a client's `handshake` writes: a ClientHello, the first or the
    /// one a HelloRetryRequest asks for, chapulin's `REC_HDR + CH_TX_HELLO`. The Finished flight
    /// and a refused flight's alert are shorter. An output this long takes all the client owes in
    /// one call, so nothing stays with chapulin for the next.
    pub const handshake_output_len_min: usize = chapulin.c.REC_HDR + chapulin.c.CH_TX_HELLO;

    const Provider = record_provider.Provider(Client);

    /// Stages the ClientHello, which the first `handshake` call writes. `now_seconds` is the
    /// clock a Web PKI chain is judged at, which the caller read (non-negotiable 3).
    pub fn start(client: *Client, config: *const ClientConfig, now_seconds: u64, resumption: ?values.Resumption) Error!void {
        client.state = .{};
        client.owed = true;
        var chosen = config.values;
        switch (chosen.trust) {
            .web_pki => |*judged| judged.now_seconds = now_seconds,
            .pins => {},
        }
        if (resumption) |offer| {
            // RFC 9846 §4.7.1: a ticket's PSK is a hash length, which chapulin checks here.
            client.offered = ticket.offered(chapulin, offer) catch return error.Refused;
            chosen.ticket = &client.offered;
            chosen.ticket_age_ms = offer.age_ms;
        }
        // RFC 9846 §4.7.1: chapulin refuses a ticket past its ticket_lifetime or seven days old,
        // and any configuration it cannot run.
        client.session.init(chosen) catch return error.Refused;
    }

    /// Writes what the client owes into `output`, then passes what the caller read to chapulin and
    /// writes what that made the client owe. chapulin takes whole records and opens each in place,
    /// so the input is mutable. The octets past `consumed` are the caller's to pass again: with
    /// what it reads next, or, once the handshake completes, to the provider's `decrypt_record`.
    pub fn handshake(client: *Client, input: []u8, output: []u8) Error!Progress {
        assert(!client.state.completed);
        var written = try client.collect(output);
        var consumed: usize = 0;
        // RFC 9846 §4.2.4: a client that owes its second ClientHello reads nothing before sending
        // it, and chapulin refuses the records until it is collected. RFC 9846 §6.2: nor does it
        // read before the output has room for the alert a refused flight owes the server, whole.
        if (!client.owed and input.len > 0 and output.len - written >= alert_record_len) {
            consumed = client.session.recordIn(input) catch {
                // The alert that says why goes out after what this call wrote. `alert` names it.
                client.state.failure_written = written + client.failure_alert(output[written..]);
                // RFC 9846 §6.2: a flight chapulin refuses ends the handshake.
                return error.HandshakeFailed;
            };
            client.owed = true;
            written += try client.collect(output[written..]);
        }
        client.state.completed = client.session.recordState() == .connected;
        return .{ .consumed = consumed, .written = written, .complete = client.state.completed };
    }

    /// The alert record a failed read staged, sealed once the client's write key is installed.
    /// None follows the server's own fatal alert (RFC 9846 §6.2).
    fn failure_alert(client: *Client, output: []u8) usize {
        assert(output.len >= alert_record_len);
        const alert_len = client.session.recordOut(output) catch return 0;
        assert(alert_len > 0 and alert_len <= alert_record_len);
        return alert_len;
    }

    /// After `handshake` failed, the octets it wrote at the front of its output, which the caller
    /// sends before it closes the connection: what the client owed, then the alert (RFC 9846 §6.2).
    pub fn failure_written(client: *const Client) usize {
        return client.state.failure_written;
    }

    /// What chapulin has staged, as much as `output` holds; the rest stays staged for the next call.
    fn collect(client: *Client, output: []u8) Error!usize {
        // chapulin refuses a capacity of 0.
        if (!client.owed or output.len == 0) return 0;
        // RFC 9846 §6.2: a session that failed owes nothing more, and chapulin says so here.
        const written = client.session.recordOut(output) catch return error.HandshakeFailed;
        assert(written <= output.len);
        // chapulin copies all it has staged or all that fits, so a short answer left none staged.
        if (written < output.len) client.owed = false;
        return written;
    }

    pub fn provider(client: *Client) tls_provider.Provider {
        return .{ .context = @ptrCast(client), .vtable = &Provider.vtable };
    }

    /// The latest ticket the server sent, which the call hands over and clears (RFC 9846 §4.7.1).
    /// A program keeps it, offers it through `start` on a later connection, and wipes it when it
    /// drops it.
    pub fn take_ticket(client: *Client) ?values.Ticket {
        var taken = client.session.takeTicket() orelse return null;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&taken));
        return ticket.value_of(chapulin, &taken);
    }

    /// Whether a ticket this client offered authenticated the handshake (RFC 9846 §2.2).
    pub fn resumed(client: *const Client) bool {
        return client.session.pskSelected();
    }

    /// The alert a failure chose (RFC 9846 §6), or null: chapulin's `ch_alert_sent`.
    pub fn alert(client: *const Client) ?u8 {
        return client.session.alertSent();
    }

    /// Wipes every secret the session holds, the offered ticket's copy included, and ends it.
    /// A connected caller sends its close_notify through the provider first.
    pub fn close(client: *Client) void {
        client.session.recordClose();
        std.crypto.secureZero(u8, std.mem.asBytes(&client.offered));
    }
};

pub const Server = struct {
    session: chapulin.record.Server(constants.receive_len),
    /// The server_name the client sent, which chapulin copies here (RFC 9846 §9.2).
    server_name: [constants.server_name_len_max]u8,
    state: State,

    const Provider = record_provider.Provider(Server);

    /// Prepares the session to read a ClientHello. A server speaks second, so nothing is written.
    /// `now_seconds` is the clock its tickets are issued and judged at, or 0 for none.
    pub fn start(server: *Server, config: *const ServerConfig, now_seconds: u64) Error!void {
        server.state = .{};
        var chosen = config.values;
        chosen.now_seconds = now_seconds;
        // RFC 9846 §9.2: chapulin refuses values it cannot serve from, such as a cookie key missing
        // for the cookie extension that section makes mandatory.
        server.session.init(chosen, &server.server_name) catch return error.Refused;
    }

    /// Runs the handshake over what the caller read, and writes the server's flight into
    /// `output`, which must hold all of it.
    pub fn handshake(server: *Server, input: []u8, output: []u8) Error!Progress {
        assert(!server.state.completed);
        const progress = server.session.recordIn(input, output) catch |failure| {
            // RFC 9846 §6.2: chapulin wrote the alert that says why after the flight's records.
            server.state.failure_written = server.session.outputLen();
            assert(server.state.failure_written <= output.len);
            return switch (failure) {
                // chapulin writes a flight record by record and fails the handshake on one that
                // does not fit (`srv_cfg.h`).
                error.Io => error.OutputTooSmall,
                else => error.HandshakeFailed,
            };
        };
        server.state.completed = server.session.recordState() == .connected;
        return .{ .consumed = progress.consumed, .written = progress.written, .complete = server.state.completed };
    }

    /// After `handshake` failed, the octets it wrote at the front of its output, which the caller
    /// sends before it closes the connection: the records of the flight that went out, then the
    /// alert (RFC 9846 §6.2), as much of it as the output held.
    pub fn failure_written(server: *const Server) usize {
        return server.state.failure_written;
    }

    pub fn provider(server: *Server) tls_provider.Provider {
        return .{ .context = @ptrCast(server), .vtable = &Provider.vtable };
    }

    /// The server_name the client sent, or null when it sent none or a longer one.
    pub fn sni(server: *const Server) ?[]const u8 {
        return server.session.sni();
    }

    /// Whether a ticket this server issued authenticated the handshake (RFC 9846 §2.2).
    pub fn resumed(server: *const Server) bool {
        return server.session.pskSelected();
    }

    /// The alert a failure chose (RFC 9846 §6), or null: chapulin's `ch_alert_sent`.
    pub fn alert(server: *const Server) ?u8 {
        return server.session.alertSent();
    }

    /// Wipes every secret the session holds and ends it.
    pub fn close(server: *Server) void {
        server.session.recordClose();
    }
};

test {
    _ = @import("record_test.zig");
    _ = @import("record_failure_test.zig");
    // Sealing a peer's KeyUpdate needs the traffic secrets, which only a `KEYLOG=on` object logs.
    if (@hasDecl(chapulin.c, "ch_keylog")) _ = @import("record_keylog_test.zig");
}
