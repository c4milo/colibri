//! QUIC sessions for h3 (decisions 94 and 97, design §8 step 16b): chapulin's
//! `TRANSPORT=quic-nonblocking` client and server behind colibri's `tls_provider.QuicProvider`
//! (`quic_provider.zig`) and `crypto.Suite` (`quic_suite.zig`).
//!
//! A program converts its values once into a `ClientConfig` or `ServerConfig`, then for each
//! connection places a session, calls `start` with the connection's clock, and hands `provider()`
//! and `suite()` to its `quic.Connection`. chapulin's session starts when colibri gives the
//! provider its transport parameters (RFC 9001 §8.2), and the caller then installs the Initial
//! keys through the suite (§5.2). The caller does not move a session after `start`: chapulin keeps
//! pointers into it.
const std = @import("std");
const tls_provider = @import("tls_provider");
const crypto = @import("crypto");
const chapulin = @import("chapulin_quic");
const constants = @import("../constants.zig");
const values = @import("../values.zig");
const config_module = @import("../config.zig");
const ticket = @import("../ticket.zig");
const quic_provider = @import("quic_provider.zig");
const quic_suite = @import("quic_suite.zig");

pub const ClientConfig = config_module.ClientConfig(chapulin);
pub const ServerConfig = config_module.ServerConfig(chapulin);
pub const ConfigError = config_module.Error;
pub const State = quic_provider.State;
pub const Retry = quic_suite.Retry;
pub const token_key_len = quic_suite.token_key_len;
pub const version = quic_suite.version;

pub const Error = error{
    /// The ticket's fields are not ones chapulin can offer (RFC 9846 §4.7.1), or it was issued by
    /// a TCP connection or in another QUIC version (RFC 9369 §5). Nothing was sent, and a caller
    /// may start again without it.
    Refused,
};

pub const Client = struct {
    session: chapulin.quic.Client(constants.receive_len),
    /// The ticket this connection offers, in chapulin's form; the session points at its PSK.
    offered: chapulin.Ticket,
    /// The values this connection starts from, which chapulin reads when its session starts.
    chosen: chapulin.Client,
    state: State,

    pub const is_client = true;
    const Provider = quic_provider.Provider(Client);
    const Suite = quic_suite.Suite(Client);

    /// Prepares the connection's values. Every draw the session makes comes from `random`
    /// (decision 94 as amended). `now_seconds` is the clock a Web PKI chain is judged at, which the
    /// caller read (non-negotiable 3). chapulin judges a ticket's age when its session starts, and
    /// refuses a stale one then.
    pub fn start(client: *Client, config: *const ClientConfig, random: values.Random, now_seconds: u64, resumption: ?values.Resumption) Error!void {
        client.state = .{};
        client.chosen = config.values;
        client.chosen.random = random;
        // RFC 9368 §2.5: the version of the client's first Initial packet, its original one, which
        // is version 1 unless its configuration names another.
        client.chosen.quic_version = config.values.quic_version orelse version;
        switch (client.chosen.trust) {
            .web_pki => |*judged| judged.now_seconds = now_seconds,
            .pins => {},
        }
        const offer = resumption orelse return;
        // RFC 9369 §5: a client MUST NOT start a connection with a ticket another version issued.
        if (!ticket.fits(offer.ticket, @intFromEnum(client.chosen.quic_version.?))) return error.Refused;
        // RFC 9846 §4.7.1: a ticket's PSK is a hash length, which chapulin checks here.
        client.offered = ticket.offered(chapulin, offer) catch return error.Refused;
        client.chosen.ticket = &client.offered;
        client.chosen.ticket_age_ms = offer.age_ms;
    }

    pub fn provider(client: *Client) tls_provider.QuicProvider {
        return .{ .context = @ptrCast(client), .vtable = &Provider.vtable };
    }

    pub fn suite(client: *Client) crypto.Suite {
        return .{ .context = @ptrCast(client), .vtable = &Suite.vtable };
    }

    /// What a `KEYLOG=on` object's `ch_keylog` receives back through `chapulin.hookContext`. Set
    /// after `start` and before the transport parameters.
    pub fn set_keylog_context(client: *Client, context: ?*anyopaque) void {
        client.state.keylog_context = context;
    }

    /// The latest ticket the server sent, which the call hands over and clears (RFC 9846 §4.7.1).
    pub fn take_ticket(client: *Client) ?values.Ticket {
        if (!client.state.started) return null;
        var taken = client.session.takeTicket() orelse return null;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&taken));
        return ticket.value_of(chapulin, &taken);
    }

    /// Whether a ticket this client offered authenticated the handshake (RFC 9846 §2.2).
    pub fn resumed(client: *const Client) bool {
        return client.state.started and client.session.pskSelected();
    }

    /// Wipes every key the session holds, the offered ticket's copy included, and ends it.
    pub fn close(client: *Client) void {
        if (client.state.started) client.session.close();
        std.crypto.secureZero(u8, std.mem.asBytes(&client.offered));
    }
};

pub const Server = struct {
    session: chapulin.quic.Server(constants.receive_len),
    /// The server_name the client sent, which chapulin copies here (RFC 9846 §9.2).
    server_name: [constants.server_name_len_max]u8,
    /// The values this connection starts from, which chapulin reads when its session starts.
    chosen: chapulin.Server,
    state: State,

    pub const is_client = false;
    const Provider = quic_provider.Provider(Server);
    const Suite = quic_suite.Suite(Server);

    /// Prepares the connection's values. Every draw the session makes comes from `random`
    /// (decision 94 as amended). `now_seconds` is the clock its tickets are issued and judged at,
    /// or 0 for none. `original` is the version of the client's first Initial packet.
    pub fn start(server: *Server, config: *const ServerConfig, random: values.Random, now_seconds: u64, original: crypto.suite.Version) void {
        server.state = .{};
        server.chosen = config.values;
        server.chosen.random = random;
        server.chosen.now_seconds = now_seconds;
        // RFC 9368 §2: the session starts in the version of the client's first Initial packet.
        server.chosen.quic_version = @enumFromInt(@intFromEnum(original));
    }

    pub fn provider(server: *Server) tls_provider.QuicProvider {
        return .{ .context = @ptrCast(server), .vtable = &Provider.vtable };
    }

    pub fn suite(server: *Server) crypto.Suite {
        return .{ .context = @ptrCast(server), .vtable = &Suite.vtable };
    }

    pub fn set_keylog_context(server: *Server, context: ?*anyopaque) void {
        server.state.keylog_context = context;
    }

    /// The server_name the client sent, or null when it sent none or a longer one.
    pub fn sni(server: *const Server) ?[]const u8 {
        if (!server.state.started) return null;
        return server.session.sni();
    }

    /// Whether a ticket this server issued authenticated the handshake, which then carried no
    /// Certificate (RFC 9846 §2.2).
    pub fn resumed(server: *const Server) bool {
        return server.state.started and server.session.pskSelected();
    }

    /// Wipes every key the session holds and ends it.
    pub fn close(server: *Server) void {
        if (server.state.started) server.session.close();
    }
};

test {
    _ = @import("quic_test.zig");
    _ = @import("quic_vectors_test.zig");
}
