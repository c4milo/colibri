//! One QUIC connection's TLS session in `src/testing/`, in either role: `tls.quic`'s client or
//! server behind one type (design §8 step 16b), so an endpoint drives both the same way.
const std = @import("std");
const entropy = @import("../entropy.zig");
const tls = @import("tls");
const quic = @import("quic");
const keylog_module = @import("keylog.zig");

const tls_provider = quic.tls_provider;
const Keylog = keylog_module.Keylog;

/// What starts a session: a client's configuration, clock and ticket, or a server's
/// configuration and clock.
pub const Start = union(enum) {
    client: struct {
        config: *const tls.quic.ClientConfig,
        /// Unix seconds, which the caller read: a Web PKI chain is judged at them.
        now_seconds: u64,
        resumption: ?tls.Resumption = null,
    },
    server: struct {
        config: *const tls.quic.ServerConfig,
        /// Unix seconds its tickets are issued and judged at, or 0 to issue none.
        now_seconds: u64,
        /// The version of the client's first Initial, which the connection runs (RFC 9368 §2).
        version: quic.crypto.suite.Version = .v1,
    },

    pub fn role(start: Start) quic.crypto.Role {
        return if (start == .client) .client else .server;
    }

    /// The version the connection starts in (RFC 9368 §2): the one a client's configuration names,
    /// version 1 unless it names another, or the version of the client's first Initial.
    pub fn version(start: Start) quic.crypto.suite.Version {
        return switch (start) {
            .client => |client| if (client.config.values.quic_version) |named| @enumFromInt(@intFromEnum(named)) else .v1,
            .server => |server| server.version,
        };
    }
};

pub const Session = union(enum) {
    client: tls.quic.Client,
    server: tls.quic.Server,

    /// Starts the session `start` names, whose secrets go to `keylog` when it is not null.
    pub fn start(session: *Session, how: Start, keylog: ?*Keylog) tls.quic.Error!void {
        switch (how) {
            .client => |client| {
                session.* = .{ .client = undefined };
                try session.client.start(client.config, entropy.random(), client.now_seconds, client.resumption);
                session.client.set_keylog_context(keylog);
            },
            .server => |server| {
                session.* = .{ .server = undefined };
                session.server.start(server.config, entropy.random(), server.now_seconds, server.version);
                session.server.set_keylog_context(keylog);
            },
        }
    }

    pub fn provider(session: *Session) tls_provider.QuicProvider {
        return switch (session.*) {
            inline else => |*role| role.provider(),
        };
    }

    pub fn suite(session: *Session) quic.crypto.Suite {
        return switch (session.*) {
            inline else => |*role| role.suite(),
        };
    }

    /// Whether a ticket authenticated the handshake (RFC 9846 §2.2).
    pub fn resumed(session: *const Session) bool {
        return switch (session.*) {
            inline else => |*role| role.resumed(),
        };
    }

    /// Wipes every key the session holds.
    pub fn close(session: *Session) void {
        switch (session.*) {
            inline else => |*role| role.close(),
        }
    }
};
