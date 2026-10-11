//! What the command line asked of the test-only server (`../server.zig`): `main` writes each value
//! once, before any worker starts, and the workers read them (`server_worker.zig`). They are here
//! so neither file imports the other for them. Split off `../server.zig` for length.
const server = @import("server");
const tls = @import("tls");
const server_identity = @import("../tls/server_identity.zig");
const server_options = @import("server_options.zig");

/// The versions the server speaks: h11 and h2, which a connection in cleartext chooses between by
/// its first octets, or one alone with `--h11` or `--h2` (decision 117).
pub var versions: server.Versions align(@alignOf(server.Versions)) = .{};
pub var listen_address: [server_options.ipv4_octets]u8 = server_options.loopback_octets;
pub var echo_mode: bool = false;
/// Whether responses are coded (`--coded`), in gzip or deflate, gzip first.
pub var coded_mode: bool = false;
pub const served_codings = [_]server.Coding{ .gzip, .deflate };
/// The h3 endpoint each TLS connection advertises (`--h3-port`), or null.
pub var h3_alternative: ?server.Alternative align(@alignOf(?server.Alternative)) = null;

/// The TLS mode's configuration, which `main` converts once when `--tls` names an identity and
/// every connection borrows, and the storage it points into.
pub var tls_shared: ?*const tls.record.ServerConfig = null;
pub var tls_config: tls.record.ServerConfig align(@alignOf(tls.record.ServerConfig)) = undefined;
pub var tls_identity: server_identity.Storage align(@alignOf(server_identity.Storage)) = undefined;
