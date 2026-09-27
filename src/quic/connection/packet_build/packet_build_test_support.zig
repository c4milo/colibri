//! The QUIC provider the connection tests share (`packet_build_test.zig` re-exports it): a
//! provider that owes `owed` octets at `owed_level` and nothing anywhere else, and that fails its
//! handshake when a test asks it to. It performs no cryptography.
const core = @import("core");
const tls_provider = @import("tls_provider");

const Level = core.Level;

pub const Fake = struct {
    owed: []const u8 = "",
    owed_level: Level = .initial,
    /// What `handshake_complete` answers (RFC 9001 §4.1.1).
    done: bool = false,
    /// Whether `write_handshake` fails as a TLS stack whose handshake failed does, and the alert
    /// `take_alert` then reports once (RFC 9001 §4.8).
    refuse_write: bool = false,
    alert_held: ?tls_provider.Alert = null,

    pub fn provider(self: *Fake) tls_provider.QuicProvider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }
    fn set_params(_: *anyopaque, _: []const u8) tls_provider.quic_provider.TransportParamsError!void {}
    fn peer_params(_: *const anyopaque) ?[]const u8 {
        return null;
    }
    fn provide(_: *anyopaque, _: Level, _: []const u8) tls_provider.quic_provider.ProvideError!void {}
    fn write(context: *anyopaque, level: Level, output: []u8) tls_provider.quic_provider.WriteError!usize {
        const self: *Fake = @ptrCast(@alignCast(context));
        // RFC 9001 §4.8: a TLS stack whose handshake failed raises an alert and writes nothing.
        if (self.refuse_write) return error.TlsFailed;
        if (level != self.owed_level or self.owed.len == 0) return 0;
        // RFC 9001 §4.1.3 lets a provider hand over what fits and keep the rest for the next
        // call, which is what makes a long flight fill a packet exactly.
        const written = @min(self.owed.len, output.len);
        @memcpy(output[0..written], self.owed[0..written]);
        self.owed = self.owed[written..];
        return written;
    }
    fn alpn(_: *const anyopaque) ?[]const u8 {
        return &tls_provider.constants.alpn_h3;
    }
    fn complete(context: *const anyopaque) bool {
        const self: *const Fake = @ptrCast(@alignCast(context));
        return self.done;
    }
    fn alert_of(context: *anyopaque) ?tls_provider.Alert {
        const self: *Fake = @ptrCast(@alignCast(context));
        defer self.alert_held = null;
        return self.alert_held;
    }
    fn exported(_: *anyopaque, _: []const u8, _: ?[]const u8, _: []u8) tls_provider.quic_provider.ExportError!void {
        // RFC 9846 §7.5 standardises the exporter without obliging a stack to offer one.
        return error.Unsupported;
    }
    const table: tls_provider.QuicVTable = .{
        .set_transport_params = set_params,
        .peer_transport_params = peer_params,
        .provide_handshake = provide,
        .write_handshake = write,
        .negotiated_alpn = alpn,
        .handshake_complete = complete,
        .take_alert = alert_of,
        .export_keying_material = exported,
    };
};
