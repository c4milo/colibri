//! A fixture the tests of `connection_datagram.zig` and `connection_early.zig` share (CLAUDE.md:
//! a fixture several test files share lives in a `*_test_support.zig` file). Test-only.
const std = @import("std");
const core = @import("core");
const tls_provider = @import("tls_provider");
const build_test = @import("packet_build/packet_build_test.zig");

const Level = core.Level;

/// The bytes a `Recorder` keeps of what it is handed: more than any test hands it.
pub const taken_len_max: usize = 64;

/// A provider that records what it was handed and answers the parameters and completion a test
/// sets. Test-only.
pub const Recorder = struct {
    taken: [taken_len_max]u8 = @splat(0),
    taken_len: usize = 0,
    peer_body: []const u8 = "",
    done: bool = false,
    /// A level whose keys the bytes it is handed produce, which it gives the suite at once, as a
    /// caller's code moves TLS's secrets to its suite (decision 48).
    makes_available: ?Level = null,
    /// The suite that level's keys go to, which a test that sets `makes_available` names.
    suite: ?*build_test.RoundTrip = null,

    pub fn provider(self: *Recorder) tls_provider.QuicProvider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }
    fn set_params(_: *anyopaque, _: []const u8) tls_provider.quic_provider.TransportParamsError!void {}
    fn peer_params(context: *const anyopaque) ?[]const u8 {
        const self: *const Recorder = @ptrCast(@alignCast(context));
        return if (self.peer_body.len == 0) null else self.peer_body;
    }
    fn provide(context: *anyopaque, _: Level, data: []const u8) tls_provider.quic_provider.ProvideError!void {
        const self: *Recorder = @ptrCast(@alignCast(context));
        @memcpy(self.taken[self.taken_len..][0..data.len], data);
        self.taken_len += data.len;
        if (self.makes_available) |level| self.suite.?.available[@intFromEnum(level)] = @splat(true);
    }
    fn write(_: *anyopaque, _: Level, _: []u8) tls_provider.quic_provider.WriteError!usize {
        return 0;
    }
    fn alpn(_: *const anyopaque) ?[]const u8 {
        return null;
    }
    fn complete(context: *const anyopaque) bool {
        const self: *const Recorder = @ptrCast(@alignCast(context));
        return self.done;
    }
    fn alert_of(_: *anyopaque) ?tls_provider.Alert {
        return null;
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
