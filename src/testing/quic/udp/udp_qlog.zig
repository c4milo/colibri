//! The qlog of one connection of the UDP QUIC endpoints (design §8 step 18c, decision 102): a
//! `quic.qlog.Log` over a buffer of the endpoint's, and the file main schema §12.1 names for it
//! under the `qlogdir=` directory, `<ODCID>_<vantage point>.sqlog`, with the extension §11.2
//! gives JSON Text Sequences.
//!
//! The connection writes its events into the buffer. Each turn of the loop writes them to the file
//! and frees the buffer, through libc, as `hq_file.zig` writes a download. A write the file
//! refuses ends the log and not the run: a log never fails the connection it describes.
const std = @import("std");
const quic = @import("quic");
const constants = @import("../../constants.zig");
const hq_file = @import("../hq/hq_file.zig");

const Log = quic.qlog.Log;
const Role = quic.connection.Role;

/// The event schemas the endpoints' logs name (quic-events §2.1, h3-events §2.1): an h3
/// connection writes its HTTP/3 events into its QUIC connection's log.
const event_schemas = [_][]const u8{ quic.qlog.quic_event_schema, quic.qlog.http3_event_schema };

/// Hex digits one octet takes.
const hex_digits_per_octet: usize = 2;

/// Octets of the longest file name: a slash, the longest connection ID in hex, an underscore, the
/// longer vantage point and the extension.
const file_name_len_max = "/".len + hex_digits_per_octet * quic.constants.connection_id_len_max + "_server.sqlog".len;

pub const Qlog = struct {
    log: Log,
    buffer: [constants.quic_qlog_len]u8,
    /// The file the records go to, or `hq_file.none` while the connection logs nothing.
    descriptor: hq_file.Descriptor,

    /// Creates the file of the connection whose original destination connection ID is
    /// `original_destination` and starts its log at `now_ns`. Null when `directory` is null, which
    /// is a run that logs nothing, or when the file cannot be created.
    pub fn open(qlog: *Qlog, directory: ?[]const u8, role: Role, original_destination: []const u8, now_ns: u64) ?*Log {
        qlog.descriptor = hq_file.none;
        const held = directory orelse return null;
        var name: [file_name_len_max]u8 = undefined;
        qlog.descriptor = hq_file.create(held, file_name(&name, role, original_destination)) orelse {
            std.debug.print("quic-udp: no qlog file could be created in {s}\n", .{held});
            return null;
        };
        qlog.log = Log.init(&qlog.buffer);
        const trace: quic.qlog.Trace = .{
            .vantage_point = vantage_point_of(role),
            // Quic-events §1.1: the original destination connection ID groups a connection's
            // events.
            .group_id = original_destination,
            .event_schemas = &event_schemas,
        };
        // `quic_qlog_len` is far past `log_len_min`, which the header of any connection ID fits.
        qlog.log.start(trace, now_ns) catch unreachable;
        return &qlog.log;
    }

    /// Writes the records the connection logged since the last call, and frees the buffer.
    pub fn write(qlog: *Qlog) void {
        if (qlog.descriptor == hq_file.none) return;
        if (!hq_file.write_all(qlog.descriptor, qlog.log.bytes())) {
            std.debug.print("quic-udp: the qlog file took no more records\n", .{});
            end(qlog);
            return;
        }
        qlog.log.clear();
    }

    /// Writes what is left and closes the file, once the connection has ended. A log that dropped
    /// events because a turn's did not fit says how many.
    pub fn close(qlog: *Qlog) void {
        qlog.write();
        if (qlog.descriptor == hq_file.none) return;
        if (qlog.log.dropped > 0) std.debug.print("quic-udp: the qlog dropped {d} events\n", .{qlog.log.dropped});
        end(qlog);
    }

    fn end(qlog: *Qlog) void {
        hq_file.close(qlog.descriptor);
        qlog.descriptor = hq_file.none;
    }
};

/// `/<ODCID>_<vantage point>.sqlog`, the ID in hex, as main schema §12.1 recommends.
fn file_name(into: *[file_name_len_max]u8, role: Role, original_destination: []const u8) []const u8 {
    std.debug.assert(original_destination.len <= quic.constants.connection_id_len_max);
    return std.fmt.bufPrint(into, "/{x}_{t}.sqlog", .{ original_destination, vantage_point_of(role) }) catch unreachable;
}

fn vantage_point_of(role: Role) quic.qlog.VantagePoint {
    return switch (role) {
        .client => .client,
        .server => .server,
    };
}

const testing = std.testing;

test "main schema §12.1: a connection's qlog is named for its original destination ID and its role" {
    var name: [file_name_len_max]u8 = undefined;
    try testing.expectEqualStrings("/0dab01_server.sqlog", file_name(&name, .server, &.{ 0x0d, 0xab, 0x01 }));
    try testing.expectEqualStrings("/ff_client.sqlog", file_name(&name, .client, &.{0xff}));
    // RFC 9000 §17.2: the longest connection ID fits.
    const longest: [quic.constants.connection_id_len_max]u8 = @splat(0xee);
    try testing.expectEqual(file_name_len_max, file_name(&name, .server, &longest).len);
}
