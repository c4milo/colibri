//! What the files of an h2 connection call that a caller outside the module does not: writing the
//! preface, and ending the connection for a limit. Split out of `connection.zig` because a
//! hand-written source file stays at or under 500 lines (CLAUDE.md), and `h2.zig` does not export
//! this file.
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const settings = @import("../settings.zig");
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;
const Error = connection_module.Error;
const Limit = connection_module.Limit;
const Writer = @import("core").Writer;

/// Writes the preface: the client's 24 octets, then colibri's SETTINGS, each once and whole.
pub fn write_preface(connection: *Connection, writer: *Writer, now_ns: u64) void {
    if (connection.role == .client and !connection.preface_written) {
        // RFC 9113 §3.4: a client starts the connection with these 24 octets.
        writer.write_bytes(constants.client_preface) catch return;
        connection.preface_written = true;
    }
    if (connection.settings_written) return;
    var buffer: [constants.settings_count]settings.Setting = undefined;
    const entries = settings.entries(connection.local, connection.role, &buffer);
    var pairs: [constants.settings_count]frame.Setting = undefined;
    for (entries, 0..) |entry, index| pairs[index] = .{ .id = entry.id, .value = entry.value };
    // RFC 9113 §3.4: the preface ends with a SETTINGS frame, which may be empty.
    frame.write_settings(writer, pairs[0..entries.len]) catch return;
    connection.settings_written = true;
    // RFC 9113 §6.5.3: the values are in force once the peer acknowledges them.
    connection.pending.push(connection.local, now_ns) catch unreachable;
}

/// Whether colibri's SETTINGS_ENABLE_PUSH of 0 has been acknowledged, after which RFC 9113
/// §6.5.2 makes a PUSH_PROMISE a connection error. A client sends the value in its preface and
/// never changes it, so the acknowledgment is the only thing to wait for (decision 17). A server
/// omits the setting (§6.5.2) and never reaches this call, because `on_push_promise` refuses a
/// PUSH_PROMISE on its role first.
pub fn push_refused(connection: *const Connection) bool {
    return connection.settings_written and connection.pending.len() == 0;
}

/// Ends the connection with ENHANCE_YOUR_CALM for `limit` (RFC 9113 §10.5), and notes which
/// limit it was. The first failure stands.
pub fn fail_limit(connection: *Connection, limit: Limit) Error {
    if (connection.failure == null) connection.failure_limit = limit;
    return connection.fail(constants.error_enhance_your_calm);
}
