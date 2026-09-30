//! The 100 (Continue) a server connection owes (RFC 9110 §10.1.1), split off `connection.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md).
const connection_module = @import("connection.zig");
const connection_h11 = @import("connection_h11.zig");
const connection_h2 = @import("connection_h2.zig");

const Connection = connection_module.Connection;

/// Writes the 100 (Continue) owed, and returns whether none is owed any more. A request the
/// caller answered with a final response, or cancelled, needs none, and the protocol refuses one.
pub fn write(connection: *Connection) bool {
    const id = connection.continue_owed orelse return true;
    if (connection.phase != .open or connection.stopped) {
        connection.continue_owed = null;
        return true;
    }
    const written = switch (connection.session) {
        .h2 => connection_h2.write_continue(connection, id),
        .h11 => connection_h11.write_continue(connection),
        .none => unreachable,
    } catch |failure| {
        // No room: the caller sends, and the 100 goes out on the next call.
        if (failure == error.NoSpaceLeft) return false;
        // The request ended before the 100 could go out, and needs none.
        connection.continue_owed = null;
        return true;
    };
    connection.output_len += written;
    connection.continue_owed = null;
    return true;
}
