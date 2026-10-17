//! The server's two limits on the resets of an h3 connection's request streams (decision 110 as
//! amended on 2026-10-17): the streams the client cancels, and the streams h3 refuses because the
//! client broke them. Each costs the application a request's work for nothing. Split out of
//! `quic_connection_h3.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const h3 = @import("h3");
const constants = @import("../constants.zig");
const quic_connection = @import("quic_connection.zig");
const internal = @import("quic_connection_internal.zig");

const QuicConnection = quic_connection.QuicConnection;

/// Counts one request stream the client opened and then cancelled, in the period the latest
/// instant falls in, and returns whether the connection goes on: past the limit it closes
/// (decision 110 as amended). A client cancels with a RESET_STREAM, or with a STOP_SENDING that
/// stops its response (RFC 9114 §4.1.1). Either cost the application a request's work, which
/// CVE-2023-44487 made the peer's to spend at line rate.
pub fn count_peer_reset(connection: *QuicConnection) bool {
    const now_ns = connection.last_ns;
    assert(now_ns >= connection.peer_reset_period_start_ns);
    assert(connection.config.peer_resets_max > 0);
    if (now_ns - connection.peer_reset_period_start_ns >= constants.quic_peer_reset_rate_period_ns) {
        connection.peer_reset_period_start_ns = now_ns;
        connection.peer_resets = 0;
    }
    if (connection.peer_resets >= connection.config.peer_resets_max) {
        connection.peer_resets_passed = true;
        close_for_load(connection);
        return false;
    }
    connection.peer_resets += 1;
    return true;
}

/// Counts one request stream h3 refused because the client broke it (RFC 9114 §4.1.2), in the
/// period the latest instant falls in, and returns whether the connection goes on: past the limit
/// it closes (decision 110 as amended). A client may send a whole head, which the application
/// starts to work on, and then break the request, so each refusal can cost what a cancel costs.
/// h2 counts each RST_STREAM it sends the same way.
pub fn count_reset_sent(connection: *QuicConnection) bool {
    const now_ns = connection.last_ns;
    assert(now_ns >= connection.resets_sent_period_start_ns);
    assert(connection.config.resets_sent_max > 0);
    if (now_ns - connection.resets_sent_period_start_ns >= constants.quic_resets_sent_period_ns) {
        connection.resets_sent_period_start_ns = now_ns;
        connection.resets_sent = 0;
    }
    if (connection.resets_sent >= connection.config.resets_sent_max) {
        connection.resets_sent_passed = true;
        close_for_load(connection);
        return false;
    }
    connection.resets_sent += 1;
    return true;
}

/// Closes the connection for a limit the client passed. RFC 9114 §10.5: an endpoint SHOULD track
/// the use of features that cost it work and set limits on it, and "MAY treat activity that is
/// suspicious as a connection error of type H3_EXCESSIVE_LOAD".
fn close_for_load(connection: *QuicConnection) void {
    const failed = connection.h3.fail(&connection.transport, h3.constants.error_excessive_load);
    assert(failed == error.ConnectionFailed);
    internal.fail(connection);
}
