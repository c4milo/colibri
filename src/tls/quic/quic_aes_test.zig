//! Decision 97 as amended for design §8 step 16e, in QUIC: an `AES=runtime` object runs the AES
//! instructions or ChaCha20 alone, as the probe each session's caller passes says. QUIC's Initial
//! packets use a key anyone can derive (RFC 9001 §5.2), so chapulin protects them in software when
//! the probe does not say yes, and the handshake completes under every probe. Split out of
//! `quic_test.zig` for length.
const std = @import("std");
const values = @import("../values.zig");
const identity = @import("../record/record_test_support.zig");
const support = @import("quic_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;

/// A payload long enough for RFC 9001 §5.4.2's header protection sample.
const payload = "a payload colibri frames, 32 oct";

/// The suite a session ran, where one that holds ChaCha20 alone may record none.
fn suite_ran(session: anytype, probed: values.Cpu) !u16 {
    if (session.suite()) |recorded| return @intFromEnum(recorded);
    try testing.expect(!identity.holds_aes_gcm(probed));
    return identity.chacha;
}

test "decision 97: each pair of probes completes a QUIC handshake and runs the suite both hold" {
    // Bounded by the probes a test may run under, at most three on each side.
    for (identity.cpus) |client_cpu| {
        for (identity.cpus) |server_cpu| {
            var offered = support.web_pki;
            offered.cpu = client_cpu;
            try support.configure(offered, .{ .cpu = server_cpu });
            try support.handshake_both(null);
            const expected = identity.default_suite_of(client_cpu, server_cpu);
            try testing.expectEqual(expected, try suite_ran(&client.session, client_cpu));
            try testing.expectEqual(expected, try suite_ran(&server.session, server_cpu));
            // RFC 9001 §5.3: a 1-RTT packet crosses in the suite both hold.
            var header_storage: [support.packet.len]u8 = undefined;
            const header = try support.short_header(1, false, &header_storage);
            const sealed = try server.suite().vtable.seal(server.suite().context, .{ .level = .application, .version = .v1, .packet_number = 1, .header = header, .packet_number_len = support.packet_number_len, .payload = payload }, &support.packet);
            const opened = try client.suite().vtable.open(client.suite().context, .{ .level = .application, .version = .v1, .packet = support.packet[0..sealed], .packet_number_offset = header.len - support.packet_number_len, .largest_packet_number = null });
            try testing.expectEqualStrings(payload, support.opened_payload(header.len, opened));
            client.close();
            server.close();
        }
    }
}
