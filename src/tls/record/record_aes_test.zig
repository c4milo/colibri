//! Decision 97 as amended for design §8 step 16e: an `AES=runtime` object runs the AES instructions
//! or ChaCha20 alone, as the probe each session's caller passes says. Split out of
//! `record_test.zig` for length.
const std = @import("std");
const builtin = @import("builtin");
const tls_provider = @import("tls_provider");
const values = @import("../values.zig");
const support = @import("record_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;

fn expect_suite(suite: u16) !void {
    for ([_]tls_provider.Provider{ client.provider(), server.provider() }) |provider| {
        try testing.expectEqual(suite, provider.vtable.negotiated_parameters(provider.context).?.cipher_suite);
    }
}

/// `web_pki` under the probe `probed`.
fn web_pki_under(probed: values.Cpu) values.Client {
    var offered = support.web_pki;
    offered.cpu = probed;
    return offered;
}

test "decision 97: on x86-64 and arm64 the object takes the caller's probe and holds AES-GCM" {
    // The build chooses `AES=runtime` there, with `SUITE=aesgcm`, whatever the target's features.
    const runtime = builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64;
    try testing.expectEqual(runtime, support.takes_answer);
    if (runtime) try testing.expect(support.aes_gcm);
}

test "decision 97: each pair of probes runs AES-256-GCM when both say yes, and ChaCha20 otherwise" {
    // Bounded by the probes a test may run under, at most three on each side.
    for (support.cpus) |client_cpu| {
        for (support.cpus) |server_cpu| {
            try support.configure(web_pki_under(client_cpu), .{ .cpu = server_cpu });
            try support.handshake_both(null);
            // chapulin's `AES=runtime`: a session whose probe is not `yes` offers and selects
            // ChaCha20 alone.
            try expect_suite(support.default_suite_of(client_cpu, server_cpu));
        }
    }
}

test "decision 97: a probe that does not say yes refuses a suite order that names AES-GCM" {
    // An object that takes no probe fixes its suites when it is built, and `config.zig` refuses
    // an order for one that holds ChaCha20 alone.
    if (!support.takes_answer or !support.aes_gcm) return;
    const order = [_]u16{tls_provider.constants.cipher_suite_aes_128_gcm_sha256};
    // `not_known` gives no more ground to run the instructions than `no` does.
    for ([_]values.Cpu{ support.cpu_without_aes, support.cpu_unknown }) |probed| {
        var offered = support.offering(&order);
        offered.cpu = probed;
        try support.configure(offered, .{ .suites = &order, .cpu = probed });
        // chapulin's entry 81: init refuses an order that names AES-GCM rather than dropping the
        // suite.
        try testing.expectError(error.Refused, client.start(&support.client_config, support.random(), support.now_seconds, null));
        try testing.expectError(error.Refused, server.start(&support.server_config, support.random(), support.now_seconds));
    }
    // ChaCha20 named alone is an order such a session holds.
    const chacha_order = [_]u16{support.chacha};
    var offered = support.offering(&chacha_order);
    offered.cpu = support.cpu_unknown;
    try support.configure(offered, .{ .suites = &chacha_order, .cpu = support.cpu_unknown });
    try support.handshake_both(null);
    try expect_suite(support.chacha);
}

test "decision 97: every probe a test may run under carries records each way" {
    for (support.cpus) |probed| {
        try support.configure(web_pki_under(probed), .{ .cpu = probed });
        try support.handshake_both(null);
        const sealed = try client.provider().vtable.encrypt_record(client.provider().context, "probe", support.to_server.free());
        support.to_server.len += sealed.written;
        try testing.expectEqualStrings("probe", support.scratch[0..try support.open_all(server.provider(), &support.to_server, &support.scratch)]);
    }
}

comptime {
    // The tests' own probe is one they may run under.
    var found = false;
    for (support.cpus) |probed| found = found or std.meta.eql(probed, support.cpu);
    std.debug.assert(found);
}
