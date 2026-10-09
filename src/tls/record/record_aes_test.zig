//! Decision 97 as amended for chapulin 0.2.0 (https://github.com/c4milo/colibri/issues/84): a host
//! object runs the AES instructions or ChaCha20 alone, as the CPU each session's caller describes
//! says. Split out of `record_test.zig` for length.
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

/// `web_pki` under the description `described`.
fn web_pki_under(described: values.Cpu) values.Client {
    var offered = support.web_pki;
    offered.cpu = described;
    return offered;
}

test "decision 97: on x86-64 and arm64 the object takes the caller's description of its CPU and holds AES-GCM" {
    // chapulin builds its host object there, with `SUITE=aesgcm`, whatever the target's features.
    const host = builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64;
    try testing.expectEqual(host, support.takes_cpu);
    if (host) try testing.expect(support.aes_gcm);
}

test "decision 97: a description becomes chapulin's claims: the AES one under a yes and the mode, the multiply under the mode" {
    if (comptime !support.takes_cpu) return;
    // Bounded by the descriptions a test may run under, at most four.
    for (support.cpus) |described| {
        try support.configure(web_pki_under(described), .{ .cpu = described });
        const stated = described.timing == .data_independent;
        for ([_]@TypeOf(support.client_config.values.cpu){ support.client_config.values.cpu, support.server_config.values.cpu }) |converted| {
            const claims = converted.?;
            try testing.expectEqual(stated and described.probe.aes_clmul == .yes, claims.constant_time_aes);
            try testing.expectEqual(stated, claims.constant_time_multiply);
            // https://github.com/c4milo/stdx/issues/16: stdx's probe answers neither yet.
            try testing.expect(!claims.avx2 and !claims.vaes);
        }
    }
}

test "decision 97: each pair of descriptions runs AES-256-GCM when both state the AES instructions, and ChaCha20 otherwise" {
    // Bounded by the descriptions a test may run under, at most four on each side.
    for (support.cpus) |client_cpu| {
        for (support.cpus) |server_cpu| {
            try support.configure(web_pki_under(client_cpu), .{ .cpu = server_cpu });
            try support.handshake_both(null);
            // chapulin's `cpu_cfg.h`: a session without CH_CPU_CONSTANT_TIME_AES offers and
            // selects ChaCha20 alone.
            try expect_suite(support.default_suite_of(client_cpu, server_cpu));
        }
    }
}

test "decision 97: a description without the AES instructions refuses a suite order that names AES-GCM" {
    // An object that takes no description fixes its suites when it is built, and `config.zig`
    // refuses an order for one that holds ChaCha20 alone.
    if (!support.takes_cpu or !support.aes_gcm) return;
    const order = [_]u16{tls_provider.constants.cipher_suite_aes_128_gcm_sha256};
    // `not_known` gives no more ground to run the instructions than `no` does, and a mode not
    // stated none at all.
    for ([_]values.Cpu{ support.cpu_without_aes, support.cpu_unknown, support.cpu_not_stated }) |described| {
        var offered = support.offering(&order);
        offered.cpu = described;
        try support.configure(offered, .{ .suites = &order, .cpu = described });
        // chapulin's `cpu_cfg.h`: init refuses an order that names AES-GCM rather than dropping
        // the suite.
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

test "decision 97: every description a test may run under carries records each way" {
    for (support.cpus) |described| {
        try support.configure(web_pki_under(described), .{ .cpu = described });
        try support.handshake_both(null);
        const sealed = try client.provider().vtable.encrypt_record(client.provider().context, "probe", support.to_server.free());
        support.to_server.len += sealed.written;
        try testing.expectEqualStrings("probe", support.scratch[0..try support.open_all(server.provider(), &support.to_server, &support.scratch)]);
    }
}

comptime {
    // The tests' own description is one they may run under.
    var found = false;
    for (support.cpus) |described| found = found or std.meta.eql(described, support.cpu);
    std.debug.assert(found);
}
