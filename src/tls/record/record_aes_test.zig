//! Decisions 97 and 175 (https://github.com/c4milo/colibri/issues/84): a host object runs the AES
//! instructions or ChaCha20 alone, as the description stdx maps from each configuration's context
//! says. Split out of `record_test.zig` for length.
const std = @import("std");
const builtin = @import("builtin");
const tls_provider = @import("tls_provider");
const stdx = @import("stdx");
const platform = stdx.platform;
const values = @import("../values.zig");
const support = @import("record_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;

fn expect_suite(suite: u16) !void {
    for ([_]tls_provider.Provider{ client.provider(), server.provider() }) |provider| {
        try testing.expectEqual(suite, provider.negotiated_parameters().?.cipher_suite);
    }
}

const web_pki_under = support.web_pki_under;

test "decision 97: on x86-64 and arm64 the object takes the caller's description of its CPU and holds AES-GCM" {
    // chapulin builds its host object there, with `SUITE=aesgcm`, whatever the target's features.
    const host = builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64;
    try testing.expectEqual(host, support.takes_cpu);
    if (host) try testing.expect(support.aes_gcm);
}

test "decision 175: a configuration keeps its context whole, the features and the random source" {
    if (comptime !support.takes_cpu) return;
    // Bounded by the feature sets a test may run under, at most two, and by four sets that hold
    // one SHA instruction each or an N2's MIDR_EL1.
    for (support.feature_sets) |cpu_features| try expect_converted(cpu_features);
    for (support.features_with_sha) |cpu_features| try expect_converted(cpu_features);
}

/// Configures both sides under `features` and checks what each configuration kept of the context,
/// which each session's `init` takes: the features whole, an N2's MIDR_EL1 too, and the source.
fn expect_converted(cpu_features: platform.CpuFeatures) !void {
    const crypto = support.context_of(cpu_features);
    try support.configure(web_pki_under(crypto), .{ .crypto = crypto });
    for ([_]stdx.crypto.Context{ support.client_config.crypto, support.server_config.crypto }) |kept| {
        try testing.expect(std.meta.eql(cpu_features, kept.features));
        try testing.expectEqual(crypto.random.ptr, kept.random.ptr);
    }
    // A set of features without the AES instructions claims none.
    if (!cpu_features.aes) try testing.expect(!support.aes_claimed(crypto));
}

test "decision 175: each pair of feature sets runs AES-256-GCM when both claim the AES instructions, and ChaCha20 otherwise" {
    // Bounded by the feature sets a test may run under, at most two on each side.
    for (support.feature_sets) |client_features| {
        for (support.feature_sets) |server_features| {
            const client_crypto = support.context_of(client_features);
            const server_crypto = support.context_of(server_features);
            try support.configure(web_pki_under(client_crypto), .{ .crypto = server_crypto });
            try support.handshake_both(null);
            // chapulin's `cpu_cfg.h`: a session without CH_CPU_CONSTANT_TIME_AES offers and
            // selects ChaCha20 alone.
            try expect_suite(support.default_suite_of(client_crypto, server_crypto));
        }
    }
}

test "decision 175: features without the AES instructions refuse a suite order that names AES-GCM" {
    // An object that takes no description fixes its suites when it is built, and `config.zig`
    // refuses an order for one that holds ChaCha20 alone.
    if (!support.takes_cpu or !support.aes_gcm) return;
    const order = [_]u16{tls_provider.constants.protocol.cipher_suite_aes_128_gcm_sha256};
    const crypto = support.context_of(support.cpu_features_without_aes);
    var offered = support.offering(&order);
    offered.crypto = crypto;
    try support.configure(offered, .{ .suites = &order, .crypto = crypto });
    // chapulin's `cpu_cfg.h`: init refuses an order that names AES-GCM rather than dropping the
    // suite.
    try testing.expectError(error.Refused, client.start(&support.client_config, support.now_seconds, null));
    try testing.expectError(error.Refused, server.start(&support.server_config, support.now_seconds));
    // ChaCha20 named alone is an order such a session holds.
    const chacha_order = [_]u16{support.chacha};
    var chacha_offered = support.offering(&chacha_order);
    chacha_offered.crypto = crypto;
    try support.configure(chacha_offered, .{ .suites = &chacha_order, .crypto = crypto });
    try support.handshake_both(null);
    try expect_suite(support.chacha);
}

test "decision 175: every feature set a test may run under carries records each way" {
    for (support.feature_sets) |cpu_features| {
        const crypto = support.context_of(cpu_features);
        try support.configure(web_pki_under(crypto), .{ .crypto = crypto });
        try support.handshake_both(null);
        const sealed = try client.provider().encrypt_record("probe", support.to_server.free());
        support.to_server.len += sealed.written;
        try testing.expectEqualStrings("probe", support.scratch[0..try support.open_all(server.provider(), &support.to_server, &support.scratch)]);
    }
}

comptime {
    // The tests' own features are a set they may run under, or lack only the AES instructions.
    var found = false;
    for (support.feature_sets) |cpu_features| found = found or std.meta.eql(cpu_features, support.cpu_features) or std.meta.eql(cpu_features, support.cpu_features_without_aes);
    std.debug.assert(found);
}
