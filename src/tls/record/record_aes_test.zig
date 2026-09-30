//! Decision 97 as amended for design §8 step 16e: an `AES=runtime` object runs the AES instructions
//! or ChaCha20 alone, as each session's caller answers. Split out of `record_test.zig` for length.
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

test "decision 97: on x86-64 and arm64 the object takes the caller's answer and holds AES-GCM" {
    // The build chooses `AES=runtime` there, with `SUITE=aesgcm`, whatever the target's features.
    const runtime = builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64;
    try testing.expectEqual(runtime, support.takes_answer);
    if (runtime) try testing.expect(support.aes_gcm);
}

test "decision 97: each pair of answers runs AES-256-GCM when both hold it, and ChaCha20 otherwise" {
    // Bounded by the answers a test may run under, at most two on each side.
    for (support.answers) |client_answer| {
        for (support.answers) |server_answer| {
            var offered = support.web_pki;
            offered.aes_instructions = client_answer;
            try support.configure(offered, .{ .aes_instructions = server_answer });
            try support.handshake_both(null);
            // chapulin's `AES=runtime`: a session under `absent` offers and selects ChaCha20 alone.
            try expect_suite(support.default_suite_of(client_answer, server_answer));
        }
    }
}

test "decision 97: under absent, a suite order that names AES-GCM is refused when a session starts" {
    // An object that takes no answer fixes its suites when it is built, and `config.zig` refuses
    // an order for one that holds ChaCha20 alone.
    if (!support.takes_answer or !support.aes_gcm) return;
    const order = [_]u16{tls_provider.constants.cipher_suite_aes_128_gcm_sha256};
    var offered = support.offering(&order);
    offered.aes_instructions = .absent;
    try support.configure(offered, .{ .suites = &order, .aes_instructions = .absent });
    // chapulin's entry 81: init refuses an order that names AES-GCM rather than dropping the suite.
    try testing.expectError(error.Refused, client.start(&support.client_config, support.random(), support.now_seconds, null));
    try testing.expectError(error.Refused, server.start(&support.server_config, support.random(), support.now_seconds));
    // ChaCha20 named alone is an order a session under `absent` holds.
    const chacha_order = [_]u16{support.chacha};
    offered = support.offering(&chacha_order);
    offered.aes_instructions = .absent;
    try support.configure(offered, .{ .suites = &chacha_order, .aes_instructions = .absent });
    try support.handshake_both(null);
    try expect_suite(support.chacha);
}

test "decision 97: every answer a test may run under carries records each way" {
    for (support.answers) |answer| {
        var offered = support.web_pki;
        offered.aes_instructions = answer;
        try support.configure(offered, .{ .aes_instructions = answer });
        try support.handshake_both(null);
        const sealed = try client.provider().vtable.encrypt_record(client.provider().context, "answer", support.to_server.free());
        support.to_server.len += sealed.written;
        try testing.expectEqualStrings("answer", support.scratch[0..try support.open_all(server.provider(), &support.to_server, &support.scratch)]);
    }
}

comptime {
    // The tests' own answer is one they may run under.
    std.debug.assert(std.mem.indexOfScalar(values.AesInstructions, support.answers, support.aes_instructions) != null);
}
