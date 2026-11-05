//! The chapulin objects the library links (decisions 94 and 97), and how the build chooses between
//! them. Split from `modules.zig`, which builds the module graph over them.
const std = @import("std");

/// chapulin's `SUITE`, `KEYLOG` and `DNSSEC` values the library's objects choose between, spelled as
/// its build spells them.
const Suite = enum { chacha, aesgcm };
const Keylog = enum { on, off };
const Dnssec = enum { on, off };

/// Decision 97's TCP object: `TRANSPORT=tcp-nonblocking ROLE=both TRUST=webpki EXPORTER=on`,
/// compiled from the pinned package with `RAND=session`, where each session draws from the source its
/// caller passes (decision 94 as amended on 2026-09-27). `SUITE=aesgcm` adds RFC 9846
/// §9.1's mandatory TLS_AES_128_GCM_SHA256, and `TX_RECORD=16384` lets a record carry TLS's largest
/// plaintext (RFC 9846 §5.1). `TRUST=webpki` is the one client trust mode that compiles ALPN in,
/// without which no client negotiates h2 (RFC 9113 §3.1). The package also translates the public
/// headers under the defines its object compiled with, so the declarations colibri reads always
/// match the object it links. The library's object is `KEYLOG=off` (decision 94); only the tests
/// of `tls_keylog` build one `on`.
pub fn record_object(b: *std.Build, target: std.Build.ResolvedTarget, keylog: Keylog) *std.Build.Dependency {
    return b.dependency("chapulin", .{
        .target = target,
        .RAND = .session,
        .TRANSPORT = .@"tcp-nonblocking",
        .ROLE = .both,
        .TRUST = .webpki,
        .EXPORTER = .on,
        .SUITE = suite_of(target),
        .TX_RECORD = "16384",
        .KEYLOG = keylog,
        .DNSSEC = dnssec_of(target),
    });
}

/// chapulin's `DNSSEC` value: `on` in a host object, whose RSA check the DNSSEC calls share, and
/// `off` in a device object, which chapulin refuses DNSSEC in (decision 142).
fn dnssec_of(target: std.Build.ResolvedTarget) Dnssec {
    return if (host_object(target)) .on else .off;
}

/// Decision 97 as amended for chapulin 0.2.0 (https://github.com/c4milo/colibri/issues/84): on a
/// host target, arm64 with NEON or x86-64 with SSE2, both objects are chapulin's host objects. They
/// hold every fast path beside the portable code, and each session picks among them from the CPU
/// its caller describes (chapulin's decision 89), so the build takes no `AES`, `WIDEMUL` or
/// `CHACHA` value. They carry `SUITE=aesgcm`, and a session runs it only where its caller states
/// the AES instructions run in constant time. Any other target builds chapulin's device object,
/// whose AES is the software one, and chapulin refuses `SUITE=aesgcm` with it, since its S-box is
/// indexed with the key (its `ct.h`, INV-26). There it carries `SUITE=chacha`,
/// TLS_CHACHA20_POLY1305_SHA256 alone.
fn suite_of(target: std.Build.ResolvedTarget) Suite {
    return if (host_object(target)) .aesgcm else .chacha;
}

/// chapulin's host test (its build's `hostTarget`): a little-endian arm64 target with NEON, or an
/// x86-64 target with SSE2, which every such CPU has.
pub fn host_object(target: std.Build.ResolvedTarget) bool {
    const cpu = target.result.cpu;
    return switch (cpu.arch) {
        .aarch64 => std.Target.aarch64.featureSetHas(cpu.features, .neon),
        .x86_64 => std.Target.x86.featureSetHas(cpu.features, .sse2),
        else => false,
    };
}

/// Decision 97's QUIC object: `TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki`, compiled from the
/// pinned package with `RAND=session` (decision 94 as amended), with the suite choice of the TCP
/// object. `SUITE=aesgcm` adds RFC 9846 §9.1's mandatory TLS_AES_128_GCM_SHA256, which is also the
/// only kind of suite h3spec offers. The library's object is `KEYLOG=off`; `tls_keylog` builds one
/// `on`, which hands the tests and the endpoints each traffic secret.
pub fn quic_object(b: *std.Build, target: std.Build.ResolvedTarget, keylog: Keylog) *std.Build.Dependency {
    return b.dependency("chapulin", .{
        .target = target,
        .RAND = .session,
        .TRANSPORT = .@"quic-nonblocking",
        .ROLE = .both,
        .TRUST = .webpki,
        .SUITE = suite_of(target),
        .KEYLOG = keylog,
    });
}
