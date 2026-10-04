//! The TLS provider vtable, in both modes (decision 8). chapulin fills it in the `tls` module
//! (decisions 94 and 97), and src/sim/ fills it with a null one, which is test-only and never
//! packaged. The module was `tls` until decision 97 gave that name to the module a program imports.
//!
//! Record mode serves h2 and is `provider.zig`. QUIC mode serves h3 and lands with design §8
//! step 9e, where RFC 9001 §4 replaces the record layer: step 7 shipped the packet formats and,
//! after decision 48, a `crypto.Suite` that protects packets and drives no handshake.
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const alert = @import("alert.zig");
    pub const provider = @import("provider.zig");
    pub const quic_provider = @import("quic_provider.zig");
};

pub const Alert = files.alert.Alert;
pub const AlertReport = files.alert.AlertReport;
pub const Provider = files.provider.Provider;
pub const VTable = files.provider.VTable;
pub const Content = files.provider.Content;
pub const Negotiated = files.provider.Negotiated;
pub const QuicProvider = files.quic_provider.QuicProvider;
pub const QuicVTable = files.quic_provider.VTable;
pub const VersionChooser = files.quic_provider.VersionChooser;
pub const Level = files.quic_provider.Level;

pub const alert = struct {
    pub const verdict = files.alert.verdict;
};

pub const provider = struct {
    pub const CloseError = files.provider.CloseError;
    pub const Content = files.provider.Content;
    pub const ExportError = files.provider.ExportError;
    pub const HandshakeReadError = files.provider.HandshakeReadError;
    pub const HandshakeWriteError = files.provider.HandshakeWriteError;
    pub const KeyUpdateError = files.provider.KeyUpdateError;
    pub const KeyUpdateRequest = files.provider.KeyUpdateRequest;
    pub const OpenError = files.provider.OpenError;
    pub const Opened = files.provider.Opened;
    pub const SealError = files.provider.SealError;
    pub const Sealed = files.provider.Sealed;
    pub const cipher_suite_admitted = files.provider.cipher_suite_admitted;
};

pub const quic_provider = struct {
    pub const ExportError = files.quic_provider.ExportError;
    pub const ProvideError = files.quic_provider.ProvideError;
    pub const TransportParamsError = files.quic_provider.TransportParamsError;
    pub const VTable = files.quic_provider.VTable;
    pub const WriteError = files.quic_provider.WriteError;
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",         "constants",  "Alert",          "AlertReport",
        "Provider",     "VTable",     "Content",        "Negotiated",
        "QuicProvider", "QuicVTable", "VersionChooser", "Level",
        "alert",        "provider",   "quic_provider",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{"core"});
}
