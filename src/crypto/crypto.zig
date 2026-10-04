//! The packet-protection vtable colibri drives for QUIC (decisions 9 and 48), and what both sides
//! of it must agree on: the sizes RFC 9001 §5 fixes, and the packet number recovery a suite
//! performs while it removes protection. No production implementation is in this tree.
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const suite = @import("suite.zig");
    pub const packet_number = @import("packet_number.zig");
};

pub const Suite = files.suite.Suite;
pub const Level = files.suite.Level;
pub const Direction = files.suite.Direction;
pub const Role = files.suite.Role;

pub const suite = struct {
    pub const Direction = files.suite.Direction;
    pub const InstallError = files.suite.InstallError;
    pub const KeySet = files.suite.KeySet;
    pub const Level = files.suite.Level;
    pub const OpenError = files.suite.OpenError;
    pub const Opened = files.suite.Opened;
    pub const Opening = files.suite.Opening;
    pub const RetryConnectionIds = files.suite.RetryConnectionIds;
    pub const RetryTagError = files.suite.RetryTagError;
    pub const Role = files.suite.Role;
    pub const SealError = files.suite.SealError;
    pub const Sealing = files.suite.Sealing;
    pub const SwitchError = files.suite.SwitchError;
    pub const TokenCheck = files.suite.TokenCheck;
    pub const TokenError = files.suite.TokenError;
    pub const UpdateError = files.suite.UpdateError;
    pub const VTable = files.suite.VTable;
    pub const Version = files.suite.Version;
    pub const directions_count = files.suite.directions_count;
    pub const levels_count = files.suite.levels_count;
};

pub const packet_number = struct {
    pub const Truncated = files.packet_number.Truncated;
    pub const decode = files.packet_number.decode;
    pub const read = files.packet_number.read;
    pub const window_of = files.packet_number.window_of;
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",      "constants", "Suite", "Level",
        "Direction", "Role",      "suite", "packet_number",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{"core"});
}
