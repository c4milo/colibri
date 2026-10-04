//! QPACK, RFC 9204.
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const http = @import("http");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const static_table = @import("static_table.zig");
    pub const representation = @import("representation.zig");
    pub const representation_write = @import("representation_write.zig");
    pub const encoder = @import("encoder.zig");
    pub const encoder_plan = @import("encoder_plan.zig");
    pub const decoder = @import("decoder.zig");
    pub const decoder_table = @import("decoder_table.zig");
    pub const decoder_stream = @import("decoder_stream.zig");
    pub const dynamic_table = @import("dynamic_table.zig");
    pub const instruction = @import("instruction.zig");
    pub const insert_count = @import("insert_count.zig");
    pub const encoder_state = @import("encoder_state.zig");
};

pub const Encoder = files.encoder.Encoder;
pub const Decoder = files.decoder.Decoder;

pub const encoder = struct {
    pub const HuffmanUse = files.encoder.HuffmanUse;
    pub const Indexing = files.encoder.Indexing;
};

pub const decoder = struct {
    pub const Error = files.decoder.Error;
    pub const Outcome = files.decoder.Outcome;
    pub const Settings = files.decoder.Settings;
    pub const error_code = files.decoder.error_code;
};

pub const decoder_stream = struct {
    pub const owes = files.decoder_stream.owes;
};

pub const instruction = struct {
    pub const read_decoder = files.instruction.read_decoder;
    pub const read_encoder = files.instruction.read_encoder;
    pub const write_decoder = files.instruction.write_decoder;
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",           "wire",        "http",    "constants",
        "Encoder",        "Decoder",     "encoder", "decoder",
        "decoder_stream", "instruction",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{ "core", "wire", "http" });
}
