//! The byte-exact corpus and its manifest (decision 26). One directory per format, one file per
//! case, and a versioned manifest naming each file's length, checksum, verdict and parameters.
//!
//! The corpus is written by `zig build golden` (tools/golden.zig) and checked here, by
//! `zig build golden-check`, which `zig build test` runs. Three checks, all against files this
//! module embeds at build time, so the check reads no file at run time:
//!   1. each committed case file holds exactly what its constructor in `corpus_cases.zig` builds;
//!   2. each committed manifest is exactly what `corpus.render_manifest` writes;
//!   3. each corpus mutation of `mutations.zig`, applied to the committed octets, produces the
//!      verdict it names.
//! A case added to the table with no file beside it does not compile, which is how a forgotten
//! `zig build golden` shows up.
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const constants = @import("constants.zig");
pub const corpus = @import("corpus.zig");
pub const mutations = @import("mutations.zig");

const Writer = core.Writer;
const Format = corpus.cases.Format;

/// The committed octets of one case, embedded when this module is built.
fn committed_case(comptime format: Format, comptime name: []const u8) []const u8 {
    return @embedFile(@tagName(format) ++ "/" ++ name ++ constants.case_file_extension);
}

fn committed_manifest(comptime format: Format) []const u8 {
    return @embedFile(@tagName(format) ++ "/" ++ constants.manifest_file_name);
}

const testing = std.testing;

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = corpus;
    _ = mutations;
}

test "golden-check: every committed case file is what its constructor builds" {
    inline for (corpus.cases.all) |entry| {
        inline for (entry.cases) |*case| {
            var buffer: [constants.case_len_max]u8 = @splat(0);
            var built = Writer.init(&buffer);
            try corpus.build(entry.format, case, &built);
            const committed = committed_case(entry.format, case.name);
            testing.expectEqualSlices(u8, built.written(), committed) catch |err| {
                std.debug.print("golden-check: {t}/{s} differs; run `zig build golden`\n", .{
                    entry.format,
                    case.name,
                });
                return err;
            };
        }
    }
}

test "golden-check: every committed manifest is what the table renders" {
    inline for (corpus.cases.all) |entry| {
        var buffer: [constants.manifest_len_max]u8 = @splat(0);
        var rendered = Writer.init(&buffer);
        try corpus.render_manifest(entry.format, &rendered);
        try testing.expectEqualStrings(rendered.written(), committed_manifest(entry.format));
    }
}

test "golden-check: every corpus mutation produces the verdict it names" {
    for (&mutations.all) |*mutation| {
        const committed = try committed_octets(mutation.format, mutation.case_name);
        var buffer: [constants.case_len_max * 2]u8 = @splat(0);
        var mutated = Writer.init(&buffer);
        try mutations.apply(mutation, committed, &mutated);
        const case = corpus.find(mutation.format, mutation.case_name);
        const result = corpus.decode(mutation.format, case.prefix_size, mutated.written());
        verdict_matches(mutation.rejection, result) catch |err| {
            std.debug.print("golden-check: mutation of {s} no longer holds: {s}\n", .{
                mutation.case_name,
                mutation.rule,
            });
            return err;
        };
    }
}

fn verdict_matches(rejection: ?anyerror, result: corpus.DecodeError!void) !void {
    if (rejection) |expected| return testing.expectError(expected, result);
    return result;
}

/// The committed octets of the case a mutation names, looked up at run time.
fn committed_octets(format: Format, name: []const u8) ![]const u8 {
    inline for (corpus.cases.all) |entry| {
        if (entry.format == format) {
            inline for (entry.cases) |case| {
                const committed = committed_case(entry.format, case.name);
                if (std.mem.eql(u8, case.name, name)) return committed;
            }
        }
    }
    return error.TestUnexpectedResult;
}
