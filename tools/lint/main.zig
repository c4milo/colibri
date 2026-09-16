//! colibri lint: the rules of CLAUDE.md and docs/invariants.md that a parser and a line scanner
//! can check, one file per rule under tools/lint/.
//!
//! Run:  zig build lint, which passes no `--rule`, so every rule registered here runs and gates.
//! `--rule NAME` runs one rule by hand.
//!
//! The driver is pepegrillo's (decision 36): it walks every PATH, hands every regular file to every
//! enabled rule, reports a `.zig` file that does not parse under the `parse` pseudo-rule, and prints
//! one line per finding, sorted by path, line, column and rule:
//!
//!     path:line: [rule-name] message
//!
//! Exit status: 0 when nothing was found, 1 when any finding was reported or a file failed to read,
//! 2 on a usage error.
//!
//! Eight rules are pepegrillo's, configured in the file named after each. `module-graph`,
//! `rfc-citation` and `peer-index` are colibri's own, written against pepegrillo's readers.
//!
//! This tool is developer tooling. It is never linked into the library, so it allocates, reads the
//! filesystem, and is exempt from the rules it enforces over `src/` (CLAUDE.md, Layout).

const std = @import("std");
const pepegrillo = @import("pepegrillo");

/// Every rule, in the order `--rule` names are looked up. Each exports a `name` and a
/// `check(context, file)`, and every one gates `zig build lint`.
const rules = .{
    @import("heap.zig"),
    @import("io.zig"),
    @import("determinism.zig"),
    @import("unbounded_loop.zig"),
    @import("relative_import.zig"),
    @import("module_graph.zig"),
    @import("markdown.zig"),
    @import("file_length.zig"),
    @import("magic_numbers.zig"),
    @import("rfc_citation.zig"),
    @import("peer_index.zig"),
};

const Linter = pepegrillo.lint.Linter(rules);

pub fn main(init: std.process.Init) !void {
    return Linter.main(init);
}

// Tests. The rules carry their own, and pepegrillo tests the driver.

const testing = std.testing;

test "the registered rules are exactly the rules CLAUDE.md names" {
    const expected = [_][]const u8{
        "heap",
        "io",
        "determinism",
        "unbounded-loop",
        "relative-import",
        "module-graph",
        "markdown",
        "file-length",
        "magic-numbers",
        "rfc-citation",
        "peer-index",
    };
    try testing.expectEqual(expected.len, Linter.count);
    inline for (rules, 0..) |rule, index| {
        try testing.expectEqualStrings(expected[index], rule.name);
        try testing.expectEqual(index, Linter.rule_index_of(rule.name).?);
    }
}

test {
    inline for (rules) |rule| _ = rule;
}
