//! Commit-message linter for the Conventional Commit rules of CLAUDE.md (Commits). It reads commit
//! messages out of git, or one message from a file, and prints one line per finding; it changes
//! nothing.
//!
//! Run:  zig build lint-commits            # the commits this branch adds to origin/main
//!       zig-out/bin/commit_lint --range REV [REV...]
//!       zig-out/bin/commit_lint --message PATH
//!
//! The linter is pepegrillo's (decision 36). This file holds colibri's configuration of it: the
//! module scopes of docs/design.md §3, scopes that admit digits so `h2` and `h3` are valid, and the
//! first words refused as not imperative. The limits are the ones CLAUDE.md states, which are
//! pepegrillo's defaults.
//!
//! One line per finding:
//!
//!     source: severity: rule-name: message
//!
//! The severity is `violation` for a rule of CLAUDE.md that was broken, and `warning` for a scope
//! outside the module graph. CLAUDE.md states that scopes track the module graph, and a closed
//! check would make this tool, rather than the design, the authority on what modules exist, so an
//! unknown scope never changes the exit status.
//!
//! Exit status: 0 when no rule was violated, warnings included; 1 when any rule was violated; 2 on
//! a usage error, an unreadable message file, or a git log that failed. .githooks/pre-push reads
//! the difference.

const std = @import("std");
const pepegrillo = @import("pepegrillo");

/// The scopes CLAUDE.md names, one per module of docs/design.md §3.
pub const module_scopes = [_][]const u8{
    "h2",  "h3",     "quic", "hpack", "qpack",  "wire",  "http",
    "tls", "crypto", "core", "sim",   "golden", "bench",
};

/// First words that describe the commit instead of commanding it.
const third_person_forms = [_][]const u8{
    "adds",    "fixes", "updates", "removes", "implements", "splits",
    "renames", "moves", "makes",   "drops",   "lands",      "keeps",
};

/// Commands whose spelling ends in `ed` or `ing` all the same. The suffix test reads the last two
/// or three bytes of a word, not its grammar, so without this list it refuses `bring the hook
/// back` and `seed the corpus`.
const imperative_exceptions = [_][]const u8{
    "bring",  "embed", "seed", "speed", "feed", "exceed", "proceed", "succeed", "shed", "ring",
    "string",
};

pub const config: pepegrillo.commit.Config = .{
    .scope_admits_digits = true,
    .known_scopes = &module_scopes,
    .unknown_scope_reason = "is not a module of the graph",
    .third_person_forms = &third_person_forms,
    .imperative_exceptions = &imperative_exceptions,
};

pub fn main(init: std.process.Init) !void {
    return pepegrillo.commit.main(init, config);
}

// Tests. pepegrillo tests the rules; these pin colibri's configuration of them.

const testing = std.testing;
const commit = pepegrillo.commit;

/// The module scopes as the scope warning prints them, written out rather than built from
/// `module_scopes`, so a scope added to or dropped from that list fails this file.
const module_scope_list = "h2, h3, quic, hpack, qpack, wire, http, tls, crypto, core, sim, golden, bench";

/// Lints `text` under colibri's configuration and checks each finding, in order, as
/// `severity: rule: message`.
fn expect_findings(text: []const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var findings: commit.Findings = .{ .arena = arena, .max_findings = config.max_findings };
    try commit.lint_message_text(arena, config, &findings, "message", text);
    try testing.expectEqual(expected.len, findings.items.items.len);
    for (findings.items.items, expected) |finding, wanted| {
        const line = try std.fmt.allocPrint(arena, "{s}: {s}: {s}", .{
            finding.severity.text(), finding.rule, finding.message,
        });
        try testing.expectEqualStrings(wanted, line);
    }
}

test "every scope CLAUDE.md names passes, digits included" {
    // Written out rather than read from `module_scopes`, so a scope dropped from that list fails.
    const scopes = [_][]const u8{
        "h2",     "h3",    "quic", "hpack", "qpack", "wire", "http", "tls", "crypto", "core", "sim",
        "golden", "bench",
    };
    try testing.expectEqual(scopes.len, module_scopes.len);
    for (scopes) |scope| {
        var buffer: [96]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "feat({s}): add the frame reader\n", .{scope});
        try expect_findings(text, &.{});
    }
}

test "a well-formed scope the graph does not name draws a warning" {
    try expect_findings("refactor(h2-frame): add the frame reader\n", &.{
        "warning: scope-known: the scope \"h2-frame\" is not a module of the graph (" ++
            module_scope_list ++ ")",
    });
}

test "every third-person form is refused" {
    // Written out rather than read from `third_person_forms`, so a form dropped from it fails.
    const forms = [_][]const u8{
        "adds",  "fixes", "updates", "removes", "implements", "splits", "renames", "moves", "makes",
        "drops", "lands", "keeps",
    };
    try testing.expectEqual(forms.len, third_person_forms.len);
    for (forms) |form| {
        var buffer: [128]u8 = undefined;
        var wanted_buffer: [160]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "feat: {s} the frame reader\n", .{form});
        const wanted = try std.fmt.bufPrint(
            &wanted_buffer,
            "violation: subject-description: \"{s}\" is a third-person form, not imperative",
            .{form},
        );
        try expect_findings(text, &.{wanted});
    }
}

test "every command whose spelling ends in ed or ing passes" {
    // Written out rather than read from `imperative_exceptions`, so a word dropped from it fails.
    const exceptions = [_][]const u8{
        "bring",  "embed", "seed", "speed", "feed", "exceed", "proceed", "succeed", "shed", "ring",
        "string",
    };
    try testing.expectEqual(exceptions.len, imperative_exceptions.len);
    for (exceptions) |exception| {
        var buffer: [128]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "feat: {s} the corpus\n", .{exception});
        try expect_findings(text, &.{});
    }
}

// The message of commit 6e04c77, which was written to these rules.

const head_commit_message =
    \\docs: establish colibri's rules, decisions, invariants and build plan
    \\
    \\Written from the RFCs, cited by section, with every citation checked against the
    \\text rather than recalled. The shape that follows: two caller-supplied vtables
    \\instead of one, because RFC 9001 fixes Initial packets, header protection and
    \\Retry to AES whatever TLS negotiates, and splitting packet protection away from
    \\the TLS provider is what lets h3 have AES without chapulin having it.
    \\
    \\Three premises changed under checking and are recorded as corrections rather
    \\than quietly fixed: QPACK reuses HPACK's prefixed integers unmodified, flow
    \\control does not share between h2 and QUIC, and the Huffman table is adopted by
    \\RFC 9204 4.1.2 rather than a section that does not exist.
    \\
    \\Nothing is implemented. Decisions 3, 9 and 10 wait on a ruling, and the plan
    \\names one gap it does not close: no step delivers the TLS server every gate from
    \\step 5 onward needs.
    \\
;

test "the message of 6e04c77 breaks one rule: its body is 143 words" {
    // Every other rule passes. The word count does not, and this test records that rather than
    // hiding it: CLAUDE.md (Commits) holds a body at 100 words and 6e04c77 carries 143. Raising
    // the limit to make this line green would be weakening a rule to pass a test, which CLAUDE.md
    // (Ask before) puts to the owner.
    try expect_findings(head_commit_message, &.{
        "violation: body-size: the body has 143 words, over the limit of 100",
    });
    const subject_end = std.mem.indexOfScalar(u8, head_commit_message, '\n').?;
    try expect_findings(head_commit_message[0 .. subject_end + 1], &.{});
}
