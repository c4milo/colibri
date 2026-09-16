//! Tests of the eight rules of `commit_lint_rules.zig`. `expect_findings` runs every rule over one
//! message and compares the `severity: rule: message` lines it recorded, in order, so a fixture
//! pins which rule fired as well as how many did.
//!
//! `rule_cases` is the table the header of that file is answerable to: one passing message and one
//! failing message per rule, written out as string constants. A rule whose check is deleted stops
//! firing on its own failing message and fails its own case, which is what makes the table a test
//! of the rules rather than a test of the fixtures.
//!
//! The boundary fixtures write their column and word counts out as literals rather than deriving
//! them from the limits in `commit_lint_rules.zig`. A fixture derived from the limit moves when the
//! limit moves and reports nothing; a literal one fails, which is the point: the limits are
//! CLAUDE.md's and this tool does not get to raise them.
//!
//! Only tests reference this file, so nothing in it runs in the tool.
const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const message_model = @import("commit_lint_message.zig");
const rules = @import("commit_lint_rules.zig");

const fixture_source = "abc1234";

/// The module scopes of CLAUDE.md as rule 4 prints them, written out rather than built from
/// `rules.module_scopes`, so a scope added to or dropped from that list fails this file.
const module_scope_list = "h2, h3, quic, hpack, qpack, wire, http, tls, crypto, core, sim, golden, bench";

/// Runs every rule over `text` and checks the findings it recorded, in order.
fn expect_findings(text: []const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const message = try message_model.parse(arena, text);
    var findings: rules.Findings = .{ .arena = arena };
    try rules.check_all(&findings, fixture_source, &message);
    try testing.expectEqual(expected.len, findings.count());
    for (findings.items.items, expected) |finding, want| {
        const line = try std.fmt.allocPrint(arena, "{s}: {s}: {s}", .{
            finding.severity.text(),
            finding.rule,
            finding.message,
        });
        try testing.expectEqualStrings(want, line);
        try testing.expectEqualStrings(fixture_source, finding.source);
    }
}

// One passing message and one failing message per rule. Every failing message breaks exactly the
// rule it is filed under, so the case names which rule fired.

const RuleCase = struct {
    rule: []const u8,
    passing: []const u8,
    failing: []const u8,
    /// True when the failing message is a warning rather than a violation.
    warns: bool = false,
};

const rule_cases = [_]RuleCase{
    .{
        .rule = rules.subject_format_rule,
        .passing = "feat(h2): add the frame reader\n",
        .failing = "feature(h2): add the frame reader\n",
    },
    .{
        .rule = rules.subject_description_rule,
        .passing = "feat(h2): add the frame reader\n",
        .failing = "feat(h2): Add the frame reader\n",
    },
    .{
        .rule = rules.subject_length_rule,
        .passing = "feat(h2): add the frame reader\n",
        .failing = "feat(h2): add the frame reader that turns bytes into one frame and no more\n",
    },
    .{
        .rule = rules.scope_known_rule,
        .passing = "feat(hpack): add the huffman decoder\n",
        .failing = "feat(frobnicator): add the huffman decoder\n",
        .warns = true,
    },
    .{
        .rule = rules.body_separation_rule,
        .passing = "feat(h2): add the frame reader\n\nwhy it exists.\n",
        .failing = "feat(h2): add the frame reader\nwhy it exists.\n",
    },
    .{
        .rule = rules.body_line_length_rule,
        .passing = "feat(h2): add the frame reader\n\n" ++ ("w" ** 100) ++ "\n",
        .failing = "feat(h2): add the frame reader\n\n" ++ ("w" ** 101) ++ "\n",
    },
    .{
        .rule = rules.body_size_rule,
        .passing = "feat(h2): add x\n\nwhy one.\n\nwhy two.\n\nwhy three.\n",
        .failing = "feat(h2): add x\n\nwhy one.\n\nwhy two.\n\nwhy three.\n\nwhy four.\n",
    },
    .{
        .rule = rules.whitespace_rule,
        .passing = "feat(h2): add x\n\nwhy it exists.\n",
        .failing = "feat(h2): add x\n\nwhy it exists. \n",
    },
};

test "every rule passes its own passing message" {
    for (rule_cases) |case| {
        errdefer std.debug.print("the passing message of {s} was refused\n", .{case.rule});
        try expect_findings(case.passing, &.{});
    }
}

test "every rule fires on its own failing message, and only that rule fires" {
    for (rule_cases) |case| {
        errdefer std.debug.print("the failing message of {s} was accepted\n", .{case.rule});
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const message = try message_model.parse(arena, case.failing);
        var findings: rules.Findings = .{ .arena = arena };
        try rules.check_all(&findings, fixture_source, &message);
        try testing.expectEqual(1, findings.count());
        try testing.expectEqualStrings(case.rule, findings.items.items[0].rule);
        const severity: rules.Severity = if (case.warns) .warning else .violation;
        try testing.expectEqual(severity, findings.items.items[0].severity);
        try testing.expectEqual(@as(usize, if (case.warns) 0 else 1), findings.count_violations());
    }
}

test "the table covers every rule check_all runs" {
    const expected = [_][]const u8{
        rules.subject_format_rule,
        rules.subject_description_rule,
        rules.subject_length_rule,
        rules.scope_known_rule,
        rules.body_separation_rule,
        rules.body_line_length_rule,
        rules.body_size_rule,
        rules.whitespace_rule,
    };
    try testing.expectEqual(expected.len, rule_cases.len);
    for (expected, rule_cases) |want, case| {
        try testing.expectEqualStrings(want, case.rule);
    }
}

// Rule 1: the subject grammar.

test "rule 1 accepts a type, an optional scope, and an optional !" {
    try expect_findings("feat: add the frame reader\n", &.{});
    try expect_findings("feat(h2): add the frame reader\n", &.{});
    try expect_findings("feat(h2)!: add the frame reader\n", &.{});
    try expect_findings("feat!: add the frame reader\n", &.{});
    // A hyphen is part of a well-formed scope. Rule 4 warns about this one because the graph does
    // not name it, which rule 1 has no opinion about.
    try expect_findings("refactor(h2-frame): add the frame reader\n", &.{
        "warning: scope-known: the scope \"h2-frame\" is not a module of the graph (" ++ module_scope_list ++ ")",
    });
}

test "rule 1 takes every type of the closed set and no other" {
    for (rules.commit_types) |commit_type| {
        var buffer: [64]u8 = undefined;
        try expect_findings(try std.fmt.bufPrint(&buffer, "{s}: add the frame reader\n", .{commit_type}), &.{});
    }
    try expect_findings("feature: add the frame reader\n", &.{
        "violation: subject-format: the type is not one of feat, fix, docs, test, refactor, perf, build, ci, chore: \"feature: add the frame reader\"",
    });
}

test "rule 1 rejects a missing colon, a bad scope, and a missing space" {
    try expect_findings("add the frame reader\n", &.{
        "violation: subject-format: no `type(scope)!: description` colon: \"add the frame reader\"",
    });
    try expect_findings("feat(H2): add x\n", &.{
        "violation: subject-format: the scope holds a byte that is not a lowercase letter, a digit, or a hyphen: \"feat(H2): add x\"",
    });
    try expect_findings("feat(): add x\n", &.{
        "violation: subject-format: the scope is empty: \"feat(): add x\"",
    });
    try expect_findings("feat(h2: add x\n", &.{
        "violation: subject-format: the scope is not closed with `)`: \"feat(h2: add x\"",
    });
    try expect_findings("feat:add x\n", &.{
        "violation: subject-format: the colon is not followed by one space: \"feat:add x\"",
    });
}

// Rule 2: the description.

test "rule 2 wants a non-empty lowercase description with no period" {
    // The only subject with an empty description ends in the space the grammar wants after the
    // colon, so rule 8 fires beside rule 2.
    try expect_findings("feat: \n", &.{
        "violation: subject-description: the description is empty",
        "violation: whitespace: line 1 ends with whitespace",
    });
    try expect_findings("feat: Add the frame reader\n", &.{
        "violation: subject-description: the description does not start with a lowercase letter: \"Add the frame reader\"",
    });
    try expect_findings("feat: add the frame reader.\n", &.{
        "violation: subject-description: the description ends with a period: \"add the frame reader.\"",
    });
}

test "rule 2 rejects a past tense, a gerund, and every third-person form" {
    try expect_findings("feat: added the frame reader\n", &.{
        "violation: subject-description: \"added\" is a past tense, not imperative",
    });
    try expect_findings("feat: adding the frame reader\n", &.{
        "violation: subject-description: \"adding\" is a gerund, not imperative",
    });
    for (rules.third_person_forms) |form| {
        var buffer: [128]u8 = undefined;
        var want_buffer: [160]u8 = undefined;
        const subject = try std.fmt.bufPrint(&buffer, "feat: {s} the frame reader\n", .{form});
        const want = try std.fmt.bufPrint(&want_buffer, "violation: subject-description: \"{s}\" is a third-person form, not imperative", .{form});
        try expect_findings(subject, &.{want});
    }
}

test "rule 2 takes every command whose spelling ends in ed or ing" {
    for (rules.imperative_exceptions) |exception| {
        var buffer: [128]u8 = undefined;
        try expect_findings(try std.fmt.bufPrint(&buffer, "feat: {s} the corpus\n", .{exception}), &.{});
    }
}

// Rule 3: the subject length. 72 and 73 columns, written out.

test "rule 3 takes a 72-column subject and refuses a 73-column one" {
    try expect_findings("feat: " ++ ("w" ** 66) ++ "\n", &.{});
    try expect_findings("feat: " ++ ("w" ** 67) ++ "\n", &.{
        "violation: subject-length: the subject is 73 columns, over the 72-column limit",
    });
}

// Rule 4: the scope against the module graph.

test "rule 4 takes every scope CLAUDE.md names" {
    for (rules.module_scopes) |scope| {
        var buffer: [96]u8 = undefined;
        try expect_findings(try std.fmt.bufPrint(&buffer, "feat({s}): add the frame reader\n", .{scope}), &.{});
    }
}

test "rule 4 warns on a well-formed scope the graph does not name" {
    try expect_findings("feat(frobnicator): add x\n", &.{
        "warning: scope-known: the scope \"frobnicator\" is not a module of the graph (" ++ module_scope_list ++ ")",
    });
}

// Rule 5: the blank line under the subject.

test "rule 5 wants exactly one blank line, not none and not two" {
    try expect_findings("feat: add x\nwhy it exists.\n", &.{
        "violation: body-separation: no blank line between the subject and the body",
    });
    try expect_findings("feat: add x\n\n\nwhy it exists.\n", &.{
        "violation: body-separation: 2 blank lines between the subject and the body, want exactly one",
    });
}

// Rules 6 and 7: the body limits, and the trailer block they leave out.

test "rule 6 takes a 100-column body line and refuses a 101-column one" {
    try expect_findings("feat: add x\n\n" ++ ("w" ** 100) ++ "\n", &.{});
    try expect_findings("feat: add x\n\n" ++ ("w" ** 101) ++ "\n", &.{
        "violation: body-line-length: line 3 is 101 columns, over the 100-column limit",
    });
}

/// Words the word-count fixture puts on one body line, so that no line of it trips rule 6 or 8.
const words_per_line: usize = 10;

/// A message whose body holds `count` words.
fn body_of_words(arena: Allocator, count: usize) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "feat: add x\n\n");
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const separator: []const u8 = if (index == 0) "" else if (index % words_per_line == 0) "\n" else " ";
        try out.appendSlice(arena, separator);
        try out.appendSlice(arena, "why");
    }
    try out.append(arena, '\n');
    return out.items;
}

test "rule 7 takes a 100-word body and refuses a 101-word one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try expect_findings(try body_of_words(arena, 100), &.{});
    try expect_findings(try body_of_words(arena, 101), &.{
        "violation: body-size: the body has 101 words, over the limit of 100",
    });
}

test "the trailer block counts against neither body limit" {
    // A trailer line over the column limit and a fourth Key: value paragraph, both silent.
    try expect_findings("feat: add x\n\nwhy one.\n\nwhy two.\n\nwhy three.\n\n" ++
        "Co-Authored-By: " ++ ("w" ** 101) ++ "\nRefs: https://github.com/c4milo/colibri/issues/1\n", &.{});
    // The same shape with a key outside the closed set is body, and is counted.
    try expect_findings("feat: add x\n\nwhy one.\n\nwhy two.\n\nwhy three.\n\nNote: " ++ ("w" ** 101) ++ "\n", &.{
        "violation: body-line-length: line 9 is 107 columns, over the 100-column limit",
        "violation: body-size: the body has 4 paragraphs, over the limit of 3",
    });
}

// Rule 8: the whitespace.

test "rule 8 refuses a trailing space and a second trailing blank line" {
    try expect_findings("feat: add x\n\nwhy it exists. \n", &.{
        "violation: whitespace: line 3 ends with whitespace",
    });
    try expect_findings("feat: add x\t\n", &.{
        "violation: whitespace: line 1 ends with whitespace",
    });
    try expect_findings("feat: add x\n\n\n", &.{
        "violation: whitespace: the message ends with 2 blank lines, over the limit of 1",
    });
}

// The message of this repository's HEAD commit, 6e04c77, which was written to these rules.

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

test "the HEAD commit message breaks one rule: its body is 143 words" {
    // Every other rule passes. The word count does not, and this test records that rather than
    // hiding it: CLAUDE.md (Commits) holds a body at 100 words and 6e04c77 carries 143, so the
    // first commit written to these rules is over the limit its own document states. Raising
    // `body_words_max` to make this line green would be weakening a rule to pass a test, which
    // CLAUDE.md (Ask before) puts to the owner.
    try expect_findings(head_commit_message, &.{
        "violation: body-size: the body has 143 words, over the limit of 100",
    });
}

test "the HEAD commit subject passes every subject rule" {
    const subject_end = std.mem.indexOfScalar(u8, head_commit_message, '\n').?;
    try expect_findings(head_commit_message[0 .. subject_end + 1], &.{});
    const parts = try rules.parse_subject(head_commit_message[0..subject_end]);
    try testing.expectEqualStrings("docs", parts.type_name);
    try testing.expectEqual(null, parts.scope);
    try testing.expectEqual(false, parts.breaking);
    try testing.expectEqualStrings("establish colibri's rules, decisions, invariants and build plan", parts.description);
}
