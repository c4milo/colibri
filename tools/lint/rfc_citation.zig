//! rfc-citation: a check that exists because an RFC demands it carries the RFC and the section in
//! a comment on the line that does the checking (CLAUDE.md non-negotiable 9). A reader must be able
//! to go from any validation to the sentence that requires it.
//!
//! Over every `.zig` file under `src/`, but for `src/golden/`, `src/sim/` and `src/testing/`, the
//! rule reads every `return error.Name` outside a `test` block as a validation branch. The branch
//! is cited when a comment holds `RFC <number> §<section>` or `RFC <number> Appendix <letter>` in
//! either of two places:
//!
//! 1. on a line from the first token of the statement holding the `return` to the `return` itself,
//!    so a trailing comment on a multi-line `if` counts;
//! 2. on the run of comment lines directly above that statement, with no blank line between.
//!
//! The statement starts after the nearest `;`, `{`, `}`, `,`, or unclosed `(` or `[`, before the
//! `return`, skipping every parenthesis and bracket closed in between. `if (octet == '\r') return
//! error.X;` starts at `if`, and `const len = cast(length) orelse return error.X;` starts at
//! `const`. A `return` alone inside braces is its own statement, and a `return` inside an argument
//! starts at that argument, so the citation goes directly above either.
//!
//! Two kinds of error are not RFC rules, and the rule does not read them:
//!
//! - `operational_errors`: a short input or a full output buffer, which CLAUDE.md calls operational
//!   and which no RFC states.
//! - a name starting `Test`, which a fuzz property function returns to fail its test.
//!
//! What the rule cannot see. It reads `return error.Name` only, so a validation that returns
//! `false`, `null` or an error held in a variable is outside it. It checks that a citation is
//! present, not that the section says what the check does: the reader of the citation does that.
//! `src/golden/`, `src/sim/` and `src/testing/` hold the corpus, the simulator and the test-only
//! endpoints, which check colibri rather than a peer.
//!
//! This rule is colibri's own, written against pepegrillo's readers (decision 36).

const std = @import("std");
const Ast = std.zig.Ast;
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const report = lint.report;
const Scope = lint.Scope;

pub const name = "rfc-citation";

/// The files the rule reads.
pub const scope: Scope = .{
    .extensions = &.{lint.paths.zig_extension},
    .include_directories = &.{"src"},
    .exclude_directories = &.{ "src/golden", "src/sim", "src/testing" },
};

/// Errors that report a short input or a full output buffer. CLAUDE.md calls these operational,
/// and no RFC states them, so they need no citation.
const operational_errors = [_][]const u8{ "Truncated", "NoSpaceLeft" };

/// The prefix of an error a fuzz property function returns to fail its test.
const test_error_prefix = "Test";

/// The words that name an RFC, and the two ways colibri names a part of one.
const rfc_word = "RFC ";
const section_mark = " §";
const appendix_word = " Appendix ";

/// The comment marker a citation must follow on its line.
const comment_marker = "//";

pub fn check(context: *report.Context, file: report.File) !void {
    if (!scope.applies(file.path)) return;
    const tree = file.tree orelse return;
    const tags = tree.tokens.items(.tag);
    var token: Ast.TokenIndex = 0;
    while (token + 3 < tags.len) : (token += 1) {
        if (!is_error_return(tags, token)) continue;
        const error_name = tree.tokenSlice(token + 3);
        if (is_exempt(error_name) or in_test_block(tree, token)) continue;
        if (is_cited(tree, statement_start(tags, token), token)) continue;
        try context.findings.add(
            name,
            file.path,
            lint.ast.token_location(tree, token).line,
            lint.ast.token_location(tree, token).column,
            "error.{s} has no RFC section comment on its check; cite the RFC and the section" ++
                " that require it (CLAUDE.md non-negotiable 9)",
            .{error_name},
        );
    }
}

/// True for the tokens `return error .` starting at `token`. A tree that parsed holds the error's
/// name next.
fn is_error_return(tags: []const std.zig.Token.Tag, token: Ast.TokenIndex) bool {
    return tags[token] == .keyword_return and tags[token + 1] == .keyword_error and
        tags[token + 2] == .period;
}

fn is_exempt(error_name: []const u8) bool {
    if (std.mem.startsWith(u8, error_name, test_error_prefix)) return true;
    for (operational_errors) |operational| {
        if (std.mem.eql(u8, error_name, operational)) return true;
    }
    return false;
}

/// True when `token` lies inside a top-level `test` block.
fn in_test_block(tree: *const Ast, token: Ast.TokenIndex) bool {
    for (tree.rootDecls()) |declaration| {
        if (tree.nodeTag(declaration) != .test_decl) continue;
        const inside = token >= tree.firstToken(declaration) and token <= tree.lastToken(declaration);
        if (inside) return true;
    }
    return false;
}

/// The first token of the statement holding the `return` at `token`.
fn statement_start(tags: []const std.zig.Token.Tag, token: Ast.TokenIndex) Ast.TokenIndex {
    var depth: usize = 0;
    var index = token;
    while (index > 0) : (index -= 1) {
        switch (tags[index - 1]) {
            .r_paren, .r_bracket => depth += 1,
            .l_paren, .l_bracket => {
                if (depth == 0) return index;
                depth -= 1;
            },
            .semicolon, .l_brace, .r_brace, .comma => if (depth == 0) return index,
            else => {},
        }
    }
    return 0;
}

/// True when the run of comment lines directly above the statement starting at `first_token`
/// holds a citation, or a comment from that token to the end of the `return` line does.
fn is_cited(tree: *const Ast, first_token: Ast.TokenIndex, return_token: Ast.TokenIndex) bool {
    const first_line = lint.ast.token_location(tree, first_token).line;
    if (is_run_above_cited(tree.source, first_line)) return true;
    const return_line = lint.ast.token_location(tree, return_token).line;
    var token = first_token;
    while (token + 1 < tree.tokens.len) : (token += 1) {
        const line = lint.ast.token_location(tree, token).line;
        if (line > return_line) return false;
        // Comments are not tokens, so they are the text between one token and the next. Past the
        // `return` line, that text belongs to the next statement.
        const gap_start = tree.tokenStart(token) + tree.tokenSlice(token).len;
        var gap = tree.source[gap_start..tree.tokenStart(token + 1)];
        if (line == return_line) gap = gap[0 .. std.mem.indexOfScalar(u8, gap, '\n') orelse gap.len];
        if (has_citation(gap)) return true;
    }
    return false;
}

/// True when the comment lines directly above `first_line`, with no other line between, hold a
/// citation.
fn is_run_above_cited(source: []const u8, first_line: usize) bool {
    var lines: lint.text.LineIterator = .{ .source = source };
    var run_cited = false;
    while (lines.next()) |line| {
        if (line.number >= first_line) break;
        // A comment line extends the run above the statement, and any other line ends it.
        const trimmed = std.mem.trimStart(u8, line.text, " \t");
        const is_comment = std.mem.startsWith(u8, trimmed, comment_marker);
        run_cited = is_comment and (run_cited or has_citation(trimmed));
    }
    return run_cited;
}

/// True when `text` holds `RFC <digits> §<digit>` or `RFC <digits> Appendix <letter>`.
fn has_citation(text: []const u8) bool {
    var rest = text;
    while (std.mem.indexOf(u8, rest, rfc_word)) |found| {
        const after = rest[found + rfc_word.len ..];
        const digits = std.mem.indexOfNone(u8, after, "0123456789") orelse after.len;
        // With no digits, `after` starts with neither part's leading space.
        if (names_a_part(after[digits..])) return true;
        rest = after;
    }
    return false;
}

/// True when `text` starts with a section mark and a digit, or the word Appendix and a letter.
fn names_a_part(text: []const u8) bool {
    if (std.mem.startsWith(u8, text, section_mark)) {
        const part = text[section_mark.len..];
        return part.len > 0 and std.ascii.isDigit(part[0]);
    }
    if (std.mem.startsWith(u8, text, appendix_word)) {
        const part = text[appendix_word.len..];
        return part.len > 0 and std.ascii.isUpper(part[0]);
    }
    return false;
}

test {
    _ = @import("rfc_citation_test.zig");
}
