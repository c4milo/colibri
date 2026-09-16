//! The eight commit-message rules of CLAUDE.md (Commits), one named function each, over the
//! `Message` of `commit_lint_message.zig`. Every finding names the rule it broke.
//!
//!  1. subject-format: the subject reads `type(scope)!: description`, with the scope and the `!`
//!     optional. The type is one of `commit_types`; the scope, when present, holds lowercase
//!     letters, digits and hyphens only, which is what `is_well_formed_scope` states the case for.
//!  2. subject-description: the description is non-empty, starts with a lowercase letter, does not
//!     end with a period, and is imperative. A first word ending in `ed` or `ing`, or one of
//!     `third_person_forms`, is not imperative unless it is one of `imperative_exceptions`. The
//!     four checks report separately, so a subject that breaks two of them says so twice.
//!  3. subject-length: the whole subject line is at most `subject_columns_max` columns.
//!  4. scope-known: a warning, not a violation, when a well-formed scope is outside
//!     `module_scopes`. CLAUDE.md states that scopes track the module graph and lists the modules
//!     of docs/design.md §3; a closed check would make this tool, rather than the design, the
//!     authority on what modules exist, and would refuse the first commit of a module the graph
//!     has just grown. So the grammar accepts any well-formed scope and this rule says which ones
//!     the graph does not name. A warning does not change the exit status.
//!  5. body-separation: when a body exists, exactly one blank line sits between it and the subject.
//!  6. body-line-length: every body line is at most `body_columns_max` columns.
//!  7. body-size: the body is at most `body_paragraphs_max` paragraphs and `body_words_max` words.
//!     The diff shows the what, so the body says why.
//!  8. whitespace: no line ends in whitespace, and the message ends with at most
//!     `trailing_blank_lines_max` blank line.
//!
//! Rule 3 reads the subject and nothing else. Rules 5, 6 and 7 read the body with the trailer
//! block left out, so a `Co-Authored-By` line is neither a body line nor a body word and no column
//! limit applies to it: an address or a URL a trailer carries is as long as it is. Rule 8 is the
//! one rule that reads every line, trailers included, because a trailer ending in a space is still
//! a defect in the message.
//!
//! Rule 2 and rule 4 report nothing when rule 1 could not parse the subject: there is no
//! description and no scope to judge, and rule 1 has already said so.
//!
//! The tests of these rules are `commit_lint_rules_test.zig`, which is a second file only because
//! CLAUDE.md holds a source file at 500 lines including its tests.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const message_model = @import("commit_lint_message.zig");
const Message = message_model.Message;

/// The closed set of types a subject may name (CLAUDE.md, Commits).
pub const commit_types = [_][]const u8{ "feat", "fix", "docs", "test", "refactor", "perf", "build", "ci", "chore" };

/// The scopes CLAUDE.md names, one per module of docs/design.md §3. A scope outside this set is a
/// warning, never a violation: see rule 4 in the header.
pub const module_scopes = [_][]const u8{ "h2", "h3", "quic", "hpack", "qpack", "wire", "http", "tls", "crypto", "core", "sim", "golden", "bench" };

/// First words that describe the commit instead of commanding it.
pub const third_person_forms = [_][]const u8{ "adds", "fixes", "updates", "removes", "implements", "splits", "renames", "moves", "makes", "drops", "lands", "keeps" };

/// Commands whose spelling ends in `ed` or `ing` all the same. The suffix test reads the last two
/// or three bytes of a word, not its grammar, so without this list it refuses `bring the hook
/// back` and `seed the corpus`.
pub const imperative_exceptions = [_][]const u8{ "bring", "embed", "seed", "speed", "feed", "exceed", "proceed", "succeed", "shed", "ring", "string", "spread" };

/// The most columns a subject line may occupy.
pub const subject_columns_max: usize = 72;

/// The most columns a body line may occupy.
pub const body_columns_max: usize = 100;

/// The most paragraphs a body may hold.
pub const body_paragraphs_max: usize = 3;

/// The most words a body may hold.
pub const body_words_max: usize = 100;

/// The most blank lines a message may end with.
pub const trailing_blank_lines_max: usize = 1;

/// Findings recorded in one run. One more is an error, never a dropped finding.
pub const findings_max: usize = 65536;

/// The word ending that marks a past tense, and the one that marks a gerund.
const past_tense_suffix = "ed";
const gerund_suffix = "ing";

/// The bytes the subject grammar is written with.
const type_separator: u8 = ':';
const separator_space: u8 = ' ';
const breaking_marker: u8 = '!';
const scope_open: u8 = '(';
const scope_close: u8 = ')';
const scope_hyphen: u8 = '-';
const description_period: u8 = '.';

pub const subject_format_rule = "subject-format";
pub const subject_description_rule = "subject-description";
pub const subject_length_rule = "subject-length";
pub const scope_known_rule = "scope-known";
pub const body_separation_rule = "body-separation";
pub const body_line_length_rule = "body-line-length";
pub const body_size_rule = "body-size";
pub const whitespace_rule = "whitespace";

/// Whether a finding refuses the commit or only reports on it. A run exits non-zero for a
/// `violation` and not for a `warning`.
pub const Severity = enum {
    violation,
    warning,

    pub fn text(self: Severity) []const u8 {
        return switch (self) {
            .violation => "violation",
            .warning => "warning",
        };
    }
};

/// A list written once and read twice: the check reads the set, the message a reader sees prints
/// the same set.
fn joined(comptime items: []const []const u8) []const u8 {
    comptime {
        var text: []const u8 = "";
        for (items, 0..) |item, index| {
            text = text ++ (if (index == 0) "" else ", ") ++ item;
        }
        return text;
    }
}

const commit_type_list = joined(&commit_types);
const module_scope_list = joined(&module_scopes);

pub const Finding = struct {
    /// The commit sha the message came from.
    source: []const u8,
    severity: Severity,
    rule: []const u8,
    message: []const u8,
};

/// What one run accumulates. Every rule calls `add` or `warn` once per finding, and `write` prints
/// them in the order they were recorded.
pub const Findings = struct {
    arena: Allocator,
    items: std.ArrayList(Finding) = .empty,

    pub fn add(
        self: *Findings,
        source: []const u8,
        rule: []const u8,
        comptime format: []const u8,
        arguments: anytype,
    ) !void {
        try self.record(.violation, source, rule, format, arguments);
    }

    pub fn warn(
        self: *Findings,
        source: []const u8,
        rule: []const u8,
        comptime format: []const u8,
        arguments: anytype,
    ) !void {
        try self.record(.warning, source, rule, format, arguments);
    }

    fn record(
        self: *Findings,
        severity: Severity,
        source: []const u8,
        rule: []const u8,
        comptime format: []const u8,
        arguments: anytype,
    ) !void {
        if (self.items.items.len >= findings_max) return error.TooManyFindings;
        try self.items.append(self.arena, .{
            .source = try self.arena.dupe(u8, source),
            .severity = severity,
            .rule = rule,
            .message = try std.fmt.allocPrint(self.arena, format, arguments),
        });
    }

    pub fn count(self: *const Findings) usize {
        return self.items.items.len;
    }

    /// Findings that refuse the commit. The exit status reads this, not `count`.
    pub fn count_violations(self: *const Findings) usize {
        var total: usize = 0;
        for (self.items.items) |finding| {
            if (finding.severity == .violation) total += 1;
        }
        return total;
    }

    /// Writes every finding as one `source: severity: rule: message` line.
    pub fn write(self: *const Findings, out: *Io.Writer) !void {
        for (self.items.items) |finding| {
            try out.print("{s}: {s}: {s}: {s}\n", .{
                finding.source,
                finding.severity.text(),
                finding.rule,
                finding.message,
            });
        }
    }
};

/// Runs every rule over one message.
pub fn check_all(findings: *Findings, source: []const u8, message: *const Message) !void {
    try check_subject_format(findings, source, message);
    try check_subject_description(findings, source, message);
    try check_subject_length(findings, source, message);
    try check_scope_known(findings, source, message);
    try check_body_separation(findings, source, message);
    try check_body_line_length(findings, source, message);
    try check_body_size(findings, source, message);
    try check_whitespace(findings, source, message);
}

// Rule 1: the subject grammar.

pub const SubjectError = error{
    MissingSeparator,
    UnknownType,
    UnclosedScope,
    EmptyScope,
    ScopeNotLowercase,
    MissingSpaceAfterColon,
};

pub const SubjectParts = struct {
    type_name: []const u8,
    scope: ?[]const u8,
    breaking: bool,
    description: []const u8,
};

pub fn parse_subject(subject: []const u8) SubjectError!SubjectParts {
    const colon = std.mem.indexOfScalar(u8, subject, type_separator) orelse return error.MissingSeparator;
    const marked = strip_breaking(subject[0..colon]);
    const scoped = try strip_scope(marked.head);
    if (!is_commit_type(scoped.head)) return error.UnknownType;
    return .{
        .type_name = scoped.head,
        .scope = scoped.scope,
        .breaking = marked.breaking,
        .description = try description_after(subject[colon + 1 ..]),
    };
}

const Marked = struct { head: []const u8, breaking: bool };

fn strip_breaking(head: []const u8) Marked {
    if (head.len != 0 and head[head.len - 1] == breaking_marker) {
        return .{ .head = head[0 .. head.len - 1], .breaking = true };
    }
    return .{ .head = head, .breaking = false };
}

const Scoped = struct { head: []const u8, scope: ?[]const u8 };

fn strip_scope(head: []const u8) SubjectError!Scoped {
    if (head.len == 0 or head[head.len - 1] != scope_close) {
        if (std.mem.indexOfScalar(u8, head, scope_open) != null) return error.UnclosedScope;
        return .{ .head = head, .scope = null };
    }
    const open = std.mem.indexOfScalar(u8, head, scope_open) orelse return error.UnclosedScope;
    const scope = head[open + 1 .. head.len - 1];
    if (scope.len == 0) return error.EmptyScope;
    if (!is_well_formed_scope(scope)) return error.ScopeNotLowercase;
    return .{ .head = head[0..open], .scope = scope };
}

fn description_after(rest: []const u8) SubjectError![]const u8 {
    if (rest.len == 0 or rest[0] != separator_space) return error.MissingSpaceAfterColon;
    return rest[1..];
}

fn is_commit_type(head: []const u8) bool {
    for (commit_types) |commit_type| {
        if (std.mem.eql(u8, head, commit_type)) return true;
    }
    return false;
}

/// True when every byte of the scope is a lowercase letter, a digit, or a hyphen. CLAUDE.md
/// (Commits) says "lowercase letters and hyphens" in one sentence and names `h2` and `h3` as
/// scopes in the next, so a digit is part of a well-formed scope: refusing one would refuse the
/// two scopes the document lists first. Uppercase and every other byte is still refused.
fn is_well_formed_scope(scope: []const u8) bool {
    for (scope) |byte| {
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != scope_hyphen) return false;
    }
    return true;
}

fn subject_error_text(err: SubjectError) []const u8 {
    return switch (err) {
        error.MissingSeparator => "no `type(scope)!: description` colon",
        error.UnknownType => "the type is not one of " ++ commit_type_list,
        error.UnclosedScope => "the scope is not closed with `)`",
        error.EmptyScope => "the scope is empty",
        error.ScopeNotLowercase => "the scope holds a byte that is not a lowercase letter, a digit, or a hyphen",
        error.MissingSpaceAfterColon => "the colon is not followed by one space",
    };
}

fn check_subject_format(findings: *Findings, source: []const u8, message: *const Message) !void {
    _ = parse_subject(message.subject) catch |err| {
        try findings.add(source, subject_format_rule, "{s}: \"{s}\"", .{ subject_error_text(err), message.subject });
    };
}

// Rule 2: the description.

fn check_subject_description(findings: *Findings, source: []const u8, message: *const Message) !void {
    const parts = parse_subject(message.subject) catch return;
    const description = parts.description;
    if (description.len == 0) {
        try findings.add(source, subject_description_rule, "the description is empty", .{});
        return;
    }
    if (!std.ascii.isLower(description[0])) {
        try findings.add(source, subject_description_rule, "the description does not start with a lowercase letter: \"{s}\"", .{description});
    }
    if (description[description.len - 1] == description_period) {
        try findings.add(source, subject_description_rule, "the description ends with a period: \"{s}\"", .{description});
    }
    const word = message_model.first_word(description);
    if (non_imperative_reason(word)) |reason| {
        try findings.add(source, subject_description_rule, "\"{s}\" is {s}, not imperative", .{ word, reason });
    }
}

/// Why the first word is not a command, or null when it reads as one. The exception list is read
/// first, because it names commands the suffix test below would otherwise refuse.
fn non_imperative_reason(word: []const u8) ?[]const u8 {
    for (imperative_exceptions) |exception| {
        if (std.mem.eql(u8, word, exception)) return null;
    }
    for (third_person_forms) |form| {
        if (std.mem.eql(u8, word, form)) return "a third-person form";
    }
    if (std.mem.endsWith(u8, word, gerund_suffix)) return "a gerund";
    if (std.mem.endsWith(u8, word, past_tense_suffix)) return "a past tense";
    return null;
}

// Rule 3: the subject length.

fn check_subject_length(findings: *Findings, source: []const u8, message: *const Message) !void {
    const width = message_model.columns(message.subject);
    if (width <= subject_columns_max) return;
    try findings.add(source, subject_length_rule, "the subject is {d} columns, over the {d}-column limit", .{ width, subject_columns_max });
}

// Rule 4: the scope against the module graph. A warning; see the header.

fn check_scope_known(findings: *Findings, source: []const u8, message: *const Message) !void {
    const parts = parse_subject(message.subject) catch return;
    const scope = parts.scope orelse return;
    for (module_scopes) |known| {
        if (std.mem.eql(u8, scope, known)) return;
    }
    try findings.warn(source, scope_known_rule, "the scope \"{s}\" is not a module of the graph ({s})", .{ scope, module_scope_list });
}

// Rule 5: the blank line under the subject.

fn check_body_separation(findings: *Findings, source: []const u8, message: *const Message) !void {
    const content = message.first_content_index() orelse return;
    if (content == 1) {
        try findings.add(source, body_separation_rule, "no blank line between the subject and the body", .{});
        return;
    }
    if (content > 2) {
        try findings.add(source, body_separation_rule, "{d} blank lines between the subject and the body, want exactly one", .{content - 1});
    }
}

// Rule 6: the body line length.

fn check_body_line_length(findings: *Findings, source: []const u8, message: *const Message) !void {
    for (message.body_lines(), 0..) |line, index| {
        const width = message_model.columns(line);
        if (width <= body_columns_max) continue;
        try findings.add(source, body_line_length_rule, "line {d} is {d} columns, over the {d}-column limit", .{ message.body_line_number(index), width, body_columns_max });
    }
}

// Rule 7: the body size.

fn check_body_size(findings: *Findings, source: []const u8, message: *const Message) !void {
    const body = message.body_lines();
    const paragraphs = message_model.count_paragraphs(body);
    if (paragraphs > body_paragraphs_max) {
        try findings.add(source, body_size_rule, "the body has {d} paragraphs, over the limit of {d}", .{ paragraphs, body_paragraphs_max });
    }
    const words = message_model.count_words(body);
    if (words > body_words_max) {
        try findings.add(source, body_size_rule, "the body has {d} words, over the limit of {d}", .{ words, body_words_max });
    }
}

// Rule 8: the whitespace.

fn check_whitespace(findings: *Findings, source: []const u8, message: *const Message) !void {
    for (message.lines, 0..) |line, index| {
        if (std.mem.trimEnd(u8, line, message_model.whitespace).len == line.len) continue;
        try findings.add(source, whitespace_rule, "line {d} ends with whitespace", .{index + 1});
    }
    const blanks = message_model.count_trailing_blank_lines(message.lines);
    if (blanks > trailing_blank_lines_max) {
        try findings.add(source, whitespace_rule, "the message ends with {d} blank lines, over the limit of {d}", .{ blanks, trailing_blank_lines_max });
    }
}
