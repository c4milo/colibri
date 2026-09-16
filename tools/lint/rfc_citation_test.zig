//! Tests for the rfc-citation rule: one fixture per shape its header names.

const std = @import("std");
const testing = std.testing;
const pepegrillo = @import("pepegrillo");
const harness = pepegrillo.lint.harness;
const rfc_citation = @import("rfc_citation.zig");

fn expect_findings(path: []const u8, source: [:0]const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), rfc_citation, path, source);
    try harness.expect_messages(findings, expected);
}

fn message(comptime error_name: []const u8) []const u8 {
    return "error." ++ error_name ++ " has no RFC section comment on its check; cite the RFC and" ++
        " the section that require it (CLAUDE.md non-negotiable 9)";
}

const uncited_fixture: [:0]const u8 =
    \\pub fn validate(value: []const u8) !void {
    \\    if (value.len == 0) return error.Empty;
    \\}
;

test "rfc-citation passes a citation above, trailing, and above a multi-line statement" {
    try expect_findings("src/http/field.zig",
        \\pub fn validate(value: []const u8, length: u64) !void {
        \\    // RFC 9110 §5.5: a recipient of CR, LF or NUL must reject the message.
        \\    if (value.len == 0) return error.Empty;
        \\    if (value[0] == ' ') return error.Leading; // RFC 9113 §8.2.1: no leading SP.
        \\    // RFC 7541 Appendix B: the code the table gives.
        \\    // A second line of the same comment.
        \\    const len = std.math.cast(usize, length) orelse
        \\        return error.TooLong;
        \\    if (value.len > len or
        \\        value.len == 3) // RFC 9000 §16: a length the encoding holds.
        \\        return error.Mismatch;
        \\    if (value.len == 4) {
        \\        return error.Four; // RFC 9000 §16
        \\    }
        \\    // RFC 9110 §5.6.2: a token.
        \\    if (check(
        \\        value,
        \\        len,
        \\    )) return error.NotToken;
        \\    _ = switch (value[0]) {
        \\        'b' => 1,
        \\        // RFC 9110 §15: three digits.
        \\        'a' => return error.Letter,
        \\        else => 2,
        \\    };
        \\}
    , &.{});
}

test "rfc-citation flags a branch with no comment" {
    try expect_findings("src/http/field.zig", uncited_fixture, &.{message("Empty")});
}

test "rfc-citation flags an RFC named with no section, and a section with no RFC" {
    try expect_findings("src/http/field.zig",
        \\pub fn validate(value: []const u8) !void {
        \\    // RFC 9110: field values.
        \\    if (value.len == 0) return error.Empty;
        \\    // §5.5 of the semantics document.
        \\    if (value.len == 1) return error.One;
        \\    // RFC 9110 Appendix for the collected ABNF.
        \\    if (value.len == 2) return error.Two;
        \\    // RFC §5.5: field values.
        \\    if (value.len == 3) return error.Three;
        \\    // RFC 9110 §x: field values.
        \\    if (value.len == 4) return error.Four;
        \\}
    , &.{ message("Empty"), message("One"), message("Two"), message("Three"), message("Four") });
}

test "rfc-citation flags a citation a blank line, a statement, a prong or an argument away" {
    try expect_findings("src/http/field.zig",
        \\pub fn validate(value: []const u8) !void {
        \\    // RFC 9110 §5.5: field values.
        \\
        \\    if (value.len == 0) return error.Empty;
        \\    // RFC 9110 §5.5: field values.
        \\    const first = value[0];
        \\    if (first == ' ') return error.Leading;
        \\    const text = "// RFC 9110 §5.5"; if (first == 'a') return error.Quoted;
        \\    _ = switch (first) {
        \\        // RFC 9110 §15: three digits.
        \\        'b' => 1,
        \\        'c' => return error.Prong,
        \\        else => 2,
        \\    };
        \\    // RFC 9110 §5.5: above the call, not above the argument.
        \\    consume(
        \\        std.math.cast(usize, value.len) orelse return error.Argument,
        \\    );
        \\}
    , &.{
        message("Empty"),
        message("Leading"),
        message("Quoted"),
        message("Prong"),
        message("Argument"),
    });
}

test "rfc-citation reads neither operational errors, test errors nor test blocks" {
    try expect_findings("src/core/reader.zig",
        \\pub fn take(self: *Reader, len: usize) ![]const u8 {
        \\    if (len > self.remaining_len()) return error.Truncated;
        \\    if (len > self.buffer.len) return error.NoSpaceLeft;
        \\    return error.TestUnexpectedResult;
        \\}
        \\test "a refusal" {
        \\    return error.Empty;
        \\}
    , &.{});
}

test "rfc-citation reads src/ but not the corpus, the simulator or the test-only endpoints" {
    try expect_findings("src/quic/packet.zig", uncited_fixture, &.{message("Empty")});
    try expect_findings("src/golden/corpus.zig", uncited_fixture, &.{});
    try expect_findings("src/sim/pipe.zig", uncited_fixture, &.{});
    try expect_findings("src/testing/endpoint.zig", uncited_fixture, &.{});
    try expect_findings("tools/golden.zig", uncited_fixture, &.{});
    try expect_findings("build/modules.zig", uncited_fixture, &.{});
    try expect_findings("src/http/field.md", uncited_fixture, &.{});
}
