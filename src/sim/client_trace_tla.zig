//! Writes one seed of the client trace run as TLA+ (decision 105): a module whose `SeedTrace` is
//! the sequence of the model's states the run went through, and a TLC configuration that checks
//! it against `spec/tla/client_exchanges/ClientExchangesTrace.tla`. `tools/client_trace.sh`
//! writes them for many seeds and runs TLC over them.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const quic = @import("quic");
const state_module = @import("client_trace_state.zig");
const plan_module = @import("client_trace_plan.zig");

const Writer = quic.core.Writer;
const State = state_module.State;
const Plan = plan_module.Plan;

pub const Error = quic.core.writer.Error;

/// The longest line one `print` writes.
const line_len_max: usize = 256;

fn print(writer: *Writer, comptime format: []const u8, arguments: anytype) Error!void {
    var line: [line_len_max]u8 = undefined;
    const text = std.fmt.bufPrint(&line, format, arguments) catch return error.NoSpaceLeft;
    try writer.write_bytes(text);
}

/// The module's name for `seed`, which its file and its configuration's file carry.
pub fn module_name(seed: u64, name: []u8) []const u8 {
    return std.fmt.bufPrint(name, "ClientTraceSeed{x:0>4}", .{seed}) catch unreachable;
}

pub fn write_module(writer: *Writer, name: []const u8, plan: *const Plan, states: []const State) Error!void {
    assert(states.len > 0);
    try print(writer, "---- MODULE {s} ----\nEXTENDS ClientExchangesTrace\n\nSeedTrace == <<\n", .{name});
    for (states, 0..) |*state, index| {
        try write_state(writer, plan.exchanges, state);
        try writer.write_bytes(if (index + 1 < states.len) ",\n" else "\n");
    }
    try writer.write_bytes(">>\n\nSeedGoal == Len(SeedTrace)\n\n====\n");
}

/// The configuration: the model's constants as the seed's plan and its run set them. Every
/// transport may fail, refuse, reset and send a GOAWAY, since the trace shows which did.
pub fn write_config(writer: *Writer, plan: *const Plan, last: *const State, goaways: u32, steps_max: u64) Error!void {
    try writer.write_bytes("\\* expect: violated\nSPECIFICATION TraceSpec\nCONSTANTS\n");
    const opens = @max(1, @max(last.opens[0], last.opens[1]));
    try print(writer, "    N = {d}\n    Opens = {d}\n    MovesMax = {d}\n", .{ plan.exchanges, opens, client.constants.moves_max });
    try print(writer, "    QuicPolicy = \"{t}\"\n", .{plan.policy});
    const all = "{\"quic\", \"tcp\"}";
    try print(writer, "    HandshakeFails = {s}\n    Breaks = {s}\n    Goaways = {s}\n", .{ all, all, all });
    try print(writer, "    GoawaysMax = {d}\n    Refusals = {s}\n    Resets = {s}\n", .{ goaways, all, all });
    try writer.write_bytes("    ReleaseOnFail = TRUE\n    CloseWhenDrained = TRUE\n    ReportWhenReleased = TRUE\n");
    try writer.write_bytes("    CancelReleases = TRUE\n    SentFailsClosed = TRUE\n    MoveRefused = TRUE\n");
    try writer.write_bytes("    Trace <- SeedTrace\n    Goal <- SeedGoal\n");
    try print(writer, "    StepsMax = {d}\nCONSTRAINT Within\nINVARIANT Unfinished\nCHECK_DEADLOCK FALSE\n", .{steps_max});
}

fn boolean(value: bool) []const u8 {
    return if (value) "TRUE" else "FALSE";
}

fn write_state(writer: *Writer, exchanges: u32, state: *const State) Error!void {
    const n: usize = exchanges;
    try writer.write_bytes("[");
    try write_names(writer, "stage", state.stage[0..n]);
    try write_names(writer, "carrier", state.carrier[0..n]);
    try write_booleans(writer, "holds", state.holds[0..n]);
    try write_names(writer, "outcome", state.outcome[0..n]);
    try write_numbers(writer, "moved", state.moved[0..n]);
    try write_booleans(writer, "seen", state.seen[0..n]);
    try write_numbers(writer, "processed", state.processed[0..n]);
    try print(writer, "phase |-> [quic |-> \"{t}\", tcp |-> \"{t}\"], ", .{ state.phase[0], state.phase[1] });
    try print(writer, "opens |-> [quic |-> {d}, tcp |-> {d}], ", .{ state.opens[0], state.opens[1] });
    try writer.write_bytes("tried |-> {");
    if (state.tried[0]) try writer.write_bytes("\"quic\"");
    if (state.tried[0] and state.tried[1]) try writer.write_bytes(", ");
    if (state.tried[1]) try writer.write_bytes("\"tcp\"");
    try print(writer, "}}, fallback |-> {s}, learned |-> {s}, shut |-> {s}]", .{ boolean(state.fallback), boolean(state.learned), boolean(state.shut) });
}

fn write_numbers(writer: *Writer, field: []const u8, values: []const u8) Error!void {
    try print(writer, "{s} |-> <<", .{field});
    for (values, 0..) |value, index| try print(writer, "{s}{d}", .{ separator(index), value });
    try writer.write_bytes(">>, ");
}

fn write_booleans(writer: *Writer, field: []const u8, values: []const bool) Error!void {
    try print(writer, "{s} |-> <<", .{field});
    for (values, 0..) |value, index| try print(writer, "{s}{s}", .{ separator(index), boolean(value) });
    try writer.write_bytes(">>, ");
}

/// A sequence of enum values, each written as the model's string, which is the value's name.
fn write_names(writer: *Writer, field: []const u8, values: anytype) Error!void {
    try print(writer, "{s} |-> <<", .{field});
    for (values, 0..) |value, index| try print(writer, "{s}\"{t}\"", .{ separator(index), value });
    try writer.write_bytes(">>, ");
}

fn separator(index: usize) []const u8 {
    return if (index == 0) "" else ", ";
}
