//! Writes one seed of the h3 deadline trace run as TLA+ (design §8 step 20d): a module whose
//! `SeedTrace` is the sequence of logged states the run went through, and a TLC configuration
//! that checks it against `spec/tla/h3_deadlines/H3DeadlinesTrace.tla` with the seed's constants.
//! `tools/h3_deadline_trace.sh` writes them for many seeds and runs TLC over them.
//!
//! The model's windows are wider than all a plan sends, so its credit never binds, as the run's
//! does not, and its congestion window holds every packet the model's colibri could send.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const plan_module = @import("h3_deadline_trace_plan.zig");
const state_module = @import("h3_deadline_trace_state.zig");

const Writer = quic.core.Writer;
const Plan = plan_module.Plan;
const State = state_module.State;

pub const Error = quic.core.writer.Error;

/// The longest line one `print` writes.
const line_len_max: usize = 256;
const credit_fraction: u32 = quic.constants.flow_credit_fraction;
/// The packets the model's colibri owes on a request stream at most besides the response's units:
/// a 408, a RESET_STREAM and STOP_SENDING, and one more for the GOAWAY.
const control_packets_per_request: u32 = 4;

fn print(writer: *Writer, comptime format: []const u8, arguments: anytype) Error!void {
    var line: [line_len_max]u8 = undefined;
    const text = std.fmt.bufPrint(&line, format, arguments) catch return error.NoSpaceLeft;
    try writer.write_bytes(text);
}

/// The module's name for `seed`, which its file and its configuration's file carry.
pub fn module_name(seed: u64, name: []u8) []const u8 {
    return std.fmt.bufPrint(name, "H3DeadlineTraceSeed{x:0>4}", .{seed}) catch unreachable;
}

pub fn write_module(writer: *Writer, name: []const u8, requests: u32, states: []const State) Error!void {
    assert(states.len > 0);
    try print(writer, "---- MODULE {s} ----\nEXTENDS H3DeadlinesTrace\n\nSeedTrace == <<\n", .{name});
    for (states, 0..) |*state, index| {
        try write_state(writer, requests, state);
        try writer.write_bytes(if (index + 1 < states.len) ",\n" else "\n");
    }
    try writer.write_bytes(">>\n\nSeedGoal == Len(SeedTrace)\n\n====\n");
}

pub fn write_config(writer: *Writer, plan: *const Plan, steps_max: u64) Error!void {
    const units = plan.units();
    try writer.write_bytes("\\* expect: violated\nSPECIFICATION TraceSpec\nCONSTANTS\n");
    try print(writer, "    N = {d}\n    HeadUnits = {d}\n    Content = {d}\n", .{ plan.requests, plan.head_units, plan.content_units });
    try print(writer, "    ResponseUnits = {d}\n", .{plan.response_units});
    // colibri owes credit once a window's fraction is read (`flow_credit_fraction`), so a window
    // that many times past what a stream, or every stream, carries never owes it.
    try print(writer, "    StreamWindow = {d}\n", .{credit_fraction * (units + 1)});
    try print(writer, "    ConnectionWindow = {d}\n", .{credit_fraction * (plan.requests * units + 1)});
    try print(writer, "    CongestionWindow = {d}\n", .{plan.requests * (plan.response_units + control_packets_per_request) + 1});
    try writer.write_bytes("    Fire = TRUE\n    ClientCancels = FALSE\n    RejectUnread = TRUE\n");
    try writer.write_bytes("    CloseAfterAck = TRUE\n    CloseAfterResets = TRUE\n");
    try writer.write_bytes("    UncountedAsked = TRUE\n    PauseForCredit = TRUE\n");
    try writer.write_bytes("    Trace <- SeedTrace\n    Goal <- SeedGoal\n");
    try print(writer, "    StepsMax = {d}\nCONSTRAINT Within\nINVARIANT Unfinished\nCHECK_DEADLOCK FALSE\n", .{steps_max});
}

fn write_state(writer: *Writer, requests: u32, state: *const State) Error!void {
    const n: usize = requests;
    try print(writer, "[opened |-> {d}, ", .{state.opened});
    try write_names(writer, "outcome", state_module.Outcome, state.outcome[0..n]);
    try print(writer, "goawayRead |-> {s}, closeRead |-> {s},\n", .{ boolean(state.goaway_read), boolean(state.close_read) });
    try print(writer, "taken |-> {d}, ", .{state.taken});
    try write_names(writer, "phase", state_module.Phase, state.phase[0..n]);
    try write_booleans(writer, "processed", state.processed[0..n]);
    try write_booleans(writer, "bodyWaits", state.body_waits[0..n]);
    try write_numbers(writer, "written", state.written[0..n]);
    try write_booleans(writer, "aborted", state.aborted[0..n]);
    try print(writer, "goawayId |-> {d}, firstRequestRead |-> {s}, ", .{ state.goaway_id, boolean(state.first_request_read) });
    try print(writer, "shuttingDown |-> {s}, timedOut |-> \"{t}\", closed |-> \"{t}\",\n", .{
        boolean(state.shutting_down), state.timed_out, state.closed,
    });
    try print(writer, "firstRequestRuns |-> {s}, idleRuns |-> {s}, ", .{ boolean(state.first_request_runs), boolean(state.idle_runs) });
    try write_booleans(writer, "headRuns", state.head_runs[0..n]);
    try write_booleans(writer, "bodyRuns", state.body_runs[0..n]);
    try print(writer, "sendRuns |-> {s}, drainRuns |-> {s}]", .{ boolean(state.send_runs), boolean(state.drain_runs) });
}

fn boolean(value: bool) []const u8 {
    return if (value) "TRUE" else "FALSE";
}

fn write_names(writer: *Writer, name: []const u8, comptime T: type, values: []const T) Error!void {
    try print(writer, "{s} |-> <<", .{name});
    for (values, 0..) |value, index| try print(writer, "{s}\"{t}\"", .{ separator(index), value });
    try writer.write_bytes(">>, ");
}

fn write_numbers(writer: *Writer, name: []const u8, values: []const u32) Error!void {
    try print(writer, "{s} |-> <<", .{name});
    for (values, 0..) |value, index| try print(writer, "{s}{d}", .{ separator(index), value });
    try writer.write_bytes(">>, ");
}

fn write_booleans(writer: *Writer, name: []const u8, values: []const bool) Error!void {
    try print(writer, "{s} |-> <<", .{name});
    for (values, 0..) |value, index| try print(writer, "{s}{s}", .{ separator(index), boolean(value) });
    try writer.write_bytes(">>, ");
}

fn separator(index: usize) []const u8 {
    return if (index == 0) "" else ", ";
}
