//! Writes one seed of the h2 trace run as TLA+ (https://github.com/c4milo/colibri/issues/75): a
//! module whose `SeedTrace` is the sequence of the model's states the run went through, and a TLC
//! configuration that checks it against `spec/tla/h2_connection/H2ConnectionTrace.tla` with the
//! plan's constants. `tools/h2_trace.sh` writes them for many seeds and runs TLC over them.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const h2_trace_state = @import("h2_trace_state.zig");
const h2_trace_plan = @import("h2_trace_plan.zig");

const Writer = h2.core.Writer;
const State = h2_trace_state.State;
const Frame = h2_trace_state.Frame;
const Plan = h2_trace_plan.Plan;

pub const Error = h2.core.writer.Error;

/// The longest line one `print` writes.
const line_len_max: usize = 256;

fn print(writer: *Writer, comptime format: []const u8, arguments: anytype) Error!void {
    var line: [line_len_max]u8 = undefined;
    const text = std.fmt.bufPrint(&line, format, arguments) catch return error.NoSpaceLeft;
    try writer.write_bytes(text);
}

/// The module's name for `seed`, which its file and its configuration's file carry.
pub fn module_name(seed: u64, name: []u8) []const u8 {
    return std.fmt.bufPrint(name, "H2TraceSeed{x:0>4}", .{seed}) catch unreachable;
}

pub fn write_module(writer: *Writer, name: []const u8, plan: *const Plan, states: []const State) Error!void {
    assert(states.len > 0);
    try print(writer, "---- MODULE {s} ----\nEXTENDS H2ConnectionTrace\n\nSeedTrace == <<\n", .{name});
    for (states, 0..) |*state, index| {
        try write_state(writer, plan.streams, state);
        try writer.write_bytes(if (index + 1 < states.len) ",\n" else "\n");
    }
    try writer.write_bytes(">>\n\nSeedGoal == Len(SeedTrace)\n\n====\n");
}

pub fn write_config(writer: *Writer, plan: *const Plan, steps_max: u64) Error!void {
    try writer.write_bytes("\\* expect: violated\nSPECIFICATION TraceSpec\nCONSTANTS\n");
    try print(writer, "    N = {d}\n    Content = {d}\n    Interims = {d}\n", .{ plan.streams, plan.content, plan.interims });
    try print(writer, "    MaxGoaways = {d}\n    Resets = {s}\n", .{ plan.goaways, boolean(plan.resets) });
    try writer.write_bytes("    SendInState = TRUE\n    DataAfterHead = TRUE\n    OneFinalHead = TRUE\n");
    try writer.write_bytes("    DiscardAfterReset = TRUE\n    IgnoreAboveGoaway = TRUE\n    NoStreamAfterGoaway = TRUE\n");
    try writer.write_bytes("    PrefaceFirst = TRUE\n");
    try writer.write_bytes("    Trace <- SeedTrace\n    Goal <- SeedGoal\n");
    try print(writer, "    StepsMax = {d}\nCONSTRAINT Within\nINVARIANT Unfinished\nCHECK_DEADLOCK FALSE\n", .{steps_max});
}

fn boolean(value: bool) []const u8 {
    return if (value) "TRUE" else "FALSE";
}

fn write_state(writer: *Writer, streams: u32, state: *const State) Error!void {
    const n: usize = streams;
    try writer.write_bytes("[");
    try write_names(writer, "clientState", state.client_state[0..n]);
    try write_names(writer, "clientClosed", state.client_closed[0..n]);
    try write_names(writer, "serverState", state.server_state[0..n]);
    try write_names(writer, "serverClosed", state.server_closed[0..n]);
    try write_names(writer, "request", state.request[0..n]);
    try write_numbers(writer, "requestData", state.request_data[0..n]);
    try write_names(writer, "response", state.response[0..n]);
    try write_numbers(writer, "responseInterims", state.response_interims[0..n]);
    try write_numbers(writer, "responseData", state.response_data[0..n]);
    try write_names(writer, "requestRead", state.request_read[0..n]);
    try write_names(writer, "responseRead", state.response_read[0..n]);
    try write_frames(writer, "toServer", state.to_server[0..state.to_server_len]);
    try write_frames(writer, "toClient", state.to_client[0..state.to_client_len]);
    try print(writer, "goawaySent |-> {d}, goawayCount |-> {d}, goawayRead |-> {d}, ", .{ state.goaway_sent, state.goaway_count, state.goaway_read });
    try print(writer, "malformed |-> {s}, broken |-> {s}, lateOpen |-> {s}, ", .{ boolean(state.malformed), boolean(state.broken), boolean(state.late_open) });
    try print(writer, "clientPreface |-> {s}, serverPreface |-> {s}, ", .{ boolean(state.client_preface), boolean(state.server_preface) });
    try print(writer, "clientReadPreface |-> {s}, serverReadPreface |-> {s}]", .{ boolean(state.client_read_preface), boolean(state.server_read_preface) });
}

fn write_numbers(writer: *Writer, field: []const u8, values: []const u32) Error!void {
    try print(writer, "{s} |-> <<", .{field});
    for (values, 0..) |value, index| try print(writer, "{s}{d}", .{ separator(index), value });
    try writer.write_bytes(">>, ");
}

/// A sequence of enum values, each written as the model's string, which is the value's name.
fn write_names(writer: *Writer, field: []const u8, values: anytype) Error!void {
    try print(writer, "{s} |-> <<", .{field});
    for (values, 0..) |value, index| try print(writer, "{s}\"{t}\"", .{ separator(index), value });
    try writer.write_bytes(">>, ");
}

fn write_frames(writer: *Writer, field: []const u8, frames: []const Frame) Error!void {
    try print(writer, "{s} |-> <<", .{field});
    for (frames, 0..) |frame, index| {
        try print(writer, "{s}[stream |-> {d}, kind |-> \"{t}\", end |-> {s}, last |-> {d}]", .{
            separator(index), frame.stream, frame.kind, boolean(frame.end), frame.last,
        });
    }
    try writer.write_bytes(">>, ");
}

fn separator(index: usize) []const u8 {
    return if (index == 0) "" else ", ";
}
