//! Writes one seed of the h3 trace run as TLA+ (https://github.com/c4milo/colibri/issues/58): a
//! module whose `SeedTrace` is the sequence of the model's states the run went through, and a TLC
//! configuration that checks it against `spec/tla/h3_connection/H3ConnectionTrace.tla` with the
//! plan's constants. `tools/h3_trace.sh` writes them for many seeds and runs TLC over them.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3_trace_state = @import("h3_trace_state.zig");

const Writer = quic.core.Writer;
const State = h3_trace_state.State;
const Scope = h3_trace_state.Scope;

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
    return std.fmt.bufPrint(name, "H3TraceSeed{x:0>4}", .{seed}) catch unreachable;
}

pub fn write_module(writer: *Writer, name: []const u8, scope: Scope, states: []const State) Error!void {
    assert(states.len > 0);
    try print(writer, "---- MODULE {s} ----\nEXTENDS H3ConnectionTrace\n\nSeedTrace == <<\n", .{name});
    for (states, 0..) |*state, index| {
        try write_state(writer, scope, state);
        try writer.write_bytes(if (index + 1 < states.len) ",\n" else "\n");
    }
    try writer.write_bytes(">>\n\nSeedGoal == Len(SeedTrace)\n\n====\n");
}

pub fn write_config(writer: *Writer, scope: Scope, steps_max: u64) Error!void {
    try writer.write_bytes("\\* expect: violated\nSPECIFICATION TraceSpec\nCONSTANTS\n");
    try print(writer, "    N = {d}\n    Content = {d}\n    MaxInserts = {d}\n", .{ scope.requests, scope.content, scope.inserts_max });
    try print(writer, "    BlockedStreams = {d}\n    ConnectionWindow = {d}\n", .{ scope.blocked_streams, scope.connection_window() });
    try print(writer, "    EncoderWindow = {d}\n    MaxGoaways = {d}\n", .{ scope.encoder_window(), scope.goaways });
    try print(writer, "    ClientCancels = TRUE\n    DecoderTable = {s}\n", .{boolean(scope.decoder_table)});
    try writer.write_bytes("    RejectAboveGoaway = TRUE\n    GoawayNamesUntaken = TRUE\n    GoawayNeverRises = TRUE\n");
    try writer.write_bytes("    KeepControlOpen = TRUE\n    SilentAfterCancel = TRUE\n    EncoderFirst = TRUE\n");
    try writer.write_bytes("    InsertNeedsCredit = TRUE\n    Trace <- SeedTrace\n    Goal <- SeedGoal\n");
    try print(writer, "    StepsMax = {d}\nCONSTRAINT Within\nINVARIANT Unfinished\nCHECK_DEADLOCK FALSE\n", .{steps_max});
}

fn boolean(value: bool) []const u8 {
    return if (value) "TRUE" else "FALSE";
}

fn write_state(writer: *Writer, scope: Scope, state: *const State) Error!void {
    const n: usize = @intCast(scope.requests);
    try print(writer, "[opened |-> {d}, inserted |-> {d}, known |-> {d}, ", .{ state.opened, state.inserted, state.known });
    try write_numbers(writer, "ric", state.ric[0..n]);
    try write_numbers(writer, "outstanding", state.outstanding[0..n]);
    try print(writer, "encoderQueued |-> {d}, ", .{state.encoder_queued});
    try write_numbers(writer, "requestQueued", state.request_queued[0..n]);
    try print(writer, "encoderSent |-> {d}, ", .{state.encoder_sent});
    try write_numbers(writer, "requestSent", state.request_sent[0..n]);
    try print(writer, "connectionLimit |-> {d}, encoderLimit |-> {d}, ", .{ state.connection_limit, state.encoder_limit });
    try print(writer, "settingsReceived |-> {s}, goawayReceived |-> {d}, ", .{ boolean(state.settings_received), state.goaway_received });
    try write_names(writer, "outcome", state.outcome[0..n]);
    try write_names(writer, "reset", state.reset[0..n]);
    try print(writer, "taken |-> {d}, ", .{state.taken});
    try write_names(writer, "phase", state.phase[0..n]);
    try write_booleans(writer, "processed", state.processed[0..n]);
    try write_numbers(writer, "consumed", state.consumed[0..n]);
    try print(writer, "encoderConsumed |-> {d}, decoderKnown |-> {d}, ", .{ state.encoder_consumed, state.decoder_known });
    try write_instructions(writer, state.decoder_stream[0..state.decoder_stream_len]);
    try write_names(writer, "toClient", state.to_client[0..n]);
    try print(writer, "goawaySent |-> {d}, goawayCount |-> {d}, ", .{ state.goaway_sent, state.goaway_count });
    try write_control(writer, state.control[0..state.control_len]);
    try writer.write_bytes("controlEnded |-> FALSE, broken |-> \"none\"]");
}

fn write_numbers(writer: *Writer, field: []const u8, values: []const u64) Error!void {
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

fn write_instructions(writer: *Writer, instructions: []const h3_trace_state.Instruction) Error!void {
    try writer.write_bytes("decoderStream |-> <<");
    for (instructions, 0..) |held, index| {
        try print(writer, "{s}[kind |-> \"{t}\", stream |-> {d}, count |-> {d}]", .{ separator(index), held.kind, held.stream, held.count });
    }
    try writer.write_bytes(">>, ");
}

fn write_control(writer: *Writer, frames: []const h3_trace_state.ControlFrame) Error!void {
    try writer.write_bytes("control |-> <<");
    for (frames, 0..) |frame, index| {
        const kind = if (frame.goaway) "goaway" else "settings";
        try print(writer, "{s}[type |-> \"{s}\", id |-> {d}]", .{ separator(index), kind, frame.id });
    }
    try writer.write_bytes(">>, ");
}

fn separator(index: usize) []const u8 {
    return if (index == 0) "" else ", ";
}
