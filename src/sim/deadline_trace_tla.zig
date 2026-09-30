//! Writes one seed of the deadline trace run as TLA+ (https://github.com/c4milo/colibri/issues/86):
//! a module whose `SeedTrace` is the sequence of the model's states the run went through, and a TLC
//! configuration that checks it against `spec/tla/server_deadlines/ServerDeadlinesTrace.tla` with
//! the seed's constants. The model's constants the plan does not draw are colibri's own, read from
//! the run's endpoints and colibri's limits. `tools/deadline_trace.sh` writes them for many seeds
//! and runs TLC over them.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const server = @import("server");
const plan_module = @import("deadline_trace_plan.zig");
const world_module = @import("deadline_trace_world.zig");
const state_module = @import("deadline_trace_state.zig");

const Writer = h2.core.Writer;
const Plan = plan_module.Plan;
const World = world_module.World;
const State = state_module.State;
const Side = state_module.Side;
const Frame = state_module.Frame;
const Part = state_module.Part;

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
    return std.fmt.bufPrint(name, "DeadlineTraceSeed{x:0>4}", .{seed}) catch unreachable;
}

pub fn write_module(writer: *Writer, name: []const u8, streams: u32, states: []const State) Error!void {
    assert(states.len > 0);
    try print(writer, "---- MODULE {s} ----\nEXTENDS ServerDeadlinesTrace\n\nSeedTrace == <<\n", .{name});
    for (states, 0..) |*state, index| {
        try write_state(writer, streams, state);
        try writer.write_bytes(if (index + 1 < states.len) ",\n" else "\n");
    }
    try writer.write_bytes(">>\n\nSeedGoal == Len(SeedTrace)\n\n====\n");
}

pub fn write_config(writer: *Writer, plan: *const Plan, world: *const World, steps_max: u64) Error!void {
    try writer.write_bytes("\\* expect: violated\nSPECIFICATION TraceSpec\nCONSTANTS\n");
    try print(writer, "    StreamCount = {d}\n    RequestBody = {d}\n    ResponseBody = {d}\n", .{ plan.streams, plan.request_body, plan.response_body });
    try print(writer, "    ProduceStep = {d}\n    ConnectionWindow = {d}\n", .{ plan.produce_step, h2.constants.initial_window_size_initial });
    try print(writer, "    LocalWindow = {d}\n    LocalThreshold = {d}\n", .{ world.server.session.h2.local.initial_window_size, h2.constants.window_update_threshold });
    try print(writer, "    PeerWindow = {d}\n    PeerThreshold = {d}\n", .{ world.client.local.initial_window_size, h2.constants.window_update_threshold });
    try print(writer, "    Floor = {d}\n    FrameMax = {d}\n", .{ world.server_config.data_frame_len_min, h2.constants.max_frame_size_initial });
    try print(writer, "    HeaderLen = {d}\n    SettingsLen = {d}\n", .{ h2.constants.frame_header_len, world.settings_len });
    try print(writer, "    UpdateLen = {d}\n    PrefaceLen = {d}\n", .{ h2.constants.window_update_len, world.preface_len });
    try print(writer, "    RequestHeadLen = {d}\n    ResponseHeadLen = {d}\n", .{ world.request_head_len orelse 0, world.response_head_len orelse 0 });
    try print(writer, "    OutputLen = {d}\n    ChannelLen = {d}\n", .{ server.constants.output_len, plan.channel_len });
    try print(writer, "    Pipelining = {s}\n    MaximalUploads = TRUE\n", .{boolean(plan.pipelining)});
    try writer.write_bytes("    IdleAfterOutput = TRUE\n    SettingsPause = TRUE\n    FloorOnlyAbove = TRUE\n");
    try writer.write_bytes("    FloorAfterSmall = TRUE\n    BodyPauseForUpdate = TRUE\n");
    try writer.write_bytes("    Trace <- SeedTrace\n    Goal <- SeedGoal\n");
    try print(writer, "    StepsMax = {d}\nCONSTRAINT Within\nINVARIANT Unfinished\nCHECK_DEADLOCK FALSE\n", .{steps_max});
}

fn boolean(value: bool) []const u8 {
    return if (value) "TRUE" else "FALSE";
}

fn write_state(writer: *Writer, streams: u32, state: *const State) Error!void {
    const n: usize = streams;
    try writer.write_bytes("[");
    try write_parts(writer, "reqRead", state.req_read[0..n]);
    try write_parts(writer, "resp", state.resp[0..n]);
    try write_numbers(writer, "respWritten", u32, state.resp_written[0..n]);
    try write_numbers(writer, "produced", u32, state.produced[0..n]);
    try write_side(writer, "sendWindow", "sendConnection", "released", "releasedConnection", &state.colibri, n);
    try write_owed(writer, "acksOwed", "connectionOwed", "streamOwed", &state.colibri);
    try write_frames(writer, "out", state.out.slice());
    try print(writer, "firstRequestRead |-> {s}, idleStarted |-> {s}, ", .{ boolean(state.first_request_read), boolean(state.idle_started) });
    try print(writer, "settingsAcked |-> {s}, smallIncrement |-> {s},\n", .{ boolean(state.settings_acked), boolean(state.small_increment) });
    try write_frames(writer, "toClient", state.to_client.slice());
    try write_frames(writer, "toServer", state.to_server.slice());
    try write_parts(writer, "cliReq", state.cli_req[0..n]);
    try write_numbers(writer, "cliSent", u32, state.cli_sent[0..n]);
    try write_parts(writer, "cliResp", state.cli_resp[0..n]);
    try write_side(writer, "cliWindow", "cliConnection", "cliReleased", "cliReleasedConnection", &state.client, n);
    try write_owed(writer, "cliAcksOwed", "cliConnectionOwed", "cliStreamOwed", &state.client);
    try print(writer, "arrived |-> {d}, handedOut |-> {d}, settingsRuns |-> {s},\n", .{ state.arrived, state.handed_out, boolean(state.settings_runs) });
    try write_booleans(writer, "bodyRuns", state.body_runs[0..n]);
    try writer.write_bytes("sendRuns |-> ");
    try write_boolean_sequence(writer, state.send_runs[0..n]);
    try writer.write_bytes("]");
}

fn write_side(writer: *Writer, window: []const u8, connection: []const u8, released: []const u8, released_connection: []const u8, side: *const Side, n: usize) Error!void {
    try write_numbers(writer, window, i64, side.window[0..n]);
    try print(writer, "{s} |-> {d}, ", .{ connection, side.connection });
    try write_numbers(writer, released, u32, side.released[0..n]);
    try print(writer, "{s} |-> {d},\n", .{ released_connection, side.released_connection });
}

fn write_owed(writer: *Writer, acks: []const u8, connection: []const u8, streams: []const u8, side: *const Side) Error!void {
    try print(writer, "{s} |-> {d}, {s} |-> {d}, {s} |-> <<", .{ acks, side.acks_owed, connection, side.connection_owed, streams });
    for (side.stream_owed.slice(), 0..) |owed, index| {
        try print(writer, "{s}<<{d}, {d}>>", .{ separator(index), owed.stream, owed.increment });
    }
    try writer.write_bytes(">>,\n");
}

fn write_frames(writer: *Writer, name: []const u8, frames: []const Frame) Error!void {
    try print(writer, "{s} |-> <<", .{name});
    for (frames, 0..) |frame, index| {
        try print(writer, "{s}[type |-> \"{s}\", stream |-> {d}, len |-> {d}, end |-> {s}, value |-> {d}]", .{
            separator(index), type_name(frame.kind), frame.stream, frame.len, boolean(frame.end), frame.value,
        });
    }
    try writer.write_bytes(">>,\n");
}

fn type_name(kind: state_module.Kind) []const u8 {
    return switch (kind) {
        .preface => "PREFACE",
        .settings => "SETTINGS",
        .settings_ack => "SETTINGS_ACK",
        .headers => "HEADERS",
        .data => "DATA",
        .window_update => "WINDOW_UPDATE",
    };
}

fn write_parts(writer: *Writer, name: []const u8, parts: []const Part) Error!void {
    try print(writer, "{s} |-> <<", .{name});
    for (parts, 0..) |part, index| try print(writer, "{s}\"{t}\"", .{ separator(index), part });
    try writer.write_bytes(">>, ");
}

fn write_numbers(writer: *Writer, name: []const u8, comptime T: type, numbers: []const T) Error!void {
    try print(writer, "{s} |-> <<", .{name});
    for (numbers, 0..) |number, index| try print(writer, "{s}{d}", .{ separator(index), number });
    try writer.write_bytes(">>, ");
}

fn write_booleans(writer: *Writer, name: []const u8, values: []const bool) Error!void {
    try print(writer, "{s} |-> ", .{name});
    try write_boolean_sequence(writer, values);
    try writer.write_bytes(", ");
}

fn write_boolean_sequence(writer: *Writer, values: []const bool) Error!void {
    try writer.write_bytes("<<");
    for (values, 0..) |value, index| try print(writer, "{s}{s}", .{ separator(index), boolean(value) });
    try writer.write_bytes(">>");
}

fn separator(index: usize) []const u8 {
    return if (index == 0) "" else ", ";
}
