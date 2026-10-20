//! Writes one seed of the pool trace run as TLA+ (decision 105 as decision 125 extends it): a
//! module whose `SeedTrace` is the sequence of the model's states the run went through, and a TLC
//! configuration that checks it against `spec/tla/client_exchanges/ClientExchangesTrace.tla`. The
//! model names the TCP slots "tcp", "tcp2" and "tcp3". `tools/pool_trace.sh` writes them for many
//! seeds and runs TLC over them.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const quic = @import("quic");
const sim = @import("sim");
const state_module = @import("pool_trace_state.zig");
const plan_module = @import("pool_trace_plan.zig");

const limits = sim.constants.pool_trace;
const Writer = quic.core.Writer;
const State = state_module.State;
const Plan = plan_module.Plan;

pub const Error = quic.core.writer.Error;

/// The longest line one `print` writes.
const line_len_max: usize = 256;
/// The model's name of each TCP slot.
const slot_names = [_][]const u8{ "tcp", "tcp2", "tcp3" };

comptime {
    assert(slot_names.len == limits.slots_max);
}

fn print(writer: *Writer, comptime format: []const u8, arguments: anytype) Error!void {
    var line: [line_len_max]u8 = undefined;
    const text = std.fmt.bufPrint(&line, format, arguments) catch return error.NoSpaceLeft;
    try writer.write_bytes(text);
}

/// The module's name for `seed`, which its file and its configuration's file carry.
pub fn module_name(seed: u64, name: []u8) []const u8 {
    return std.fmt.bufPrint(name, "PoolTraceSeed{x:0>4}", .{seed}) catch unreachable;
}

pub fn write_module(writer: *Writer, name: []const u8, plan: *const Plan, states: []const State) Error!void {
    assert(states.len > 0);
    try print(writer, "---- MODULE {s} ----\nEXTENDS ClientExchangesTrace\n\nSeedTrace == <<\n", .{name});
    for (states, 0..) |*state, index| {
        try write_state(writer, plan, state);
        try writer.write_bytes(if (index + 1 < states.len) ",\n" else "\n");
    }
    try writer.write_bytes(">>\n\nSeedGoal == Len(SeedTrace)\n\n====\n");
}

/// The configuration: the model's constants as the seed's plan and its run set them. Every slot
/// may fail its handshake and break, and send what the model counts as a GOAWAY: an answer with
/// `Connection: close` (RFC 9112 §9.6).
pub fn write_config(writer: *Writer, plan: *const Plan, last: *const State) Error!void {
    try writer.write_bytes("\\* expect: violated\nSPECIFICATION TraceSpec\nCONSTANTS\n");
    var opens: u64 = 1;
    for (last.opens[0..plan.slots]) |slot_opens| opens = @max(opens, slot_opens);
    try print(writer, "    N = {d}\n    Opens = {d}\n    MovesMax = {d}\n", .{ plan.exchanges, opens, client.constants.moves_max });
    try writer.write_bytes("    QuicPolicy = \"never\"\n    TcpAllowed = TRUE\n");
    try write_slot_set(writer, "HandshakeFails", plan);
    try write_slot_set(writer, "Breaks", plan);
    try write_slot_set(writer, "Goaways", plan);
    // Each exchange's request may be read twice: once, and once more after it moved.
    const goaways = plan.closes() * (@as(u32, client.constants.moves_max) + 1);
    try print(writer, "    GoawaysMax = {d}\n    Refusals = {{}}\n    Resets = {{}}\n", .{goaways});
    try write_idempotent(writer, plan);
    try write_slot_set(writer, "TcpSlots", plan);
    // Decision 125: an h11 connection in a pool of several slots holds one exchange at a time.
    try writer.write_bytes("    TcpCapacity = 1\n");
    // h11 reads the rest of a cancelled exchange's response and drops it, as
    // `client.Connection.cancel` says.
    try writer.write_bytes("    TcpDrops = TRUE\n");
    try writer.write_bytes("    ReleaseOnFail = TRUE\n    CloseWhenDrained = TRUE\n    ReportWhenReleased = TRUE\n");
    try writer.write_bytes("    CancelReleases = TRUE\n    SentFailsClosed = TRUE\n    MoveRefused = TRUE\n");
    try writer.write_bytes("    RetireStale = TRUE\n    KeepAlive = TRUE\n    TakeAtHandshake = TRUE\n");
    try writer.write_bytes("    TcpWhenAllowed = TRUE\n    ResendIdempotent = TRUE\n    OneBudget = TRUE\n");
    try writer.write_bytes("    TakeWithinRoom = TRUE\n    TryOncePerWait = TRUE\n");
    try writer.write_bytes("    Trace <- SeedTrace\n    Goal <- SeedGoal\n");
    try print(writer, "    StepsMax = {d}\nCONSTRAINT Within\nINVARIANT Unfinished\nCHECK_DEADLOCK FALSE\n", .{limits.steps_max});
}

/// `name` set to the plan's TCP slots.
fn write_slot_set(writer: *Writer, name: []const u8, plan: *const Plan) Error!void {
    try print(writer, "    {s} = {{", .{name});
    for (slot_names[0..plan.slots], 0..) |slot_name, index| try print(writer, "{s}\"{s}\"", .{ separator(index), slot_name });
    try writer.write_bytes("}\n");
}

/// The model's `Idempotent`: the exchanges the plan makes GETs, counted from 1 (decision 124).
fn write_idempotent(writer: *Writer, plan: *const Plan) Error!void {
    try writer.write_bytes("    Idempotent = {");
    var written: usize = 0;
    for (0..plan.exchanges) |index| {
        if (!plan.idempotent(index)) continue;
        try print(writer, "{s}{d}", .{ separator(written), index + 1 });
        written += 1;
    }
    try writer.write_bytes("}\n");
}

fn boolean(value: bool) []const u8 {
    return if (value) "TRUE" else "FALSE";
}

fn write_state(writer: *Writer, plan: *const Plan, state: *const State) Error!void {
    const n: usize = plan.exchanges;
    try writer.write_bytes("[");
    try write_names(writer, "stage", state.stage[0..n]);
    try writer.write_bytes("carrier |-> <<");
    for (state.carrier[0..n], 0..) |carrier, index| {
        const carrier_name = if (carrier) |slot| slot_names[slot] else "none";
        try print(writer, "{s}\"{s}\"", .{ separator(index), carrier_name });
    }
    try writer.write_bytes(">>, holds |-> <<");
    for (0..n) |index| try print(writer, "{s}FALSE", .{separator(index)});
    try writer.write_bytes(">>, ");
    try write_names(writer, "outcome", state.outcome[0..n]);
    try write_numbers(writer, "moved", state.moved[0..n]);
    try write_booleans(writer, "seen", state.seen[0..n]);
    try write_numbers(writer, "processed", state.processed[0..n]);
    try write_booleans(writer, "drops", state.drops[0..n]);
    try writer.write_bytes("phase |-> [quic |-> \"none\"");
    for (slot_names[0..plan.slots], state.phase[0..plan.slots]) |slot_name, phase| try print(writer, ", {s} |-> \"{t}\"", .{ slot_name, phase });
    try writer.write_bytes("], opens |-> [quic |-> 0");
    for (slot_names[0..plan.slots], state.opens[0..plan.slots]) |slot_name, opens| try print(writer, ", {s} |-> {d}", .{ slot_name, opens });
    try writer.write_bytes("], tried |-> {");
    var written: usize = 0;
    for (slot_names[0..plan.slots], state.tried[0..plan.slots]) |slot_name, tried| {
        if (!tried) continue;
        try print(writer, "{s}\"{s}\"", .{ separator(written), slot_name });
        written += 1;
    }
    try print(writer, "}}, fallback |-> FALSE, learned |-> FALSE, shut |-> {s}, stale |-> FALSE]", .{boolean(state.shut)});
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
