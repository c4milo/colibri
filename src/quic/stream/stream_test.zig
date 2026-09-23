//! The stream state machines' tests (RFC 9000 §3.1, §3.2, §4.5). Each machine's transitions are
//! checked by enumerating every state and event pair, which for a finite machine is the whole
//! function rather than a sample of it; design §8 step 9 records why that is done here instead
//! of in a model checker.
const std = @import("std");
const stream_send = @import("stream_send.zig");
const stream_recv = @import("stream_recv.zig");

const Sending = stream_send.Sending;
const Receiving = stream_recv.Receiving;
const testing = std.testing;

/// Drives a sending part into `state`, however it has to be reached. Test-only.
fn sending_in(state: stream_send.State) Sending {
    var sending = Sending.init();
    switch (state) {
        .ready => {},
        .send => _ = sending.on(.sent_data),
        .data_sent => _ = sending.on(.sent_fin),
        .data_recvd => {
            _ = sending.on(.sent_fin);
            _ = sending.on(.all_data_acknowledged);
        },
        .reset_sent => _ = sending.on(.sent_reset),
        .reset_recvd => {
            _ = sending.on(.sent_reset);
            _ = sending.on(.reset_acknowledged);
        },
    }
    std.debug.assert(sending.state == state);
    return sending;
}

/// Drives a receiving part into `state`. Test-only.
fn receiving_in(state: stream_recv.State) Receiving {
    var receiving = Receiving.init();
    switch (state) {
        .recv => {},
        .size_known => _ = receiving.on(.received_fin),
        .data_recvd => {
            _ = receiving.on(.received_fin);
            _ = receiving.on(.all_data_received);
        },
        .data_read => {
            _ = receiving.on(.received_fin);
            _ = receiving.on(.all_data_received);
            _ = receiving.on(.application_read_all);
        },
        .reset_recvd => _ = receiving.on(.received_reset),
        .reset_read => {
            _ = receiving.on(.received_reset);
            _ = receiving.on(.application_read_reset);
        },
    }
    std.debug.assert(receiving.state == state);
    return receiving;
}

/// One row: the state an event is raised in, and what it leads to. A `to` of null is the event
/// the state does not admit. Test-only.
fn Row(comptime State: type, comptime Event: type) type {
    return struct { from: State, event: Event, to: ?State };
}

/// Checks that `table` holds every state and event pair exactly once. Test-only.
fn expect_whole_table(comptime State: type, comptime Event: type, table: []const Row(State, Event)) !void {
    const states = @typeInfo(State).@"enum".fields.len;
    const events = @typeInfo(Event).@"enum".fields.len;
    try testing.expectEqual(states * events, table.len);
    for (table, 0..) |row, index| {
        for (table[index + 1 ..]) |other| {
            try testing.expect(row.from != other.from or row.event != other.event);
        }
    }
}

test "§3.1: Figure 2's transitions, every state and event pair" {
    const SendRow = Row(stream_send.State, stream_send.Event);
    const table = [_]SendRow{
        // RFC 9000 §3.1: sending a STREAM or STREAM_DATA_BLOCKED frame enters "Send".
        .{ .from = .ready, .event = .sent_data, .to = .send },
        .{ .from = .ready, .event = .sent_fin, .to = .data_sent },
        .{ .from = .ready, .event = .all_data_acknowledged, .to = null },
        .{ .from = .ready, .event = .sent_reset, .to = .reset_sent },
        .{ .from = .ready, .event = .reset_acknowledged, .to = null },

        .{ .from = .send, .event = .sent_data, .to = .send },
        .{ .from = .send, .event = .sent_fin, .to = .data_sent },
        .{ .from = .send, .event = .all_data_acknowledged, .to = null },
        .{ .from = .send, .event = .sent_reset, .to = .reset_sent },
        .{ .from = .send, .event = .reset_acknowledged, .to = null },

        // RFC 9000 §3.1: after the FIN the part only retransmits, so no new data goes out.
        .{ .from = .data_sent, .event = .sent_data, .to = null },
        .{ .from = .data_sent, .event = .sent_fin, .to = null },
        .{ .from = .data_sent, .event = .all_data_acknowledged, .to = .data_recvd },
        .{ .from = .data_sent, .event = .sent_reset, .to = .reset_sent },
        .{ .from = .data_sent, .event = .reset_acknowledged, .to = null },

        // "Data Recvd" is terminal.
        .{ .from = .data_recvd, .event = .sent_data, .to = null },
        .{ .from = .data_recvd, .event = .sent_fin, .to = null },
        .{ .from = .data_recvd, .event = .all_data_acknowledged, .to = null },
        .{ .from = .data_recvd, .event = .sent_reset, .to = null },
        .{ .from = .data_recvd, .event = .reset_acknowledged, .to = null },

        .{ .from = .reset_sent, .event = .sent_data, .to = null },
        .{ .from = .reset_sent, .event = .sent_fin, .to = null },
        .{ .from = .reset_sent, .event = .all_data_acknowledged, .to = null },
        .{ .from = .reset_sent, .event = .sent_reset, .to = null },
        .{ .from = .reset_sent, .event = .reset_acknowledged, .to = .reset_recvd },

        // "Reset Recvd" is terminal.
        .{ .from = .reset_recvd, .event = .sent_data, .to = null },
        .{ .from = .reset_recvd, .event = .sent_fin, .to = null },
        .{ .from = .reset_recvd, .event = .all_data_acknowledged, .to = null },
        .{ .from = .reset_recvd, .event = .sent_reset, .to = null },
        .{ .from = .reset_recvd, .event = .reset_acknowledged, .to = null },
    };
    try expect_whole_table(stream_send.State, stream_send.Event, &table);
    for (table) |row| {
        var sending = sending_in(row.from);
        const taken = sending.on(row.event) == .taken;
        try testing.expectEqual(row.to != null, taken);
        try testing.expectEqual(row.to orelse row.from, sending.state);
        // A terminal state is left by nothing.
        if (row.from.is_terminal()) try testing.expectEqual(row.from, sending.state);
    }
}

test "§3.2: Figure 3's transitions, every state and event pair" {
    const RecvRow = Row(stream_recv.State, stream_recv.Event);
    const table = [_]RecvRow{
        .{ .from = .recv, .event = .received_data, .to = .recv },
        .{ .from = .recv, .event = .received_fin, .to = .size_known },
        .{ .from = .recv, .event = .all_data_received, .to = null },
        .{ .from = .recv, .event = .application_read_all, .to = null },
        .{ .from = .recv, .event = .received_reset, .to = .reset_recvd },
        .{ .from = .recv, .event = .application_read_reset, .to = null },

        // RFC 9000 §3.2: in "Size Known" only retransmissions arrive, which change no state.
        .{ .from = .size_known, .event = .received_data, .to = .size_known },
        .{ .from = .size_known, .event = .received_fin, .to = .size_known },
        .{ .from = .size_known, .event = .all_data_received, .to = .data_recvd },
        .{ .from = .size_known, .event = .application_read_all, .to = null },
        .{ .from = .size_known, .event = .received_reset, .to = .reset_recvd },
        .{ .from = .size_known, .event = .application_read_reset, .to = null },

        .{ .from = .data_recvd, .event = .received_data, .to = null },
        .{ .from = .data_recvd, .event = .received_fin, .to = null },
        .{ .from = .data_recvd, .event = .all_data_received, .to = null },
        .{ .from = .data_recvd, .event = .application_read_all, .to = .data_read },
        // RFC 9000 §3.2, Figure 3: a RESET_STREAM here is the optional edge.
        .{ .from = .data_recvd, .event = .received_reset, .to = .reset_recvd },
        .{ .from = .data_recvd, .event = .application_read_reset, .to = null },

        // "Data Read" is terminal.
        .{ .from = .data_read, .event = .received_data, .to = null },
        .{ .from = .data_read, .event = .received_fin, .to = null },
        .{ .from = .data_read, .event = .all_data_received, .to = null },
        .{ .from = .data_read, .event = .application_read_all, .to = null },
        .{ .from = .data_read, .event = .received_reset, .to = null },
        .{ .from = .data_read, .event = .application_read_reset, .to = null },

        .{ .from = .reset_recvd, .event = .received_data, .to = null },
        .{ .from = .reset_recvd, .event = .received_fin, .to = null },
        .{ .from = .reset_recvd, .event = .all_data_received, .to = null },
        .{ .from = .reset_recvd, .event = .application_read_all, .to = null },
        .{ .from = .reset_recvd, .event = .received_reset, .to = null },
        .{ .from = .reset_recvd, .event = .application_read_reset, .to = .reset_read },

        // "Reset Read" is terminal.
        .{ .from = .reset_read, .event = .received_data, .to = null },
        .{ .from = .reset_read, .event = .received_fin, .to = null },
        .{ .from = .reset_read, .event = .all_data_received, .to = null },
        .{ .from = .reset_read, .event = .application_read_all, .to = null },
        .{ .from = .reset_read, .event = .received_reset, .to = null },
        .{ .from = .reset_read, .event = .application_read_reset, .to = null },
    };
    try expect_whole_table(stream_recv.State, stream_recv.Event, &table);
    for (table) |row| {
        var receiving = receiving_in(row.from);
        const taken = receiving.on(row.event) == .taken;
        try testing.expectEqual(row.to != null, taken);
        try testing.expectEqual(row.to orelse row.from, receiving.state);
        if (row.from.is_terminal()) try testing.expectEqual(row.from, receiving.state);
    }
}

test "§3.1: data flows and flow control applies until the FIN goes out" {
    var sending = Sending.init();
    try testing.expect(sending.may_send_data() and sending.observes_flow_control());
    _ = sending.on(.sent_data);
    try testing.expect(sending.may_send_data() and sending.observes_flow_control());
    // RFC 9000 §3.1: in "Data Sent" the endpoint need not check the limits, because the final
    // size is fixed and only retransmissions remain.
    _ = sending.on(.sent_fin);
    try testing.expect(!sending.may_send_data() and !sending.observes_flow_control());
    _ = sending.on(.all_data_acknowledged);
    try testing.expect(!sending.may_send_data());
    // A reset stream sends nothing either.
    var reset = Sending.init();
    _ = reset.on(.sent_reset);
    try testing.expect(!reset.may_send_data() and !reset.observes_flow_control());
}

test "§3.2: credit is offered only while the size is unknown" {
    var receiving = Receiving.init();
    try testing.expect(receiving.offers_credit());
    _ = receiving.on(.received_data);
    try testing.expect(receiving.offers_credit());
    // RFC 9000 §3.2: in "Size Known" no more MAX_STREAM_DATA frames are needed.
    _ = receiving.on(.received_fin);
    try testing.expect(!receiving.offers_credit());
}

test "§4.5: a final size cannot change, and data may not reach past it" {
    var receiving = Receiving.init();
    try receiving.on_stream_frame(0, 10, false);
    try testing.expectEqual(null, receiving.final_size);
    try receiving.on_stream_frame(10, 5, true);
    try testing.expectEqual(15, receiving.final_size.?);
    // A retransmission of the same FIN says what is already known.
    try receiving.on_stream_frame(10, 5, true);
    // RFC 9000 §4.5: a different final size is an error.
    try testing.expectError(error.FinalSizeChanged, receiving.on_stream_frame(10, 6, true));
    try testing.expectError(error.FinalSizeChanged, receiving.on_reset(14));
    // Data at or beyond the final size is an error; data below it is a retransmission.
    try testing.expectError(error.DataBeyondFinalSize, receiving.on_stream_frame(14, 2, false));
    try receiving.on_stream_frame(0, 15, false);
    // RFC 9000 §20.1: both are FINAL_SIZE_ERROR, which is 0x06.
    try testing.expectEqual(0x06, stream_recv.connection_error_code(error.FinalSizeChanged));
    try testing.expectEqual(0x06, stream_recv.connection_error_code(error.DataBeyondFinalSize));
}

test "§4.5: what already arrived is remembered, whatever order it arrived in" {
    var receiving = Receiving.init();
    // The later octets arrive first, so a frame that reaches less far must not lower the mark.
    try receiving.on_stream_frame(10, 5, false);
    try receiving.on_stream_frame(0, 5, false);
    try testing.expectEqual(15, receiving.highest_offset);
    // RFC 9000 §4.5: a final size below what arrived is refused, by either frame.
    try testing.expectError(error.FinalSizeChanged, receiving.on_reset(10));
    try testing.expectError(error.FinalSizeChanged, receiving.on_stream_frame(0, 10, true));
    try receiving.on_reset(15);
}

test "§4.5: a final size below what already arrived is refused, by either frame" {
    var receiving = Receiving.init();
    try receiving.on_stream_frame(0, 20, false);
    // RFC 9000 §4.5: the final size accounts for every octet sent, so it cannot be below what
    // this endpoint has already taken.
    try testing.expectError(error.FinalSizeChanged, receiving.on_stream_frame(0, 19, true));
    try testing.expectError(error.FinalSizeChanged, receiving.on_reset(19));
    // Exactly what arrived is admitted, from either frame.
    try receiving.on_reset(20);
    try testing.expectEqual(20, receiving.final_size.?);

    var by_reset = Receiving.init();
    try by_reset.on_reset(7);
    try testing.expectEqual(7, by_reset.final_size.?);
    try testing.expectError(error.FinalSizeChanged, by_reset.on_stream_frame(0, 8, true));
}

const constants = @import("../constants.zig");
const stream_table = @import("stream_table.zig");
const stream_lost = @import("stream_lost.zig");

/// A table whose streams this endpoint opens, as a client. Test-only.
var test_streams: stream_table.Streams = undefined;
const test_stream_limit: u64 = 4;
const test_stream_limits: [constants.stream_directionalities]u64 = @splat(test_stream_limit);
/// A stream's octets, sent in two frames of half each. Test-only.
const test_body_len: u64 = 1_000;
const test_half_len: u64 = 500;

/// Opens a stream and sends its body in two frames, the FIN with the second, as `send` would.
fn sent_stream() !*stream_table.Stream {
    test_streams.init(.client, test_stream_limits, test_stream_limits);
    const stream = try test_streams.open_local(.bidirectional);
    try stream.outgoing.supply(test_body_len, true);
    _ = stream.sending.on(.sent_data);
    stream.outgoing.on_framed(test_half_len, false);
    _ = stream.sending.on(.sent_fin);
    stream.outgoing.on_framed(test_half_len, true);
    return stream;
}

fn first_half(stream: *const stream_table.Stream) stream_lost.Range {
    return .{ .stream_id = stream.id, .offset = 0, .len = test_half_len, .fin = false };
}

fn second_half(stream: *const stream_table.Stream) stream_lost.Range {
    return .{ .stream_id = stream.id, .offset = test_half_len, .len = test_half_len, .fin = true };
}

test "§3.1: the range that completes a stream's acknowledgment moves it to Data Recvd" {
    const stream = try sent_stream();
    // The FIN's range arrives first, which leaves the first half outstanding.
    try testing.expect(!test_streams.on_range_acknowledged(second_half(stream)));
    try testing.expectEqual(.data_sent, stream.sending.state);
    try testing.expect(test_streams.on_range_acknowledged(first_half(stream)));
    try testing.expectEqual(.data_recvd, stream.sending.state);
}

test "§3.1: a stream reset after its FIN stays in Reset Sent when its data is acknowledged" {
    const stream = try sent_stream();
    _ = stream.sending.on(.sent_reset);
    try testing.expect(!test_streams.on_range_acknowledged(first_half(stream)));
    try testing.expect(!test_streams.on_range_acknowledged(second_half(stream)));
    try testing.expectEqual(.reset_sent, stream.sending.state);
}

test "§13.3: a lost range is kept, and none is kept once RESET_STREAM has gone out" {
    const stream = try sent_stream();
    try test_streams.on_range_lost(first_half(stream));
    try testing.expectEqual(1, test_streams.lost.count);
    try testing.expectEqual(0, test_streams.lost.oldest().?.offset);
    // "Once an endpoint sends a RESET_STREAM frame, no further STREAM frames are needed."
    _ = stream.sending.on(.sent_reset);
    try test_streams.on_range_lost(second_half(stream));
    try testing.expectEqual(1, test_streams.lost.count);
    // A stream still in "Send", its FIN not yet out, retransmits too (§3.1).
    const open = try test_streams.open_local(.bidirectional);
    try open.outgoing.supply(test_body_len, false);
    _ = open.sending.on(.sent_data);
    open.outgoing.on_framed(test_half_len, false);
    try test_streams.on_range_lost(first_half(open));
    try testing.expectEqual(2, test_streams.lost.count);
}

test "§13.3: a range of a stream that has since closed counts toward nothing" {
    const stream = try sent_stream();
    const id = stream.stream_identifier();
    const range = first_half(stream);
    // The peer read the reset and acknowledged it, and the stream closed with both halves done.
    _ = stream.sending.on(.sent_reset);
    _ = stream.sending.on(.reset_acknowledged);
    _ = stream.receiving.on(.received_reset);
    _ = stream.receiving.on(.application_read_reset);
    test_streams.close(id);
    try testing.expect(!test_streams.on_range_acknowledged(range));
    try test_streams.on_range_lost(range);
    try testing.expectEqual(0, test_streams.lost.count);
}

test "§13.3: a lost range the full table cannot hold is refused, not dropped" {
    const stream = try sent_stream();
    const far_offset = 4 * test_body_len;
    for (0..constants.stream_lost_ranges_max) |index| {
        // Another stream's ranges, a gap apart, so the stream's own range joins none of them.
        const other: stream_lost.Range = .{ .stream_id = stream.id + 4, .offset = far_offset * index, .len = 1, .fin = false };
        try test_streams.lost.add(other);
    }
    try testing.expectError(stream_lost.Error.Full, test_streams.on_range_lost(first_half(stream)));
}
