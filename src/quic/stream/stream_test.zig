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
