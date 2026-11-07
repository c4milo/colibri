//! The settle of a server QUIC connection's requests (`quic_connection_h3.zig`): each request
//! brought up to date with its stream after a datagram, and after a call of the caller's that
//! changed its response (design §8 steps 29d.6 and 29d.7).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const quic_body = @import("quic_body.zig");
const quic_sends = @import("quic_sends.zig");
const quic_request = @import("quic_request.zig");
const quic_connection = @import("quic_connection.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");
const quic_coding = @import("quic_coding.zig");
const quic_continue = @import("quic_continue.zig");
const resets = @import("quic_connection_resets.zig");

const QuicConnection = quic_connection.QuicConnection;
const Request = quic_request.Request;
const StreamId = quic.StreamId;
const end = quic_connection_h3.end;
const finish_if_drained = quic_connection_h3.finish_if_drained;

/// Brings each request up to date with its stream: drops the runs the peer acknowledged, reports
/// a response that is done or a stream the peer stopped, writes the 100 (Continue) a request is
/// owed, and frees each record whose stream closed. A connection shut down ends once it holds
/// none.
pub fn settle(connection: *QuicConnection) void {
    if (connection.closed or connection.stopped) return;
    // A 100 (Continue) that finds no room in this pass sets it again (`quic_continue.zig`).
    connection.continue_owed = false;
    connection.requests.changed = .initEmpty();
    var held = connection.requests.walk();
    // Bounded by the records in use.
    while (held.next()) |record| settle_one(connection, record);
    finish_if_drained(connection);
}

/// Settles the requests whose response a call of the caller's changed since the last settle. Only
/// a datagram, which settles every request, or such a call changes what `settle_one` reads
/// (design §8 step 29d.7).
pub fn settle_changed(connection: *QuicConnection) void {
    if (connection.closed or connection.stopped) return;
    const requests = &connection.requests;
    // The walk reads a copy, so a record that a settle marks again stays marked for the next one.
    const marked = requests.changed;
    requests.changed = .initEmpty();
    var changed = marked.iterator(.{});
    // Bounded by the records in use.
    while (changed.next()) |index| {
        assert(requests.held.isSet(index));
        settle_one(connection, &requests.records[index]);
    }
    finish_if_drained(connection);
}

/// The live stream of `record`, or null once it closed. The first lookup that finds it keeps its
/// slot, and each later one reads that slot alone: a slot that no longer holds the identifier
/// says the stream closed, where a lookup would scan every slot to say so (design §8 step 29d.11).
fn live_stream(connection: *QuicConnection, record: *Request) ?*quic.Stream {
    const streams = &connection.transport.streams;
    if (record.stream_slot) |slot| {
        if (!streams.pool.holds(slot, record.stream_id)) return null;
        return streams.pool.at(slot);
    }
    const stream = switch (streams.lookup(.{ .value = record.stream_id })) {
        .live => |stream| stream,
        .closed, .unopened => return null,
    };
    record.stream_slot = streams.pool.index_of(stream);
    return stream;
}

fn settle_one(connection: *QuicConnection, record: *Request) void {
    const id: StreamId = .{ .value = record.stream_id };
    const stream = live_stream(connection, record) orelse {
        // RFC 9000 §3: a stream closes once each part is finished. `settle` runs after every
        // datagram, and saw any reset of the response first, so one not over was acknowledged
        // whole.
        if (!record.over) {
            assert(record.finished);
            end(connection, record, .done);
        }
        // Each way a request ends gave its encoder back, and each way its stream's receiving part
        // ends stopped the wait for its content.
        assert(record.coded == null);
        assert(!quic_body.waits(connection, record));
        quic_sends.forget(connection, record);
        connection.requests.free(record);
        return;
    };
    quic_sends.look(connection, record, stream);
    switch (stream.sending.state) {
        // RFC 9000 §3.1: "Data Recvd" means the peer acknowledged every octet.
        .data_recvd => if (!record.over) end(connection, record, .done),
        // RFC 9000 §3.5: the peer's STOP_SENDING reset the stream, whose octets are read no more.
        // RFC 9114 §4.1.1: that is the client cancelling its request, which the limit counts.
        .reset_sent, .reset_recvd => if (!record.over) {
            end(connection, record, .{ .cancelled = .peer_reset });
            if (!resets.count_peer_reset(connection)) return;
        },
        .ready, .send, .data_sent => {},
    }
    // The acknowledged end scans every packet in flight, and `settle` runs after each datagram,
    // so it is read only when a run can go.
    if (record.response.may_release(stream.outgoing.acknowledged_len)) release(connection, record, id);
    quic_coding.go_on(connection, record);
    quic_continue.write(connection, record, stream);
}

/// Drops the runs of `record`'s response that the peer acknowledged.
fn release(connection: *QuicConnection, record: *Request, id: StreamId) void {
    const acknowledged = quic.Connection.acknowledged_end(&connection.transport, id) orelse return;
    const freed = record.response.release_below(@min(acknowledged, record.response.end));
    // A coded response's runs are its ring's, which frees what the peer acknowledged.
    if (record.coded) |*coded| coded.ring.free(freed);
}
