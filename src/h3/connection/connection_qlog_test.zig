//! The tests of `connection_qlog.zig`: the HTTP/3 events an h3 connection given a log writes,
//! read back as the records `qlog.Log` holds. Both endpoints are the harness's, so each frame one
//! writes, the other reads.
const std = @import("std");
const core = @import("core");
const qlog = @import("qlog");
const quic = @import("quic");
const connection_module = @import("connection.zig");
const harness = @import("connection_test.zig");

const testing = std.testing;
const client = &harness.client;
const server = &harness.server;

/// Room for every record one test writes. Test-only.
const log_len: usize = 16_384;
var client_log: qlog.Log align(@alignOf(qlog.Log)) = undefined;
var server_log: qlog.Log align(@alignOf(qlog.Log)) = undefined;
var client_log_buffer: [log_len]u8 = undefined;
var server_log_buffer: [log_len]u8 = undefined;
const schemas = [_][]const u8{qlog.http3_event_schema};
const group_octet: u8 = 0xc1;
const group_id_len: usize = 4;
const group_id: [group_id_len]u8 = @splat(group_octet);
/// Instants after the harness's, 2.5 and 4.5 milliseconds into each log. Test-only.
const later_ns: u64 = 3_500_000;
const latest_ns: u64 = 5_500_000;

/// Two endpoints whose h3 connections log, with h3 started and the SETTINGS frames read.
fn pair_logged() !void {
    try start_log(&client_log, &client_log_buffer, .client);
    try start_log(&server_log, &server_log_buffer, .server);
    try harness.pair(.{ .role = .client, .qlog = &client_log }, .{ .role = .server, .qlog = &server_log });
}

fn start_log(log: *qlog.Log, buffer: []u8, vantage_point: qlog.VantagePoint) !void {
    log.* = qlog.Log.init(buffer, qlog.Features.none());
    try log.start(.{ .vantage_point = vantage_point, .group_id = &group_id, .event_schemas = &schemas }, harness.test_now_ns);
    // The tests read the events the connections write, so the header goes.
    log.clear();
}

fn expect_record(log: *const qlog.Log, expected: []const u8) !void {
    if (std.mem.indexOf(u8, log.bytes(), expected) != null) return;
    std.debug.print("record not in the log: {s}\nlog: {s}\n", .{ expected, log.bytes() });
    return error.TestExpectedRecord;
}

fn count_of(log: *const qlog.Log, needle: []const u8) usize {
    return std.mem.count(u8, log.bytes(), needle);
}

test "a started connection logs its three streams, its SETTINGS frame and its settings" {
    try pair_logged();
    // RFC 9000 §2.1: a client's unidirectional streams are 2, 6 and 10, and a server's 3, 7 and 11.
    try expect_record(&client_log, "\"name\":\"http3:stream_type_set\",\"data\":{\"initiator\":\"local\",\"stream_id\":2,\"stream_type\":\"control\"}}");
    try expect_record(&client_log, "\"data\":{\"initiator\":\"local\",\"stream_id\":6,\"stream_type\":\"qpack_encode\"}}");
    try expect_record(&client_log, "\"data\":{\"initiator\":\"local\",\"stream_id\":10,\"stream_type\":\"qpack_decode\"}}");
    // RFC 9114 §7.2.4.1: the field section size colibri accepts, and a reserved setting.
    var expected: [256]u8 = undefined;
    try expect_record(&client_log, try std.fmt.bufPrint(&expected, "\"name\":\"http3:frame_created\",\"data\":{{\"stream_id\":2,\"frame\":" ++
        "{{\"frame_type\":\"settings\",\"settings\":[{{\"name\":\"settings_max_field_section_size\",\"value\":{d}}}," ++
        "{{\"name\":\"reserved\",\"value\":0}}]", .{core.constants.field_section_size_max}));
    try expect_record(&client_log, try std.fmt.bufPrint(&expected, "\"name\":\"http3:parameters_set\",\"data\":{{\"initiator\":\"local\"," ++
        "\"max_field_section_size\":{d}}}}}", .{core.constants.field_section_size_max}));
    // The peer's three, its SETTINGS frame read, and its settings taken.
    try expect_record(&client_log, "\"data\":{\"initiator\":\"remote\",\"stream_id\":3,\"stream_type\":\"control\"}}");
    try expect_record(&client_log, "\"name\":\"http3:frame_parsed\",\"data\":{\"stream_id\":3,\"frame\":{\"frame_type\":\"settings\"");
    try expect_record(&client_log, "\"name\":\"http3:parameters_set\",\"data\":{\"initiator\":\"remote\"");
    try testing.expectEqual(6, count_of(&server_log, "http3:stream_type_set"));
}

test "a request and its response are logged as frames, with their lines, where each is written and read" {
    try pair_logged();
    client_log.clear();
    server_log.clear();
    const id = try harness.request(&harness.get_lines, "hello");
    try expect_record(&client_log, "\"data\":{\"initiator\":\"local\",\"stream_id\":0,\"stream_type\":\"request\"}}");
    try expect_record(&client_log, "\"name\":\"http3:frame_created\",\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"headers\",\"headers\":[" ++
        "{\"name\":\":method\",\"value\":\"GET\"},{\"name\":\":scheme\",\"value\":\"https\"}," ++
        "{\"name\":\":authority\",\"value\":\"example.com\"},{\"name\":\":path\",\"value\":\"/index.html\"}],\"raw\":{\"payload_length\":");
    try expect_record(&client_log, "\"name\":\"http3:frame_created\",\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"data\",\"raw\":{\"payload_length\":5}}}}");
    try harness.exchange();
    while (try harness.next(server)) |_| {}
    try expect_record(&server_log, "\"data\":{\"initiator\":\"remote\",\"stream_id\":0,\"stream_type\":\"request\"}}");
    try expect_record(&server_log, "\"name\":\"http3:frame_parsed\",\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"headers\",\"headers\":[{\"name\":\":method\",\"value\":\"GET\"}");
    try expect_record(&server_log, "\"name\":\"http3:frame_parsed\",\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"data\",\"raw\":{\"payload_length\":5}}}}");
    try harness.respond(id, &harness.ok_lines, "");
    try expect_record(&server_log, "\"name\":\"http3:frame_created\",\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"headers\",\"headers\":[{\"name\":\":status\",\"value\":\"200\"}");
    try harness.exchange();
    while (try harness.next(client)) |_| {}
    try expect_record(&client_log, "\"name\":\"http3:frame_parsed\",\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"headers\",\"headers\":[{\"name\":\":status\",\"value\":\"200\"}");
}

test "each event carries the instant of the call that wrote or read its frame" {
    try pair_logged();
    client_log.clear();
    const section = try harness.section_of(&harness.test_section, &harness.get_lines);
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, section, &.{}, &writer, later_ns);
    try client.h3.write_data_header(id, 0, &writer, latest_ns);
    // The stream's type and its HEADERS frame 2.5 milliseconds after the log's first instant, and
    // its DATA frame 4.5.
    try testing.expectEqual(2, count_of(&client_log, "{\"time\":2.500,"));
    try expect_record(&client_log, "{\"time\":4.500,\"name\":\"http3:frame_created\",\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"data\"");
}

test "a GOAWAY is logged where it is written and where it is read" {
    try pair_logged();
    try server.h3.shutdown(&server.transport, harness.test_now_ns);
    // RFC 9114 §5.2: a server that took no request names stream 0.
    try expect_record(&server_log, "\"name\":\"http3:frame_created\",\"data\":{\"stream_id\":3,\"frame\":{\"frame_type\":\"goaway\",\"id\":0,\"raw\":{\"payload_length\":1}}}}");
    try harness.exchange();
    try testing.expectEqual(connection_module.Event{ .goaway = 0 }, (try harness.next(client)).?);
    try expect_record(&client_log, "\"name\":\"http3:frame_parsed\",\"data\":{\"stream_id\":3,\"frame\":{\"frame_type\":\"goaway\",\"id\":0,\"raw\":{\"payload_length\":1}}}}");
}

test "a reserved or unknown frame, or stream, is logged with its type" {
    try pair_logged();
    const section = try harness.section_of(&harness.test_section, &harness.get_lines);
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, section, &.{}, &writer, harness.test_now_ns);
    try client.commit(id, writer.written(), false);
    // RFC 9114 §7.2.8's reserved type 0x21 and a type no RFC defines, each with an empty payload,
    // after the request.
    try client.send_raw(id, &.{ 0x21, 0x00, 0x2f, 0x00 }, false);
    // RFC 9114 §6.2.3's reserved stream type 0x21, and a type no RFC defines.
    var reserved = try quic.connection_stream_send.open(&client.transport, .unidirectional);
    try client.send_raw(reserved.value, &.{0x21}, false);
    reserved = try quic.connection_stream_send.open(&client.transport, .unidirectional);
    try client.send_raw(reserved.value, &.{0x14}, false);
    try harness.exchange();
    while (try harness.next(server)) |_| {}
    try expect_record(&server_log, "\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"reserved\",\"frame_type_bytes\":33,\"raw\":{\"payload_length\":0}}}}");
    try expect_record(&server_log, "\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"unknown\",\"frame_type_bytes\":47,\"raw\":{\"payload_length\":0}}}}");
    try expect_record(&server_log, "\"data\":{\"initiator\":\"remote\",\"stream_id\":14,\"stream_type\":\"reserved\"}}");
    try expect_record(&server_log, "\"data\":{\"initiator\":\"remote\",\"stream_id\":18,\"stream_type\":\"unknown\",\"stream_type_bytes\":20}}");
}

test "a trailer section is logged as a HEADERS frame of its own" {
    try pair_logged();
    client_log.clear();
    const post = [_]harness.Line{ .{ ":method", "POST" }, .{ ":scheme", "https" }, .{ ":path", "/upload" }, .{ ":authority", "a" } };
    const section = try harness.section_of(&harness.test_section, &post);
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, section, &.{}, &writer, harness.test_now_ns);
    try client.h3.write_trailers(&client.transport, id, try harness.section_of(&harness.test_section, &.{.{ "x-checksum", "1" }}), &writer, harness.test_now_ns);
    try expect_record(&client_log, "\"frame\":{\"frame_type\":\"headers\",\"headers\":[{\"name\":\"x-checksum\",\"value\":\"1\"}]");
}

test "a reserved frame on the control stream is logged where it is skipped" {
    try start_log(&server_log, &server_log_buffer, .server);
    harness.pair_unstarted(.{ .role = .client }, .{ .role = .server, .qlog = &server_log });
    try server.h3.start(&server.transport, harness.test_now_ns);
    // A control stream the client writes itself: its type, an empty SETTINGS frame, and RFC 9114
    // §7.2.8's reserved type 0x21 with two octets.
    const id = try quic.connection_stream_send.open(&client.transport, .unidirectional);
    try client.send_raw(id.value, &.{ 0x00, 0x04, 0x00, 0x21, 0x02, 'a', 'b' }, false);
    try harness.exchange();
    while (try harness.next(server)) |_| {}
    try expect_record(&server_log, "\"data\":{\"stream_id\":2,\"frame\":{\"frame_type\":\"reserved\",\"frame_type_bytes\":33,\"raw\":{\"payload_length\":2}}}}");
}
