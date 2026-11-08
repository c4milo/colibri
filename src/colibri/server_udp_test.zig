//! The test of a `colibri.Server`'s UDP receive path (design §8 step 37): the host reports each
//! datagram's ECN codepoint, and the driver passes it to the engine. The engine must take a
//! datagram marked ECT(0), as quic-go marks them, and must not halt the server (decision 68). The
//! test is the host: it completes the receive that the driver wrote, with bytes that it lends for
//! the call alone (decision 159). Decision 150 ruling 7 lets this test bind loopback.
const std = @import("std");
const server = @import("server");
const testdata = @import("testdata");
const server_module = @import("server.zig");
const server_loop = @import("server_loop.zig");
const host = @import("host.zig");
const support = @import("test_support.zig");

const testing = std.testing;

/// RFC 9110 §15.6.1: 500 (Internal Server Error).
const internal_server_error: server.Status = .internal_server_error;
/// The room of the router's one response, which holds a head and no body.
const response_bytes = 64;

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/", answer },
    },
};
const Router = server.Router(void, routes, .{ .requests = 1, .response_bytes = response_bytes, .body_bytes = 0 });

fn answer(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.end();
}

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}

/// A server with one TCP connection and one QUIC connection, so `init` opens the UDP socket.
const TestServer = server_module.Server(.{ .tcp_connections = 1, .quic_connections = 1 }, .private);

/// The server and its router, which the test places outside any stack frame. Test-only.
var test_server: TestServer align(@alignOf(TestServer)) = undefined;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};

fn hex(comptime digits: []const u8) [digits.len / hex_digits_per_octet]u8 {
    @setEvalBranchQuota(hex_branches_per_digit * digits.len);
    var octets: [digits.len / hex_digits_per_octet]u8 = undefined;
    _ = std.fmt.hexToBytes(&octets, digits) catch unreachable;
    return octets;
}
const hex_digits_per_octet = 2;
const hex_branches_per_digit = 64;

/// RFC 9001 Appendix A.2: a client's protected Initial, one datagram of 1200 octets (RFC 9001
/// lines 2421 to 2458).
const client_initial = hex("c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" ++
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" ++
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" ++
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" ++
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" ++
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" ++
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" ++
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" ++
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" ++
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" ++
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" ++
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" ++
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" ++
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" ++
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" ++
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" ++
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" ++
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" ++
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" ++
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" ++
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" ++
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" ++
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" ++
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" ++
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" ++
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" ++
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" ++
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" ++
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" ++
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" ++
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" ++
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" ++
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" ++
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" ++
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" ++
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" ++
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" ++
    "e221af44860018ab0856972e194cd934");

/// The room a test's turn writes into: an accept and the receive, then the sends.
const operations_len = 8;

test "design §8 step 37: the engine takes a datagram marked ECT(0) and counts its codepoint" {
    var counter: support.Counter = .{};
    router = .{};
    try test_server.init(&.{
        .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem },
        .cpu = support.cpu(),
        .random = counter.random(),
    }, &router, &context);
    defer test_server.deinit();
    // Decision 68: the server's host reads each codepoint, so its engine says so, whatever the
    // program's configuration says.
    try testing.expect(test_server.engine_config.ecn);
    try server_loop.start(&test_server, 0);
    var operations: [operations_len]host.Operation = undefined;
    const first = server_loop.turn(&test_server, 0, &operations);
    const receive = receive_written(operations[0..first.operations]).?;
    var datagram = client_initial;
    // RFC 9000 §13.4: the host read ECT(0) off the datagram's IP header.
    const loopback = [_]u8{ 127, 0, 0, 1 };
    server_loop.complete(&test_server, &.{ .id = receive, .more = true, .result = .{ .datagram = .{
        .bytes = &datagram,
        .from = server.Address.of(&loopback, 4433),
        .ecn = .ect_0,
    } } }, 1);
    // Decision 159: the host lends the bytes for `complete` alone, and may write over them next.
    @memset(&datagram, 0);
    // RFC 9000 §13.4.1: the Initial space counts one ECT(0) packet. No program reads the count, so
    // the test reads the field of the engine's one QUIC connection.
    const transport = &test_server.engine.state.connections.connections[0].transport;
    try testing.expectEqual(1, transport.spaces[0].ecn.ect_0);
    // The engine opened the Initial, and the next turn sends the client its own Initial.
    const second = server_loop.turn(&test_server, 1, &operations);
    const sent = send_written(operations[0..second.operations]).?;
    try testing.expect(sent.bytes.len > 0);
    try testing.expectEqual(4433, sent.to.port);
    // RFC 9000 §13.4.2: an endpoint that reads ECN marks what it sends ECT(0) while it tests the
    // path. The driver names ECT(0) here, and a test in `rotor_host_udp.zig` checks that the
    // host asks Rotor to set it.
    try testing.expectEqual(server.Ecn.ect_0, sent.ecn);
}

/// The id of the receive of datagrams among `written`, or null.
fn receive_written(written: []const host.Operation) ?host.OperationId {
    for (written) |operation| {
        if (operation.kind == .receive_datagram) return operation.id;
    }
    return null;
}

/// The first send of datagrams among `written`, or null.
fn send_written(written: []const host.Operation) ?@FieldType(host.Operation.Kind, "send_datagram") {
    for (written) |operation| {
        if (operation.kind == .send_datagram) return operation.kind.send_datagram;
    }
    return null;
}
