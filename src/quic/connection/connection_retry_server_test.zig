//! The tests of `connection_retry.zig`'s server half: RFC 9000 §17.2.5.1's packet and §8.1.2's
//! verdict on the token a client returns.
//!
//! The fixture is `connection_retry_test.zig`'s, because both halves drive the same suite and the
//! strongest case here is a round trip through it; split off that file for length.
const std = @import("std");
const error_code = @import("../error_code.zig");
const header = @import("../packet/packet_header.zig");
const retry = @import("connection_retry.zig");
const fixture = @import("connection_retry_test.zig");

const testing = std.testing;

/// The client's address, as the opaque octets RFC 9000 §8.1.4 binds a token to. colibri owns no
/// socket, so what they mean is the caller's business and never colibri's.
const address_octet: u8 = 0xad;
const other_address_octet: u8 = 0xae;
const address_len: usize = 6;
const test_address: [address_len]u8 = @splat(address_octet);
const other_address: [address_len]u8 = @splat(other_address_octet);

fn request() retry.Request {
    return .{
        .client_source = &fixture.c1,
        .original_destination = &fixture.s1,
        .server_source = &fixture.s2,
        .address = &test_address,
        .now_ns = fixture.test_now_ns,
    };
}

fn answer(held: retry.Request) retry.Answer {
    return retry.answer(fixture.checker.suite(), held, &fixture.pseudo, &fixture.output);
}

test "RFC 9000 §17.2.5.1: a server writes a Retry the client of §17.2.5.2 accepts" {
    fixture.checker.init();
    const written = answer(request()).written;

    // The same octets, read by a client that sent its first Initial to S1.
    fixture.open_as(.client);
    const parsed = (try header.read(fixture.output[0..written], fixture.test_connection.identity.local_len())).retry;
    // §17.2.5.1: the Destination Connection ID is what the client put in its Source Connection ID.
    try testing.expectEqualSlices(u8, &fixture.c1, parsed.dcid);
    try testing.expectEqualSlices(u8, &fixture.s2, parsed.scid);
    // §8.1.2's token is the suite's, and the client repeats whatever it holds.
    // Decision 55: it carries both connection IDs §7.3 has the server send back.
    try testing.expectEqual(fixture.suite_token_len(.of(&fixture.s1, &fixture.s2)), parsed.token.len);

    const outcome = retry.receive(&fixture.test_connection, fixture.checker.suite(), parsed, &fixture.pseudo);
    try testing.expectEqualSlices(u8, &fixture.s2, outcome.taken.destination);
    try testing.expectEqualSlices(u8, parsed.token, fixture.test_connection.retry_token.slice());
}

test "RFC 9000 §17.2.5.1: a Source Connection ID equal to the client's Destination is refused" {
    fixture.checker.init();
    var held = request();
    // "This value MUST NOT be equal to the Destination Connection ID field of the packet sent by
    // the client", which is what the client's first Initial addressed.
    held.server_source = &fixture.s1;
    try testing.expectEqual(retry.Refused.source_is_destination, answer(held).refused);
}

test "RFC 9000 §8.1.1: a suite that mints no token writes no Retry" {
    fixture.checker.init();
    fixture.checker.mints_token = false;
    // §17.2.5.2 has a client discard "a Retry packet with a zero-length Retry Token field", so a
    // Retry without one is not worth sending.
    try testing.expectEqual(retry.Refused.no_token, answer(request()).refused);
}

test "RFC 9000 §17.2.5.2: a zero-length token is no Retry to send" {
    fixture.checker.init();
    fixture.checker.writes_empty_token = true;
    // "A client MUST discard a Retry packet with a zero-length Retry Token field", so a server
    // that could write only one sends nothing instead.
    try testing.expectEqual(retry.Refused.no_token, answer(request()).refused);
}

test "RFC 9001 §5.8: a suite that writes no Retry Integrity Tag writes no Retry" {
    fixture.checker.init();
    fixture.checker.writes_tag = false;
    try testing.expectEqual(retry.Refused.no_tag, answer(request()).refused);
}

test "RFC 9000 §17.2.5: a Retry is refused when the fixture.output cannot hold it" {
    fixture.checker.init();
    var small: [1]u8 = undefined;
    try testing.expectEqual(
        retry.Refused.no_space,
        retry.answer(fixture.checker.suite(), request(), &fixture.pseudo, &small).refused,
    );
}

test "RFC 9000 §8.1.2: an Initial's token is absent, validated or invalid" {
    fixture.checker.init();
    const written = answer(request()).written;
    const parsed = (try header.read(fixture.output[0..written], fixture.c1.len)).retry;
    const suite = fixture.checker.suite();
    const now_ns = fixture.test_now_ns;

    // §17.2.2: "This value is 0 if no token is present", which leaves the address unvalidated.
    try testing.expectEqual(.absent, retry.verify_token(suite, &test_address, &.{}, &fixture.s2, now_ns));
    // §8.1.2: the client returned the token, which "proves to the server that it received" it,
    // to the Retry's Source Connection ID, as §17.2.5.2 has it. Decision 55: the token gives back
    // both IDs §7.3 has the server send.
    const ids = retry.verify_token(suite, &test_address, parsed.token, &fixture.s2, now_ns).validated;
    try testing.expectEqualSlices(u8, &fixture.s1, ids.original_destination_slice());
    try testing.expectEqualSlices(u8, &fixture.s2, ids.retry_source_slice());
    // §8.1.4: "Tokens sent in Retry packets SHOULD include information that allows the server to
    // verify that the source IP address and port in client packets remain constant."
    try testing.expectEqual(.invalid, retry.verify_token(suite, &other_address, parsed.token, &fixture.s2, now_ns));
    // §8.1.4: "Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a
    // short time, as they are returned immediately by clients."
    const late_ns = now_ns + fixture.token_lifetime_ns;
    try testing.expectEqual(.invalid, retry.verify_token(suite, &test_address, parsed.token, &fixture.s2, late_ns));
}

test "RFC 9000 §17.2.5.2: a token returned to an ID its Retry did not name is invalid" {
    fixture.checker.init();
    const written = answer(request()).written;
    const parsed = (try header.read(fixture.output[0..written], fixture.c1.len)).retry;
    // The client addresses the Retry's Source Connection ID, so a token that arrives addressed to
    // another came from another Retry, and its retry_source_connection_id would not be this one.
    try testing.expectEqual(.invalid, retry.verify_token(fixture.checker.suite(), &test_address, parsed.token, &fixture.s1, fixture.test_now_ns));
}

test "RFC 9000 §8.1.3: a token that is not a Retry token leaves the address unvalidated" {
    fixture.checker.init();
    const written = answer(request()).written;
    const parsed = (try header.read(fixture.output[0..written], fixture.c1.len)).retry;
    var other_type: [fixture.token_bytes_max]u8 = undefined;
    @memcpy(other_type[0..parsed.token.len], parsed.token);
    other_type[0] = fixture.retry_token_type + 1;
    // "the server SHOULD proceed as if the client did not have a validated address, including
    // potentially sending a Retry packet", which is what an absent token means.
    try testing.expectEqual(.absent, retry.verify_token(fixture.checker.suite(), &test_address, other_type[0..parsed.token.len], &fixture.s2, fixture.test_now_ns));
}

test "RFC 9000 §8.1.2: an invalid token closes the connection with INVALID_TOKEN" {
    // "the server SHOULD immediately close (Section 10.2) the connection with an INVALID_TOKEN
    // error", which RFC 9000 §20.1 numbers 0x0b.
    try testing.expectEqual(error_code.invalid_token, retry.connection_error_code(.invalid).?);
    // Neither of the others ends the connection.
    try testing.expectEqual(null, retry.connection_error_code(.absent));
    try testing.expectEqual(null, retry.connection_error_code(.{ .validated = .{} }));
}
