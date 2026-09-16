//! The connection-specific field names: the denylist both h2 and h3 enforce (decision 15).
//!
//! RFC 9110 §7.6.1 defines the Connection field and names fields an intermediary should remove
//! before forwarding, a list it says is not complete: Proxy-Connection, Keep-Alive, TE,
//! Transfer-Encoding and Upgrade. The rule that refuses them is h2's and h3's. RFC 9113 §8.2.2
//! makes a message carrying Connection, Proxy-Connection, Keep-Alive, Transfer-Encoding or Upgrade
//! malformed, and RFC 9114 §4.2 makes a message carrying a connection-specific field malformed.
//! Both state one exception in nearly the same words: TE may appear in a request when its value is
//! "trailers".
//!
//! `te_is_trailers` accepts every form of a trailers-only TE value that RFC 9110 admits, not one
//! fixed string. TE is a list (`TE = #t-codings`, RFC 9110 §10.1.4), so members are separated by
//! commas with optional whitespace, and empty members are ignored (RFC 9110 §5.6.1.2). "trailers"
//! is an ABNF quoted string, which matches in any case (RFC 5234 §2.3). The owner ruled on
//! 2026-09-16 that colibri accepts all of these (decision 15). The function trims whitespace from
//! every member, so it also accepts whitespace at either end of the value. Field validation
//! refuses that whitespace before this function is asked.
//!
//! This file classifies; it does not decide. `classify` names which connection-specific field a
//! name is, and `te_is_trailers` answers the exception's question. Whether a TE in a response, or a
//! TE with another value, is malformed, and what error that is, is the protocol module's.
const std = @import("std");
const core = @import("core");
const field = @import("field.zig");

/// The whitespace RFC 9110 §5.6.3 allows around a list separator: OWS is SP or HTAB.
const optional_whitespace = " \t";

pub const ConnectionSpecific = enum {
    connection,
    proxy_connection,
    keep_alive,
    te,
    transfer_encoding,
    upgrade,
};

/// Every connection-specific field name, as RFC 9110 §7.6.1 spells it.
const names = [_]struct { []const u8, ConnectionSpecific }{
    .{ "Connection", .connection },
    .{ "Proxy-Connection", .proxy_connection },
    .{ "Keep-Alive", .keep_alive },
    .{ "TE", .te },
    .{ "Transfer-Encoding", .transfer_encoding },
    .{ "Upgrade", .upgrade },
};

/// The only TE member RFC 9113 §8.2.2 and RFC 9114 §4.2 permit.
pub const te_trailers = "trailers";

/// Which connection-specific field `name` is, compared case-insensitively (RFC 9110 §5.1), or null
/// when it is none of them.
pub fn classify(name: []const u8) ?ConnectionSpecific {
    for (names) |entry| {
        // RFC 9113 §8.2.2, RFC 9114 §4.2: connection-specific fields make a message malformed.
        if (field.names_equal(name, entry[0])) return entry[1];
    }
    return null;
}

/// Most calls `te_is_trailers` makes to its splitter. n octets hold at most n + 1 members, and one
/// more call finds the end, so the bound is never the reason the loop stops.
const te_split_calls_max = core.constants.field_value_len_max + te_split_calls_past_len;
const te_split_calls_past_len = 2;

/// True when every member of a TE value is "trailers", the one member RFC 9113 §8.2.2 and RFC 9114
/// §4.2 permit. A value with no member at all holds nothing else, so it is true too. A value longer
/// than `field_value_len_max` is false: field validation has already refused it.
pub fn te_is_trailers(value: []const u8) bool {
    if (value.len > core.constants.field_value_len_max) return false;
    var members = std.mem.splitScalar(u8, value, ',');
    for (0..te_split_calls_max) |_| {
        const member = members.next() orelse return true;
        // RFC 9110 §5.6.1.2: OWS around the comma, and empty members are ignored.
        const trimmed = std.mem.trim(u8, member, optional_whitespace);
        if (trimmed.len == 0) continue;
        // RFC 9113 §8.2.2, RFC 9114 §4.2: no member other than trailers; RFC 5234 §2.3: in any case.
        if (!std.ascii.eqlIgnoreCase(trimmed, te_trailers)) return false;
    }
    unreachable;
}

const testing = std.testing;

test "the five fields RFC 9110 §7.6.1 lists and Connection itself classify, in any case" {
    try testing.expectEqual(ConnectionSpecific.connection, classify("connection").?);
    try testing.expectEqual(ConnectionSpecific.proxy_connection, classify("proxy-connection").?);
    try testing.expectEqual(ConnectionSpecific.keep_alive, classify("KEEP-ALIVE").?);
    try testing.expectEqual(ConnectionSpecific.te, classify("te").?);
    try testing.expectEqual(ConnectionSpecific.transfer_encoding, classify("Transfer-Encoding").?);
    try testing.expectEqual(ConnectionSpecific.upgrade, classify("upgrade").?);
}

test "an end-to-end field is not connection-specific" {
    const end_to_end = [_][]const u8{ "content-length", "trailer", "tea", "t", "", "connections" };
    for (end_to_end) |name| try testing.expectEqual(null, classify(name));
}

test "TE is trailers in any case, as a list with optional whitespace and empty members" {
    const accepted = [_][]const u8{
        "trailers",   "Trailers",            "TRAILERS",    "trailers,",
        ", trailers", "trailers , trailers", " trailers\t", "trailers,,\t,Trailers",
        "",           ",",
    };
    for (accepted) |value| try testing.expect(te_is_trailers(value));
}

test "TE with any other member is not trailers" {
    const refused = [_][]const u8{
        "gzip",      "trailers, gzip", "gzip, trailers", "trailers;q=0.5", "trailer", "trailersx",
        "trai lers", "trailers\x0b",   "\"trailers\"",
    };
    for (refused) |value| try testing.expect(!te_is_trailers(value));
    const too_long: [core.constants.field_value_len_max + 1]u8 = @splat(',');
    try testing.expect(!te_is_trailers(&too_long));
}

test "TE at the length limit, all empty members, ends the list rather than the loop" {
    // field_value_len_max commas are one more member than octets: the most members a value holds.
    const commas: [core.constants.field_value_len_max]u8 = @splat(',');
    try testing.expect(te_is_trailers(&commas));
}

/// Most octets a fuzz input carries. Test-only.
const fuzz_input_len_max = 32;

fn fuzz_te(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const value = input[0..smith.slice(&input)];
    if (!te_is_trailers(value)) return;
    // Every octet of a value that holds only trailers is a letter of it, a comma or OWS.
    for (value) |octet| try testing.expect(std.mem.indexOfScalar(u8, "trailersTRAILERS, \t", octet) != null);
}

test "fuzz: a TE value that is trailers holds only trailers, commas and whitespace" {
    try testing.fuzz({}, fuzz_te, .{ .corpus = &.{
        core.fuzz.input("Trailers, trailers"),
        core.fuzz.input("trailers, gzip"),
    } });
}

test "sweep: every TE value of up to two octets that is trailers holds nothing else" {
    try core.fuzz.sweep(fuzz_te, null);
}
