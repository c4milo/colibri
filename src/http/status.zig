//! The response status code as RFC 9110 §15 models it (decision 15): an integer from 100 to 599,
//! whose first digit is its class, and where a code the recipient does not recognise is treated as
//! the x00 code of its class.
//!
//! A status written as text is checked in this order (invariant 7):
//!   1. exactly three octets, or `error.StatusNotThreeDigits`;
//!   2. every octet a DIGIT, or `error.StatusNotThreeDigits`;
//!   3. the value in 100 to 599, or `error.StatusOutOfRange`.
//! h2 and h3 both carry the status as the text of the `:status` pseudo-header, so the text form is
//! the one peer bytes reach. `error.StatusOutOfRange` is a reason, not a verdict: RFC 9110 §15 asks
//! a client to process an invalid code as a 5xx, so the protocol module decides whether to refuse
//! the response and cites its own rule when it does.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

pub const Error = error{
    StatusNotThreeDigits,
    StatusOutOfRange,
};

/// The five classes, numbered by the first digit (RFC 9110 §15).
pub const Class = enum(u3) {
    informational = 1,
    successful = 2,
    redirection = 3,
    client_error = 4,
    server_error = 5,
};

/// Every status code RFC 9110 §15.2 to §15.6 defines, named as its section heading names it. 306
/// and 418 are absent: §15.4.7 and §15.5.19 mark them unused, so they carry no semantics and are
/// understood as their class's x00.
pub const Code = enum(u16) {
    @"continue" = 100,
    switching_protocols = 101,
    ok = 200,
    created = 201,
    accepted = 202,
    non_authoritative_information = 203,
    no_content = 204,
    reset_content = 205,
    partial_content = 206,
    multiple_choices = 300,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    use_proxy = 305,
    temporary_redirect = 307,
    permanent_redirect = 308,
    bad_request = 400,
    unauthorized = 401,
    payment_required = 402,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    proxy_authentication_required = 407,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    precondition_failed = 412,
    content_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    expectation_failed = 417,
    misdirected_request = 421,
    unprocessable_content = 422,
    upgrade_required = 426,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,
};

pub const Status = struct {
    code: u16,

    /// The status whose code is `code`.
    pub fn from_code(code: u16) Error!Status {
        const in_range = code >= constants.status_code_min and code <= constants.status_code_max;
        // RFC 9110 §15: all valid status codes are within the range of 100 to 599, inclusive.
        if (!in_range) return error.StatusOutOfRange;
        return .{ .code = code };
    }

    /// The status written as three ASCII digits.
    pub fn from_digits(digits: []const u8) Error!Status {
        // RFC 9110 §15: the status code is a three-digit integer code.
        if (digits.len != constants.status_digits_len) return error.StatusNotThreeDigits;
        var code: u16 = 0;
        for (digits) |digit| {
            // RFC 9110 §15: three digits; DIGIT is 0x30 to 0x39 (RFC 5234 Appendix B.1).
            if (!std.ascii.isDigit(digit)) return error.StatusNotThreeDigits;
            code = code * constants.status_digit_radix + (digit - '0');
        }
        return from_code(code);
    }

    /// The class the first digit names (RFC 9110 §15).
    /// Writes the three digits of the status code into `digits`, the mirror of `from_digits`:
    /// RFC 9113 §8.3.2 and RFC 9114 §4.3.2 carry them as the `:status` value, and RFC 9110 §15
    /// makes them three, leading zeros included.
    pub fn write_digits(self: Status, digits: *[constants.status_digits_len]u8) []const u8 {
        assert(self.code >= constants.status_code_min and self.code <= constants.status_code_max);
        var rest = self.code;
        var index = constants.status_digits_len;
        while (index > 0) {
            index -= 1;
            digits[index] = '0' + @as(u8, @intCast(rest % constants.status_digit_radix));
            rest /= constants.status_digit_radix;
        }
        assert(rest == 0);
        return digits;
    }

    pub fn class(self: Status) Class {
        assert(self.code >= constants.status_code_min and self.code <= constants.status_code_max);
        return @enumFromInt(self.code / constants.status_class_size);
    }

    /// True when RFC 9110 §15.2 to §15.6 define this code.
    pub fn is_recognized(self: Status) bool {
        return std.enums.fromInt(Code, self.code) != null;
    }

    /// The status a recipient acts on: the code itself when recognised, otherwise the x00 code of
    /// its class (RFC 9110 §15).
    pub fn understood(self: Status) Status {
        // RFC 9110 §15: treat an unrecognized status code as the x00 status code of its class.
        if (self.is_recognized()) return self;
        const understood_code = @as(u16, @intFromEnum(self.class())) * constants.status_class_size;
        assert(std.enums.fromInt(Code, understood_code) != null);
        return .{ .code = understood_code };
    }

    /// True for a 1xx response, which RFC 9110 §15 calls interim: zero or more of them precede
    /// exactly one final response.
    pub fn is_interim(self: Status) bool {
        return self.class() == .informational;
    }
};

const testing = std.testing;

test "write_digits is the mirror of from_digits over every status code" {
    var digits: [constants.status_digits_len]u8 = undefined;
    var code: u16 = constants.status_code_min;
    while (code <= constants.status_code_max) : (code += 1) {
        const status = try Status.from_code(code);
        const written = status.write_digits(&digits);
        try std.testing.expectEqual(constants.status_digits_len, written.len);
        try std.testing.expectEqual(code, (try Status.from_digits(written)).code);
    }
    const found = try Status.from_code(200);
    try std.testing.expectEqualStrings("200", found.write_digits(&digits));
}

test "the range ends are 100 and 599" {
    try testing.expectError(error.StatusOutOfRange, Status.from_code(99));
    try testing.expectEqual(100, (try Status.from_code(100)).code);
    try testing.expectEqual(599, (try Status.from_code(599)).code);
    try testing.expectError(error.StatusOutOfRange, Status.from_code(600));
    try testing.expectError(error.StatusOutOfRange, Status.from_code(0));
}

test "three digits parse, and anything else is refused in check order" {
    try testing.expectEqual(204, (try Status.from_digits("204")).code);
    try testing.expectError(error.StatusNotThreeDigits, Status.from_digits("20"));
    try testing.expectError(error.StatusNotThreeDigits, Status.from_digits("2040"));
    try testing.expectError(error.StatusNotThreeDigits, Status.from_digits(""));
    try testing.expectError(error.StatusNotThreeDigits, Status.from_digits("2x4"));
    try testing.expectError(error.StatusNotThreeDigits, Status.from_digits(" 20"));
    try testing.expectError(error.StatusNotThreeDigits, Status.from_digits("+20"));
    try testing.expectError(error.StatusOutOfRange, Status.from_digits("099"));
    try testing.expectError(error.StatusOutOfRange, Status.from_digits("600"));
    try testing.expectError(error.StatusOutOfRange, Status.from_digits("999"));
}

test "the first digit is the class" {
    try testing.expectEqual(Class.informational, (try Status.from_code(103)).class());
    try testing.expectEqual(Class.successful, (try Status.from_code(299)).class());
    try testing.expectEqual(Class.redirection, (try Status.from_code(300)).class());
    try testing.expectEqual(Class.client_error, (try Status.from_code(451)).class());
    try testing.expectEqual(Class.server_error, (try Status.from_code(599)).class());
    try testing.expect((try Status.from_code(100)).is_interim());
    try testing.expect(!(try Status.from_code(200)).is_interim());
}

test "an unrecognised code is understood as the x00 of its class" {
    try testing.expectEqual(400, (try Status.from_code(471)).understood().code);
    try testing.expectEqual(404, (try Status.from_code(404)).understood().code);
    try testing.expectEqual(300, (try Status.from_code(306)).understood().code);
    try testing.expectEqual(400, (try Status.from_code(418)).understood().code);
    try testing.expectEqual(500, (try Status.from_code(599)).understood().code);
    try testing.expectEqual(100, (try Status.from_code(199)).understood().code);
    // Every class's x00 is itself recognised, so understanding never needs a second step.
    for (1..6) |digit| {
        const code: u16 = @intCast(digit * constants.status_class_size);
        try testing.expect((try Status.from_code(code)).is_recognized());
    }
}

test "the recognised codes are exactly those RFC 9110 §15.2 to §15.6 define" {
    // The same set written as ranges, as the RFC's section headings run: 306 and 418 unused.
    for (constants.status_code_min..constants.status_code_max + 1) |number| {
        const code: u16 = @intCast(number);
        const defined = switch (code) {
            100...101, 200...206, 300...305, 307...308, 400...417, 421, 422, 426, 500...505 => true,
            else => false,
        };
        try testing.expectEqual(defined, (try Status.from_code(code)).is_recognized());
    }
}

/// Most octets a fuzz input carries: one more than a status, so a fourth digit is reachable.
const fuzz_input_len_max = constants.status_digits_len + 1;

fn fuzz_from_digits(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const digits = input[0..smith.slice(&input)];
    const status = Status.from_digits(digits) catch return;
    try testing.expect(status.code >= constants.status_code_min);
    try testing.expect(status.code <= constants.status_code_max);
    try testing.expect(status.understood().is_recognized());
}

test "fuzz: a status that parses is in range and understood as a recognised code" {
    try testing.fuzz({}, fuzz_from_digits, .{ .corpus = &.{
        core.fuzz.input("200"),
        core.fuzz.input("471"),
        core.fuzz.input("600"),
        core.fuzz.input("20"),
    } });
}

test "every three-digit string parses exactly when it is 100 to 599" {
    for (0..1000) |number| {
        var digits: [constants.status_digits_len]u8 = @splat('0');
        _ = std.fmt.bufPrint(&digits, "{d:0>3}", .{number}) catch unreachable;
        const in_range = number >= constants.status_code_min and number <= constants.status_code_max;
        if (Status.from_digits(&digits)) |status| {
            try testing.expect(in_range);
            try testing.expectEqual(number, status.code);
        } else |err| {
            try testing.expect(!in_range);
            try testing.expectEqual(error.StatusOutOfRange, err);
        }
    }
}
