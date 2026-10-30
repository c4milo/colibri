//! The parameters of a path that a route table matched (decision 122, design §8 step 21e). A
//! program places one `PathParameters`, passes it to each `match` of its table, and reads a value
//! by its name with `get`.
//!
//! Each name is a constant of the table, so it stays valid for the whole program. Each value is
//! the segment that `match` read, percent-decoded (RFC 3986 §2.1, decision 127). A segment with no
//! "%" is a slice of the path that the program passed to `match`, valid until the endpoint's next
//! call that the comment on `Endpoint.receive` lists. A decoded one is a slice of `storage`, valid
//! until the next `match`.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// The parameters that one `match` wrote: a name and a value for each, in the order of the
/// pattern's segments. `match` sets `count` to 0 first, so a value of an earlier match is never
/// read.
pub const PathParameters = struct {
    names: [constants.limits.path_parameters_max][]const u8 = @splat(""),
    values: [constants.limits.path_parameters_max][]const u8 = @splat(""),
    /// How many entries of `names` and `values` the last `match` wrote.
    count: std.math.IntFittingRange(0, constants.limits.path_parameters_max) = 0,
    /// Where `match` decodes the segments that hold a "%", each at its own offset in the path,
    /// so a decoded segment never writes over another.
    storage: [constants.limits.path_len_max]u8 = undefined,

    /// The value of the parameter `name`, or null when the route that matched has no parameter of
    /// that name. The names compare octet for octet.
    pub fn get(parameters: *const PathParameters, name: []const u8) ?[]const u8 {
        assert(parameters.count <= constants.limits.path_parameters_max);
        const count = parameters.count;
        for (parameters.names[0..count], parameters.values[0..count]) |held, value| {
            if (std.mem.eql(u8, held, name)) return value;
        }
        return null;
    }
};

const testing = std.testing;

test "decision 122: PathParameters exports get alone" {
    try @import("core").public_names.expect(PathParameters, &.{"get"});
}

test "decision 122: get finds a parameter by its whole name, and nothing in an empty set" {
    var parameters: PathParameters = .{};
    try testing.expectEqual(null, parameters.get("id"));
    parameters.names[0] = "id";
    parameters.values[0] = "42";
    // A name the count does not include is not read.
    try testing.expectEqual(null, parameters.get("id"));
    parameters.count = 1;
    try testing.expectEqualStrings("42", parameters.get("id").?);
    try testing.expectEqual(null, parameters.get("i"));
    try testing.expectEqual(null, parameters.get("idx"));
    try testing.expectEqual(null, parameters.get("ID"));
}
