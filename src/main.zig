const std = @import("std");
const scrypt = @import("scrypt");

pub fn main() !void {
    var buf: [scrypt.MCF_LEN]u8 = undefined;
    try scrypt.hashSimple(&buf, "TEST");

    std.debug.print("{s}\n", .{buf});

    const ok = try scrypt.check(&buf, "TEST");
    if (!ok) {
        std.debug.print("Incorrect Password!\n", .{});
    }
}
