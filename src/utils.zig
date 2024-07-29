const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();

pub fn macAddressToString(allocator: std.mem.Allocator, macAddress: u48) ![]const u8 {
    const str = std.fmt.allocPrint(allocator, "{x}:{x}:{x}:{x}:{x}:{x}", .{
        macAddress & 0xFF,
        (macAddress >> 8) & 0xFF,
        (macAddress >> 16) & 0xFF,
        (macAddress >> 24) & 0xFF,
        (macAddress >> 32) & 0xFF,
        (macAddress >> 40) & 0xFF,
    });

    return str;
}

pub fn ipAddressToString(allocator: std.mem.Allocator, ipAddress: u32) ![]const u8 {
    if (native_endian == .little) {
        const str = std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            (ipAddress >> 24) & 0xFF,
            (ipAddress >> 16) & 0xFF,
            (ipAddress >> 8) & 0xFF,
            ipAddress & 0xFF,
        });

        return str;
    } else {
        const str = std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            (ipAddress >> 24) & 0xFF,
            (ipAddress >> 16) & 0xFF,
            (ipAddress >> 8) & 0xFF,
            ipAddress & 0xFF,
        });

        return str;
    }
}
