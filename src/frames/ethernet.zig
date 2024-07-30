const std = @import("std");
const pcap = @cImport({
    @cInclude("pcap.h");
    @cInclude("pcap/pcap.h");
});
const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();
const utils = @import("../utils.zig");
const ipv4 = @import("../packets/ipv4.zig");
const tcp = @import("../packets/tcp.zig");

const PcapWrapperError = error{
    UnintializedError,
    PcapError,
};

const EthernetHeader = struct {
    sourceAddress: u48,
    destinationAddress: u48,
    etherType: EtherType,
};

const EtherType = enum(u16) {
    IPv4 = 0x0800,
    IPv6 = 0x86DD,
    ARP = 0x0806,
};

fn etherTypeToString(etherType: EtherType) []const u8 {
    switch (etherType) {
        EtherType.IPv4 => return "IPv4",
        EtherType.IPv6 => return "IPv6",
        EtherType.ARP => return "ARP",
    }
}

pub const EthernetFrame = struct {
    header: EthernetHeader,
    payload: []const u8,

    pub fn print(self: EthernetFrame, allocator: std.mem.Allocator) !void {
        const fmtSourceAddress = try utils.macAddressToString(allocator, self.header.sourceAddress);
        defer allocator.free(fmtSourceAddress);

        const fmtDestinationAddress = try utils.macAddressToString(allocator, self.header.destinationAddress);
        defer allocator.free(fmtDestinationAddress);

        std.debug.print("EthernetII Header:\n", .{});
        std.debug.print("  sourceAddress: {s}\n", .{fmtSourceAddress});
        std.debug.print("  destinationAddress: {s}\n", .{fmtDestinationAddress});
        std.debug.print("  etherType: {s}\n", .{etherTypeToString(self.header.etherType)});
    }

    pub fn readFromBytes(allocator: std.mem.Allocator, bytes: []const u8, headerLength: usize, totalLength: usize) !EthernetFrame {
        var frame: EthernetFrame = undefined;
        var header: EthernetHeader = undefined;

        // bits already in right order, so pass "big-endian" to do nothing
        header.sourceAddress = std.mem.readInt(u48, bytes[0..6], .big);
        header.destinationAddress = std.mem.readInt(u48, bytes[6..12], .big);

        // only EthernetII Frames are supported
        header.etherType = @enumFromInt(std.mem.readInt(u16, @ptrCast(bytes[12..headerLength]), .big));

        frame.header = header;
        frame.payload = bytes[headerLength..totalLength];

        try frame.print(allocator);

        const ip = ipv4.IPv4Packet.readFromBytes(frame.payload);
        try ip.print(allocator);

        const t = tcp.TcpPacket.readFromBytes(ip.payload, ip.header.totalLength - ip.header.headerLength);
        t.print(allocator);

        return frame;
    }
};
