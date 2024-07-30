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
    source_address: u48,
    destination_address: u48,
    ether_type: EtherType,
};

const EtherType = enum(u16) {
    IPv4 = 0x0800,
    IPv6 = 0x86DD,
    ARP = 0x0806,
};

fn etherTypeToString(ether_type: EtherType) []const u8 {
    switch (ether_type) {
        EtherType.IPv4 => return "IPv4",
        EtherType.IPv6 => return "IPv6",
        EtherType.ARP => return "ARP",
    }
}

pub const EthernetFrame = struct {
    header: EthernetHeader,
    payload: []const u8,

    pub fn print(self: EthernetFrame, allocator: std.mem.Allocator) !void {
        const fmt_source_address = try utils.macAddressToString(allocator, self.header.source_address);
        defer allocator.free(fmt_source_address);

        const fmt_destination_address = try utils.macAddressToString(allocator, self.header.destination_address);
        defer allocator.free(fmt_destination_address);

        std.debug.print("EthernetII Header:\n", .{});
        std.debug.print("  source_address: {s}\n", .{fmt_source_address});
        std.debug.print("  destination_address: {s}\n", .{fmt_destination_address});
        std.debug.print("  ether_type: {s}\n", .{etherTypeToString(self.header.ether_type)});
    }

    pub fn readFromBytes(allocator: std.mem.Allocator, bytes: []const u8, header_length: usize, total_length: usize) !EthernetFrame {
        var frame: EthernetFrame = undefined;
        var header: EthernetHeader = undefined;

        // bits already in right order, so pass "big-endian" to do nothing
        header.source_address = std.mem.readInt(u48, bytes[0..6], .big);
        header.destination_address = std.mem.readInt(u48, bytes[6..12], .big);

        // only EthernetII Frames are supported
        header.ether_type = @enumFromInt(std.mem.readInt(u16, @ptrCast(bytes[12..header_length]), .big));

        frame.header = header;
        frame.payload = bytes[header_length..total_length];

        try frame.print(allocator);

        const ip = ipv4.IPv4Packet.readFromBytes(frame.payload);
        try ip.print(allocator);

        const t = tcp.TcpPacket.readFromBytes(ip.payload, ip.header.total_length - ip.header.header_length);
        t.print(allocator);

        return frame;
    }
};
