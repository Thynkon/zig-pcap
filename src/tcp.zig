const std = @import("std");
const pcap = @cImport({
    @cInclude("pcap.h");
    @cInclude("pcap/pcap.h");
});
const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();

const PcapWrapperError = error{
    UnintializedError,
    PcapError,
};

const TcpFlags = packed struct(u8) {
    cwr: bool,
    ece: bool,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,

    pub fn toString(self: TcpFlags) []const u8 {
        _ = self;
        return "";
    }
};

const TcpHeader = struct {
    sourcePort: u16,
    destinationPort: u16,
    sequenceNumber: u32,
    ackNumber: u32,
    headerLength: u4,
    flags: TcpFlags,
    windowSize: u16,
    checksum: u32,
    urgentPointer: u32,
    // TODO: implement options
};

pub const TcpPacket = struct {
    header: TcpHeader,
    payload: []const u8,

    pub fn print(self: TcpPacket, allocator: std.mem.Allocator) void {
        _ = allocator;
        std.debug.print("TCP Header:\n", .{});
        std.debug.print("  Source Port: {d}\n", .{self.header.sourcePort});
        std.debug.print("  Destination Port: {d}\n", .{self.header.destinationPort});
        std.debug.print("  Sequence Number: {d}\n", .{self.header.sequenceNumber});
        std.debug.print("  Acknowledgment Number: {d}\n", .{self.header.ackNumber});
        std.debug.print("  Header Length: {d}\n", .{self.header.headerLength});
        std.debug.print("  Flags: {s}\n", .{self.header.flags.toString()});
        std.debug.print("  Window Size: {d}\n", .{self.header.windowSize});
        std.debug.print("  Checksum: 0x{x}\n", .{self.header.checksum});
        std.debug.print("  Urgent Pointer: {d}\n\n\n", .{self.header.urgentPointer});
    }
};

pub fn tcpFlagsFromBytes(byte: u8) TcpFlags {
    return TcpFlags{
        .cwr = (byte & 0x1) != 0,
        .ece = (byte & 0x2) != 0,
        .urg = (byte & 0x3) != 0,
        .ack = (byte & 0x4) != 0,
        .psh = (byte & 0x5) != 0,
        .rst = (byte & 0x6) != 0,
        .syn = (byte & 0x7) != 0,
        .fin = (byte & 0x8) != 0,
    };
}

pub fn readFromBytes(bytes: []const u8, totalLength: usize) TcpPacket {
    var packet: TcpPacket = undefined;
    var header: TcpHeader = undefined;

    // bits already in right order, so pass "big-endian" to do nothing
    header.sourcePort = std.mem.readInt(u16, bytes[0..2], .big);
    header.destinationPort = std.mem.readInt(u16, bytes[2..4], .big);
    header.sequenceNumber = std.mem.readInt(u32, bytes[4..8], .big);
    header.ackNumber = std.mem.readInt(u32, bytes[8..12], .big);
    header.headerLength = @truncate(bytes[12]);
    header.flags = tcpFlagsFromBytes(bytes[13]);
    header.windowSize = std.mem.readInt(u16, bytes[14..16], .big);
    header.checksum = std.mem.readInt(u16, bytes[16..18], .big);
    header.urgentPointer = std.mem.readInt(u16, bytes[18..20], .big);

    packet.header = header;
    packet.payload = bytes[header.headerLength..totalLength];

    return packet;
}
