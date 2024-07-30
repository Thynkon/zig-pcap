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
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    ack_number: u32,
    header_length: u4,
    flags: TcpFlags,
    window_size: u16,
    checksum: u32,
    urgent_pointer: u32,
    // TODO: implement options
};

pub const TcpPacket = struct {
    header: TcpHeader,
    payload: []const u8,

    pub fn print(self: TcpPacket, _: std.mem.Allocator) void {
        std.debug.print("TCP Header:\n", .{});
        std.debug.print("  Source Port: {d}\n", .{self.header.source_port});
        std.debug.print("  Destination Port: {d}\n", .{self.header.destination_port});
        std.debug.print("  Sequence Number: {d}\n", .{self.header.sequence_number});
        std.debug.print("  Acknowledgment Number: {d}\n", .{self.header.ack_number});
        std.debug.print("  Header Length: {d}\n", .{self.header.header_length});
        std.debug.print("  Flags: {s}\n", .{self.header.flags.toString()});
        std.debug.print("  Window Size: {d}\n", .{self.header.window_size});
        std.debug.print("  Checksum: 0x{x}\n", .{self.header.checksum});
        std.debug.print("  Urgent Pointer: {d}\n\n\n", .{self.header.urgent_pointer});
    }

    pub fn readFromBytes(bytes: []const u8, total_length: usize) TcpPacket {
        var packet: TcpPacket = undefined;
        var header: TcpHeader = undefined;

        // bits already in right order, so pass "big-endian" to do nothing
        header.source_port = std.mem.readInt(u16, bytes[0..2], .big);
        header.destination_port = std.mem.readInt(u16, bytes[2..4], .big);
        header.sequence_number = std.mem.readInt(u32, bytes[4..8], .big);
        header.ack_number = std.mem.readInt(u32, bytes[8..12], .big);
        header.header_length = @truncate(bytes[12]);
        header.flags = tcpFlagsFromBytes(bytes[13]);
        header.window_size = std.mem.readInt(u16, bytes[14..16], .big);
        header.checksum = std.mem.readInt(u16, bytes[16..18], .big);
        header.urgent_pointer = std.mem.readInt(u16, bytes[18..20], .big);

        packet.header = header;
        packet.payload = bytes[header.header_length..total_length];

        return packet;
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
