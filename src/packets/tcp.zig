const std = @import("std");
const pcap = @cImport({
    @cInclude("pcap.h");
    @cInclude("pcap/pcap.h");
});
const builtin = @import("builtin");
const ipv4 = @import("ipv4.zig");
const native_endian = builtin.target.cpu.arch.endian();

const PcapWrapperError = error{
    UnintializedError,
    PcapError,
};

const TcpFlags = packed struct(u8) {
    fin: bool,
    syn: bool,
    rst: bool,
    psh: bool,
    ack: bool,
    urg: bool,
    ece: bool,
    cwr: bool,

    pub fn toString(self: TcpFlags, allocator: std.mem.Allocator) ![]const u8 {
        var result = std.ArrayList(u8).init(allocator);
        defer {
            if (result.capacity == 0) {
                result.deinit();
            }
        }

        const flag_strings = [_][]const u8{
            "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR",
        };

        const flag_masks: [8]u8 = [_]u8{
            0x01, // FIN
            0x02, // SYN
            0x04, // RST
            0x08, // PSH
            0x10, // ACK
            0x20, // URG
            0x40, // ECE
            0x80, // CWR
        };

        const flags: u8 = @bitCast(self);
        for (flag_strings, 0..) |flag, i| {
            if ((flags & flag_masks[i]) != 0) {
                if (result.items.len != 0) {
                    try result.appendSlice(" ");
                }

                try result.appendSlice(flag);
            }
        }

        return result.toOwnedSlice();
    }
};

const TcpHeader = struct {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    ack_number: u32,
    offset: u6, // header length, original specifies the length in 32-bit words (divided by 4)
    reserved: u4,
    flags: TcpFlags,
    window_size: u16,
    checksum: u32,
    urgent_pointer: u32,
    // TODO: implement options
};

pub const TcpPacket = struct {
    header: TcpHeader,
    payload: []const u8,

    pub fn print(self: TcpPacket, allocator: std.mem.Allocator) !void {
        const flags = try self.header.flags.toString(allocator);
        defer allocator.free(flags);

        std.debug.print("TCP Header:\n", .{});
        std.debug.print("  Source Port: {d}\n", .{self.header.source_port});
        std.debug.print("  Destination Port: {d}\n", .{self.header.destination_port});
        std.debug.print("  Sequence Number: {d}\n", .{self.header.sequence_number});
        std.debug.print("  Acknowledgment Number: {d}\n", .{self.header.ack_number});
        std.debug.print("  Header Length: {d}\n", .{self.header.offset});
        std.debug.print("  Flags: {s}\n", .{flags});
        std.debug.print("  Window Size: {d}\n", .{self.header.window_size});
        std.debug.print("  Checksum: 0x{x}\n", .{self.header.checksum});
        std.debug.print("  Urgent Pointer: {d}\n\n\n", .{self.header.urgent_pointer});
    }

    pub fn tcpFlagsFromBytes(byte: u8) TcpFlags {
        return TcpFlags{
            .fin = (byte & 0x1) != 0,
            .syn = (byte & 0x2) != 0,
            .rst = (byte & 0x4) != 0,
            .psh = (byte & 0x8) != 0,
            .ack = (byte & 0x10) != 0,
            .urg = (byte & 0x20) != 0,
            .ece = (byte & 0x40) != 0,
            .cwr = (byte & 0x80) != 0,
        };
    }

    pub fn readFromBytes(bytes: []const u8, total_length: usize) TcpPacket {
        var packet: TcpPacket = undefined;
        var header: TcpHeader = undefined;

        // bits already in right order, so pass "big-endian" to do nothing
        header.source_port = std.mem.readInt(u16, bytes[0..2], .big);
        header.destination_port = std.mem.readInt(u16, bytes[2..4], .big);
        header.sequence_number = std.mem.readInt(u32, bytes[4..8], .big);
        header.ack_number = std.mem.readInt(u32, bytes[8..12], .big);
        if (native_endian == .big) {
            header.offset = @intCast(bytes[12] & 0x0F);
            header.reserved = @intCast(bytes[12] >> 4);
        } else {
            header.offset = @intCast(bytes[12] >> 4);
            header.reserved = @intCast(bytes[12] & 0x0F);
        }
        header.offset *= 4;
        header.flags = tcpFlagsFromBytes(bytes[13]);
        header.window_size = std.mem.readInt(u16, bytes[14..16], .big);
        header.checksum = std.mem.readInt(u16, bytes[16..18], .big);
        header.urgent_pointer = std.mem.readInt(u16, bytes[18..20], .big);

        packet.header = header;
        packet.payload = bytes[@as(usize, @intCast(header.offset))..total_length];

        return packet;
    }
};
