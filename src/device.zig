const std = @import("std");
const pcap = @cImport({
    @cInclude("pcap.h");
    @cInclude("pcap/pcap.h");
});
const cString = @cImport({
    @cInclude("string.h");
});
const wrapper = @import("pcap_wrapper.zig");
const ipv4_packet = @import("packets/ipv4.zig");

// TODO: Attach mesages fro errbuff to error messages
// Currently, there is no way to attach mesages/values to errvalues like in rust
const DeviceError = error{PcapError};

pub fn list_all(allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
    var result = std.ArrayList([]const u8).init(allocator);
    var alldevs: [*c]pcap.pcap_if_t = undefined;
    var errbuff: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;

    if (pcap.pcap_findalldevs(&alldevs, &errbuff) == pcap.PCAP_ERROR) {
        std.log.err("pcap error from pcap_findalldevs: {s}", .{errbuff});
        return DeviceError.PcapError;
    }
    defer pcap.pcap_freealldevs(alldevs);

    var d: [*c]pcap.pcap_if_t = alldevs;
    while (d != null) {
        const name = try allocator.dupe(u8, std.mem.span(d.*.name));
        try result.append(name);

        d = d.*.next;
    }

    return result;
}

fn packet_handler(user: [*c]u8, packet_header: [*c]const pcap.pcap_pkthdr, packet: [*c]const u8) callconv(.C) void {
    const pcap_wrapper = @as(*wrapper.PcapWrapper, @ptrCast(@alignCast(user))).*;
    const pkt: [*]const u8 = packet;

    const frame_length: usize = @intCast(packet_header.*.len);
    std.debug.print("Total length: {d}\n", .{frame_length});

    const link_header_length = pcap_wrapper.get_link_header_length() catch unreachable;
    const frame_header_slice: []const u8 = pkt[0..link_header_length];

    std.debug.print("Frame header: ", .{});
    for (frame_header_slice) |byte| {
        std.debug.print("{x:0>2} ", .{byte});
    }
    std.debug.print("\n\n", .{});

    const ip_slice: []const u8 = pkt[link_header_length..frame_length];
    std.debug.print("IP data: ", .{});
    for (ip_slice) |byte| {
        std.debug.print("{x:0>2} ", .{byte});
    }
    std.debug.print("\n\n\n", .{});
}

pub fn capture(allocator: std.mem.Allocator, device: []const u8, filter: []const u8) !void {
    var pcap_wrapper = wrapper.PcapWrapper{ .allocator = allocator, .device = device, .filter = filter, .packet_count = 0 };
    try pcap_wrapper.start();
    defer pcap_wrapper.deinit();

    try pcap_wrapper.set_loop_callback(packet_handler);
}
