const std = @import("std");
const pcap = @cImport({
    @cInclude("pcap.h");
    @cInclude("pcap/pcap.h");
});

const PcapWrapperError = error{
    UnintializedError,
    PcapError,
};

pub const PcapWrapper = struct {
    device: []const u8,
    packet_count: u8 = 0,
    filter: []const u8,
    handle: ?*pcap.pcap_t = null,
    allocator: std.mem.Allocator,

    pub fn get_link_header_length(self: PcapWrapper) !u32 {
        if (self.handle == null) {
            std.log.err("Pcap handle was not initialized yet!", .{});
            return PcapWrapperError.UnintializedError;
        }

        var link_type: u32 = 0;
        var link_header_length: u32 = 0;

        // Determine the datalink layer type.
        link_type = @intCast(pcap.pcap_datalink(self.handle));
        if (link_type == pcap.PCAP_ERROR) {
            std.log.err("pcap_datalink: {s}", .{pcap.pcap_geterr(self.handle)});
            return PcapWrapperError.UnintializedError;
        }

        // Set the datalink layer header size.
        link_header_length = switch (link_type) {
            pcap.DLT_NULL => 4,
            pcap.DLT_EN10MB => 14,
            pcap.DLT_SLIP => 24,
            else => {
                std.log.err("Unsupported datalink: {d}\n", .{link_type});
                unreachable;
            },
        };

        return link_header_length;
    }

    pub fn start(self: *PcapWrapper) !void {
        var errbuff: [pcap.PCAP_ERRBUF_SIZE]u8 = undefined;
        var bpf = pcap.bpf_program{};
        var netmask: pcap.bpf_u_int32 = undefined;
        var src_ip: pcap.bpf_u_int32 = undefined;
        var h: ?*pcap.pcap_t = null;

        // Get network device source IP address and netmask.
        if (pcap.pcap_lookupnet(self.device.ptr, &src_ip, &netmask, &errbuff) == pcap.PCAP_ERROR) {
            std.log.err("pcap_lookupnet: {s}", .{errbuff});
            return PcapWrapperError.PcapError;
        }

        const BUFSIZ: u32 = 8192;

        // Open the device for live capture.
        h = pcap.pcap_open_live(self.device.ptr, BUFSIZ, 1, 1000, &errbuff);
        if (h == null) {
            std.log.err("pcap_open_live: {s}", .{errbuff});
            return PcapWrapperError.PcapError;
        }
        self.handle = h;
        h = null;

        // Convert the packet filter epxression into a packet filter binary.
        if (pcap.pcap_compile(self.handle, &bpf, self.filter.ptr, 0, netmask) ==
            pcap.PCAP_ERROR)
        {
            std.log.err("pcap_compile: {s}", .{pcap.pcap_geterr(self.handle)});
            return PcapWrapperError.PcapError;
        }

        // Bind the packet filter to the libpcap handle.
        if (pcap.pcap_setfilter(self.handle, &bpf) == pcap.PCAP_ERROR) {
            std.log.err("pcap_setfilter: {s}\n", .{pcap.pcap_geterr(self.handle)});
            return PcapWrapperError.PcapError;
        }
    }

    pub fn set_loop_callback(self: PcapWrapper, callback: pcap.pcap_handler) !void {
        if (pcap.pcap_loop(self.handle, self.packet_count, callback, @constCast(@ptrCast(@alignCast(&self)))) < 0) {
            std.log.err("pcap_loop failed: {s}", .{pcap.pcap_geterr(self.handle)});
            return PcapWrapperError.PcapError;
        }
    }

    pub fn deinit(self: PcapWrapper) void {
        if (self.handle != null) {
            pcap.pcap_close(self.handle);
        }

        self.allocator.free(self.device);
        self.allocator.free(self.filter);
    }
};
pub fn init() PcapWrapper {
    return PcapWrapper{};
}
