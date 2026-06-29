// ©AngelaMos | 2026
// template.zig

const std = @import("std");
const packet = @import("packet");
const cookie = @import("cookie");

const ethertype_ipv4: u16 = 0x0800;
const ipv4_version_ihl: u8 = 0x45;
const ip_proto_tcp: u8 = 6;
const ip_total_len: u16 = 40;
const ip_flag_dont_fragment: u16 = 0x4000;
const default_ttl: u8 = 64;
const tcp_data_offset: u8 = 0x50;
const tcp_flag_syn: u8 = 0x02;
const default_window: u16 = 1024;

pub const SynTemplate = struct {
    pub const frame_len: usize = 54;

    base: [frame_len]u8,
    src_ip_be: u32,
    src_port: u16,
    cookie: cookie.Cookie,

    pub const Config = struct {
        src_mac: [6]u8,
        dst_mac: [6]u8,
        src_ip: u32,
        src_port: u16,
        cookie: cookie.Cookie,
    };

    pub fn init(cfg: Config) SynTemplate {
        var base: [frame_len]u8 = undefined;

        const eth = packet.EthHdr{
            .dst = cfg.dst_mac,
            .src = cfg.src_mac,
            .ethertype = std.mem.nativeToBig(u16, ethertype_ipv4),
        };
        @memcpy(base[0..14], std.mem.asBytes(&eth));

        const ip = packet.Ipv4Hdr{
            .version_ihl = ipv4_version_ihl,
            .tos = 0,
            .total_len = std.mem.nativeToBig(u16, ip_total_len),
            .id = 0,
            .flags_frag = std.mem.nativeToBig(u16, ip_flag_dont_fragment),
            .ttl = default_ttl,
            .protocol = ip_proto_tcp,
            .checksum = 0,
            .src = std.mem.nativeToBig(u32, cfg.src_ip),
            .dst = 0,
        };
        @memcpy(base[14..34], std.mem.asBytes(&ip));

        const tcp = packet.TcpHdr{
            .src_port = std.mem.nativeToBig(u16, cfg.src_port),
            .dst_port = 0,
            .seq = 0,
            .ack = 0,
            .data_off_ns = tcp_data_offset,
            .flags = tcp_flag_syn,
            .window = std.mem.nativeToBig(u16, default_window),
            .checksum = 0,
            .urgent = 0,
        };
        @memcpy(base[34..54], std.mem.asBytes(&tcp));

        return .{
            .base = base,
            .src_ip_be = std.mem.nativeToBig(u32, cfg.src_ip),
            .src_port = cfg.src_port,
            .cookie = cfg.cookie,
        };
    }

    pub fn stamp(self: *const SynTemplate, out: *[frame_len]u8, dst_ip: u32, dst_port: u16) void {
        @memcpy(out, &self.base);

        std.mem.writeInt(u32, out[30..34], dst_ip, .big);
        std.mem.writeInt(u16, out[24..26], 0, .big);
        const ip_ck = packet.checksum(out[14..34]);
        std.mem.writeInt(u16, out[24..26], ip_ck, .big);

        const src_ip = std.mem.bigToNative(u32, self.src_ip_be);
        const seq = self.cookie.seq(dst_ip, dst_port, src_ip, self.src_port);
        std.mem.writeInt(u16, out[36..38], dst_port, .big);
        std.mem.writeInt(u32, out[38..42], seq, .big);
        std.mem.writeInt(u16, out[50..52], 0, .big);
        const dst_be = std.mem.nativeToBig(u32, dst_ip);
        const tcp_ck = packet.tcpChecksum(self.src_ip_be, dst_be, out[34..54]);
        std.mem.writeInt(u16, out[50..52], tcp_ck, .big);
    }
};

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

test "stamped frame is 54 bytes with self-verifying IP and TCP checksums" {
    const ck = cookie.Cookie.init(test_key);
    const tmpl = SynTemplate.init(.{
        .src_mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .dst_mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 },
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = ck,
    });
    var frame: [SynTemplate.frame_len]u8 = undefined;
    tmpl.stamp(&frame, 0x08080808, 443);

    try std.testing.expectEqual(@as(usize, 54), frame.len);
    try std.testing.expectEqual(@as(u16, 0), packet.checksum(frame[14..34]));
    const ip_src = std.mem.nativeToBig(u32, 0x0a000001);
    const ip_dst = std.mem.nativeToBig(u32, 0x08080808);
    try std.testing.expectEqual(@as(u16, 0), packet.tcpChecksum(ip_src, ip_dst, frame[34..54]));
}

test "stamp writes the destination and the SipHash seq" {
    const ck = cookie.Cookie.init(test_key);
    const tmpl = SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = ck,
    });
    var frame: [SynTemplate.frame_len]u8 = undefined;
    tmpl.stamp(&frame, 0x08080808, 443);

    try std.testing.expectEqual(@as(u32, 0x08080808), std.mem.readInt(u32, frame[30..34], .big));
    try std.testing.expectEqual(@as(u16, 443), std.mem.readInt(u16, frame[36..38], .big));
    const want_seq = ck.seq(0x08080808, 443, 0x0a000001, 40000);
    try std.testing.expectEqual(want_seq, std.mem.readInt(u32, frame[38..42], .big));
}

test "two different targets produce two different seqs" {
    const ck = cookie.Cookie.init(test_key);
    const tmpl = SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = ck,
    });
    var a: [SynTemplate.frame_len]u8 = undefined;
    var b: [SynTemplate.frame_len]u8 = undefined;
    tmpl.stamp(&a, 0x08080808, 443);
    tmpl.stamp(&b, 0x08080808, 80);
    try std.testing.expect(!std.mem.eql(u8, a[38..42], b[38..42]));
}
