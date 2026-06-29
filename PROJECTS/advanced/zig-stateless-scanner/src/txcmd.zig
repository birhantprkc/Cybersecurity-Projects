// ©AngelaMos | 2026
// txcmd.zig

const std = @import("std");
const linux = std.os.linux;
const targets = @import("targets");
const template = @import("template");
const ratelimit = @import("ratelimit");
const afpacket = @import("afpacket");
const cookie = @import("cookie");
const tx = @import("tx");

const default_iface = "lo";
const default_rate: u64 = 10_000;
const default_src_port: u16 = 40_000;
const default_ports = [_]u16{80};

const RealClock = struct {
    pub fn now(_: *RealClock) u64 {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
    }
    pub fn sleepNs(_: *RealClock, ns: u64) void {
        const ts = linux.timespec{
            .sec = @intCast(ns / 1_000_000_000),
            .nsec = @intCast(ns % 1_000_000_000),
        };
        _ = linux.nanosleep(&ts, null);
    }
};

fn getFlag(args: []const []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 1 < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], name)) return args[i + 1];
    }
    return null;
}

fn parseIpv4(text: []const u8) !u32 {
    var addr: u32 = 0;
    var octets: usize = 0;
    var it = std.mem.splitScalar(u8, text, '.');
    while (it.next()) |part| {
        if (octets == 4) return error.InvalidIpv4;
        const octet = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIpv4;
        addr = (addr << 8) | octet;
        octets += 1;
    }
    if (octets != 4) return error.InvalidIpv4;
    return addr;
}

fn parseMac(text: []const u8) ![6]u8 {
    var mac: [6]u8 = undefined;
    var octets: usize = 0;
    var it = std.mem.splitScalar(u8, text, ':');
    while (it.next()) |part| {
        if (octets == 6) return error.InvalidMac;
        mac[octets] = std.fmt.parseInt(u8, part, 16) catch return error.InvalidMac;
        octets += 1;
    }
    if (octets != 6) return error.InvalidMac;
    return mac;
}

fn parsePorts(allocator: std.mem.Allocator, text: []const u8) ![]u16 {
    var list: std.ArrayList(u16) = .empty;
    errdefer list.deinit(allocator);
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        const port = std.fmt.parseInt(u16, part, 10) catch return error.InvalidPort;
        try list.append(allocator, port);
    }
    if (list.items.len == 0) return error.InvalidPort;
    return list.toOwnedSlice(allocator);
}

fn ifaceQuery(ifname: []const u8, request: u32) !linux.sockaddr {
    const rc_sock = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    if (linux.errno(rc_sock) != .SUCCESS) return error.ResolveSocketFailed;
    const fd: i32 = @intCast(rc_sock);
    defer _ = linux.close(fd);

    var ifr = std.mem.zeroes(linux.ifreq);
    if (ifname.len >= ifr.ifrn.name.len) return error.IfNameTooLong;
    @memcpy(ifr.ifrn.name[0..ifname.len], ifname);
    if (linux.errno(linux.ioctl(fd, request, @intFromPtr(&ifr))) != .SUCCESS) return error.IfQueryFailed;
    return ifr.ifru.addr;
}

fn resolveSrcIp(ifname: []const u8) !u32 {
    const sa = try ifaceQuery(ifname, linux.SIOCGIFADDR);
    return std.mem.readInt(u32, sa.data[2..6], .big);
}

fn resolveSrcMac(ifname: []const u8) ![6]u8 {
    const sa = try ifaceQuery(ifname, linux.SIOCGIFHWADDR);
    return sa.data[0..6].*;
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    var buf: [512]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;

    const target_text = getFlag(args, "--target") orelse {
        try out.writeAll("tx: --target <cidr> is required (e.g. --target 10.0.0.0/24)\n");
        try out.flush();
        return;
    };
    const ifname = getFlag(args, "--iface") orelse default_iface;
    const rate = if (getFlag(args, "--rate")) |r| try std.fmt.parseInt(u64, r, 10) else default_rate;
    const src_port = if (getFlag(args, "--src-port")) |p| try std.fmt.parseInt(u16, p, 10) else default_src_port;

    const ports = if (getFlag(args, "--ports")) |p| try parsePorts(allocator, p) else try allocator.dupe(u16, &default_ports);
    const gw_mac = if (getFlag(args, "--gw-mac")) |m| try parseMac(m) else [_]u8{0} ** 6;
    const src_ip = if (getFlag(args, "--src-ip")) |s| try parseIpv4(s) else try resolveSrcIp(ifname);
    const src_mac = try resolveSrcMac(ifname);

    var seed: u64 = undefined;
    if (getFlag(args, "--seed")) |s| {
        seed = try std.fmt.parseInt(u64, s, 10);
    } else {
        var seed_bytes: [8]u8 = undefined;
        try io.randomSecure(&seed_bytes);
        seed = std.mem.readInt(u64, &seed_bytes, .little);
    }

    const cidr = try targets.parseCidr(target_text);
    var eng = try targets.Engine.init(allocator, &.{cidr}, ports, seed);
    defer eng.deinit();

    const count = if (getFlag(args, "--count")) |c| try std.fmt.parseInt(u64, c, 10) else eng.total;

    const ck = try cookie.Cookie.random(io);
    const tmpl = template.SynTemplate.init(.{
        .src_mac = src_mac,
        .dst_mac = gw_mac,
        .src_ip = src_ip,
        .src_port = src_port,
        .cookie = ck,
    });
    var bucket = ratelimit.TokenBucket.init(rate, rate);

    var backend = afpacket.Backend.open(ifname, .{}) catch |err| switch (err) {
        error.NeedCapNetRaw => {
            try out.writeAll("tx: need CAP_NET_RAW + CAP_NET_ADMIN. Grant once, then re-run (no sudo):\n  sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/zingela\nSkipping.\n");
            try out.flush();
            return;
        },
        else => return err,
    };
    defer backend.close();

    var clock = RealClock{};
    const t0 = clock.now();
    const sent = tx.run(&eng, &tmpl, &bucket, &backend, &clock, count);
    const elapsed_ns = clock.now() - t0;

    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
    const pps = if (elapsed_s > 0) @as(f64, @floatFromInt(sent)) / elapsed_s else 0;
    try out.print("tx: sent {d} SYN frames on {s} in {d:.3}s ({d:.0} pps)\n", .{ sent, ifname, elapsed_s, pps });
    try out.flush();
}

test "parseIpv4 round-trips dotted quads" {
    try std.testing.expectEqual(@as(u32, 0x7f000001), try parseIpv4("127.0.0.1"));
    try std.testing.expectEqual(@as(u32, 0x08080808), try parseIpv4("8.8.8.8"));
    try std.testing.expectError(error.InvalidIpv4, parseIpv4("1.2.3"));
    try std.testing.expectError(error.InvalidIpv4, parseIpv4("256.0.0.1"));
}

test "parseMac parses colon-separated hex" {
    try std.testing.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, try parseMac("aa:bb:cc:dd:ee:ff"));
    try std.testing.expectEqual([_]u8{0} ** 6, try parseMac("00:00:00:00:00:00"));
    try std.testing.expectError(error.InvalidMac, parseMac("aa:bb:cc"));
}

test "parsePorts parses a comma list and rejects empty" {
    const ports = try parsePorts(std.testing.allocator, "80,443,22");
    defer std.testing.allocator.free(ports);
    try std.testing.expectEqualSlices(u16, &.{ 80, 443, 22 }, ports);
    try std.testing.expectError(error.InvalidPort, parsePorts(std.testing.allocator, ""));
}

test "getFlag finds values and tolerates missing" {
    const args = [_][]const u8{ "tx", "--iface", "eth0", "--rate", "5000" };
    try std.testing.expectEqualStrings("eth0", getFlag(&args, "--iface").?);
    try std.testing.expectEqualStrings("5000", getFlag(&args, "--rate").?);
    try std.testing.expect(getFlag(&args, "--target") == null);
}
