// ©AngelaMos | 2026
// netutil.zig

const std = @import("std");
const linux = std.os.linux;

pub fn getFlag(args: []const []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 1 < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], name)) return args[i + 1];
    }
    return null;
}

pub fn hasFlag(args: []const []const u8, name: []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, name)) return true;
    }
    return false;
}

pub fn parseIpv4(text: []const u8) !u32 {
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

pub fn parseMac(text: []const u8) ![6]u8 {
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

pub fn parsePorts(allocator: std.mem.Allocator, text: []const u8) ![]u16 {
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

pub fn resolveSrcIp(ifname: []const u8) !u32 {
    const sa = try ifaceQuery(ifname, linux.SIOCGIFADDR);
    return std.mem.readInt(u32, sa.data[2..6], .big);
}

pub fn resolveSrcMac(ifname: []const u8) ![6]u8 {
    const sa = try ifaceQuery(ifname, linux.SIOCGIFHWADDR);
    return sa.data[0..6].*;
}

pub const RealClock = struct {
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

test "hasFlag detects a valueless boolean flag in any position" {
    const args = [_][]const u8{ "scan", "--target", "10.0.0.0/24", "--json" };
    try std.testing.expect(hasFlag(&args, "--json"));
    try std.testing.expect(hasFlag(&args, "scan"));
    try std.testing.expect(!hasFlag(&args, "--nope"));
}
