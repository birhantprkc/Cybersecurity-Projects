// ©AngelaMos | 2026
// packet.zig

const std = @import("std");
const builtin = @import("builtin");

pub const EthHdr = extern struct {
    dst: [6]u8,
    src: [6]u8,
    ethertype: u16,
};

pub const Ipv4Hdr = extern struct {
    version_ihl: u8,
    tos: u8,
    total_len: u16,
    id: u16,
    flags_frag: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: u32,
    dst: u32,
};

pub const TcpHdr = extern struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_off_ns: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent: u16,
};

comptime {
    std.debug.assert(@sizeOf(EthHdr) == 14);
    std.debug.assert(@sizeOf(Ipv4Hdr) == 20);
    std.debug.assert(@sizeOf(TcpHdr) == 20);
}

pub fn checksum(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        const word = (@as(u16, bytes[i]) << 8) | @as(u16, bytes[i + 1]);
        sum += word;
    }
    if (i < bytes.len) {
        sum += @as(u32, bytes[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

pub fn checksumSimd(bytes: []const u8) u16 {
    const lanes = comptime (std.simd.suggestVectorLength(u16) orelse 8);
    const stride = lanes * 2;
    const native_le = builtin.cpu.arch.endian() == .little;

    var acc: @Vector(lanes, u32) = @splat(0);
    var i: usize = 0;
    while (i + stride <= bytes.len) : (i += stride) {
        const block: [stride]u8 = bytes[i..][0..stride].*;
        var words: @Vector(lanes, u16) = @bitCast(block);
        if (native_le) words = @byteSwap(words);
        acc += @as(@Vector(lanes, u32), words);
    }

    var sum: u32 = @reduce(.Add, acc);
    while (i + 1 < bytes.len) : (i += 2) {
        sum += (@as(u32, bytes[i]) << 8) | @as(u32, bytes[i + 1]);
    }
    if (i < bytes.len) {
        sum += @as(u32, bytes[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

pub fn incrementalUpdate(old_check: u16, old_word: u16, new_word: u16) u16 {
    var sum: u32 = @as(u32, ~old_check) + @as(u32, ~old_word) + @as(u32, new_word);
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

pub fn tcpChecksum(src_be: u32, dst_be: u32, segment: []const u8) u16 {
    var pseudo: [12]u8 = undefined;
    @memcpy(pseudo[0..4], std.mem.asBytes(&src_be));
    @memcpy(pseudo[4..8], std.mem.asBytes(&dst_be));
    pseudo[8] = 0;
    pseudo[9] = 6;
    std.mem.writeInt(u16, pseudo[10..12], @intCast(segment.len), .big);

    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < pseudo.len) : (i += 2) {
        sum += (@as(u32, pseudo[i]) << 8) | @as(u32, pseudo[i + 1]);
    }
    i = 0;
    while (i + 1 < segment.len) : (i += 2) {
        sum += (@as(u32, segment[i]) << 8) | @as(u32, segment[i + 1]);
    }
    if (i < segment.len) {
        sum += @as(u32, segment[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

test "header sizes are wire-exact" {
    try std.testing.expectEqual(@as(usize, 14), @sizeOf(EthHdr));
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(Ipv4Hdr));
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(TcpHdr));
}

test "RFC 1071 checksum matches the canonical IPv4 KAT (0xb861)" {
    const hdr = [_]u8{
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    };
    try std.testing.expectEqual(@as(u16, 0xb861), checksum(&hdr));
}

test "SIMD checksum matches the canonical IPv4 KAT (0xb861)" {
    const hdr = [_]u8{
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    };
    try std.testing.expectEqual(@as(u16, 0xb861), checksumSimd(&hdr));
}

test "SIMD checksum equals scalar checksum for every length 0..256" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1624_517A);
    const rand = prng.random();
    var buf: [256]u8 = undefined;
    var len: usize = 0;
    while (len <= 256) : (len += 1) {
        rand.bytes(buf[0..len]);
        try std.testing.expectEqual(checksum(buf[0..len]), checksumSimd(buf[0..len]));
    }
}

test "RFC 1624 incremental update matches the RFC section 4 worked example" {
    try std.testing.expectEqual(@as(u16, 0x0000), incrementalUpdate(0xDD2F, 0x5555, 0x3285));
}

test "incremental update equals a full recompute for random single-word edits" {
    var prng = std.Random.DefaultPrng.init(0x1624_DEAD_BEEF_0001);
    const rand = prng.random();
    var hdr: [20]u8 = undefined;
    var trial: usize = 0;
    while (trial < 4096) : (trial += 1) {
        rand.bytes(&hdr);
        std.mem.writeInt(u16, hdr[10..12], 0, .big);
        const old_check = checksum(&hdr);
        const word_index = rand.uintLessThan(usize, 9) * 2;
        const off = if (word_index >= 10) word_index + 2 else word_index;
        const old_word = std.mem.readInt(u16, hdr[off..][0..2], .big);
        const new_word = rand.int(u16);
        std.mem.writeInt(u16, hdr[off..][0..2], new_word, .big);
        const full = checksum(&hdr);
        try std.testing.expectEqual(full, incrementalUpdate(old_check, old_word, new_word));
    }
}

test "tcpChecksum self-verifies: a segment with its correct checksum folds to 0" {
    var tcp = TcpHdr{
        .src_port = std.mem.nativeToBig(u16, 54321),
        .dst_port = std.mem.nativeToBig(u16, 80),
        .seq = std.mem.nativeToBig(u32, 0xdead_beef),
        .ack = 0,
        .data_off_ns = 0x50,
        .flags = 0x02,
        .window = std.mem.nativeToBig(u16, 1024),
        .checksum = 0,
        .urgent = 0,
    };
    const src = std.mem.nativeToBig(u32, 0x7f000001);
    const dst = std.mem.nativeToBig(u32, 0x7f000001);
    tcp.checksum = std.mem.nativeToBig(u16, tcpChecksum(src, dst, std.mem.asBytes(&tcp)));
    try std.testing.expectEqual(@as(u16, 0), tcpChecksum(src, dst, std.mem.asBytes(&tcp)));
}
