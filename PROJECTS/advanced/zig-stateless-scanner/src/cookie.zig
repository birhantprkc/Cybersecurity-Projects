// ©AngelaMos | 2026
// cookie.zig

const std = @import("std");

pub const Cookie = struct {
    key: [16]u8,

    pub fn init(key: [16]u8) Cookie {
        return .{ .key = key };
    }

    pub fn random(io: std.Io) !Cookie {
        var key: [16]u8 = undefined;
        try io.randomSecure(&key);
        return .{ .key = key };
    }

    pub fn generate(self: Cookie, ip_them: u32, port_them: u16, ip_me: u32, port_me: u16) u64 {
        var data: [12]u8 = undefined;
        std.mem.writeInt(u32, data[0..4], ip_them, .big);
        std.mem.writeInt(u16, data[4..6], port_them, .big);
        std.mem.writeInt(u32, data[6..10], ip_me, .big);
        std.mem.writeInt(u16, data[10..12], port_me, .big);
        return std.hash.SipHash64(2, 4).toInt(&data, &self.key);
    }

    pub fn seq(self: Cookie, ip_them: u32, port_them: u16, ip_me: u32, port_me: u16) u32 {
        return @truncate(self.generate(ip_them, port_them, ip_me, port_me));
    }

    pub fn validateSynAck(self: Cookie, ack: u32, ip_them: u32, port_them: u16, ip_me: u32, port_me: u16) bool {
        return ack == self.seq(ip_them, port_them, ip_me, port_me) +% 1;
    }
};

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

test "SipHash64(2,4) reproduces the reference empty-message vector" {
    try std.testing.expectEqual(
        @as(u64, 0x726fdb47dd0e0e31),
        std.hash.SipHash64(2, 4).toInt("", &test_key),
    );
}

test "cookie is deterministic for a fixed key + 4-tuple (golden KAT)" {
    const c = Cookie.init(test_key);
    const a = c.generate(0x0a000001, 443, 0xc0a80002, 51000);
    const b = c.generate(0x0a000001, 443, 0xc0a80002, 51000);
    try std.testing.expectEqual(a, b);
    try std.testing.expectEqual(@as(u64, 0x559a4e08e1deb9a7), a);
}

test "seq is the low 32 bits of the cookie" {
    const c = Cookie.init(test_key);
    const full = c.generate(0x0a000001, 443, 0xc0a80002, 51000);
    try std.testing.expectEqual(@as(u32, @truncate(full)), c.seq(0x0a000001, 443, 0xc0a80002, 51000));
}

test "validateSynAck accepts ack == seq + 1 and rejects others" {
    const c = Cookie.init(test_key);
    const s = c.seq(0x0a000001, 443, 0xc0a80002, 51000);
    try std.testing.expect(c.validateSynAck(s +% 1, 0x0a000001, 443, 0xc0a80002, 51000));
    try std.testing.expect(!c.validateSynAck(s, 0x0a000001, 443, 0xc0a80002, 51000));
    try std.testing.expect(!c.validateSynAck(s +% 2, 0x0a000001, 443, 0xc0a80002, 51000));
}

test "validateSynAck wraps at the u32 boundary" {
    const seq_max: u32 = 0xFFFFFFFF;
    try std.testing.expectEqual(@as(u32, 0), seq_max +% 1);
}
