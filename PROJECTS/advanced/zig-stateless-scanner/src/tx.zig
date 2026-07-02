// ©AngelaMos | 2026
// tx.zig

const std = @import("std");
const targets = @import("targets");
const template = @import("template");
const ratelimit = @import("ratelimit");
const cookie = @import("cookie");
const packet = @import("packet");

pub fn run(
    engine: *targets.Engine,
    tmpl: *const template.SynTemplate,
    bucket: *ratelimit.TokenBucket,
    sink: anytype,
    clock: anytype,
    max_packets: u64,
    deadline_ns: u64,
) u64 {
    _ = bucket.takeBatch(clock.now(), 0);
    var sent: u64 = 0;
    var frame: [template.SynTemplate.frame_len]u8 = undefined;

    var pending: ?targets.Target = engine.next();
    while (pending != null and sent < max_packets) {
        const now_ns = clock.now();
        if (now_ns >= deadline_ns) break;
        const granted = bucket.takeBatch(now_ns, max_packets - sent);
        if (granted == 0) {
            clock.sleepNs(bucket.step_ns);
            continue;
        }
        var n: u64 = 0;
        while (n < granted) : (n += 1) {
            const t = pending orelse break;
            tmpl.stamp(&frame, t.ip, t.port);
            if (!sink.submit(&frame)) {
                @branchHint(.unlikely);
                sink.kick();
                if (!sink.submit(&frame)) break;
            }
            sent += 1;
            pending = engine.next();
            if (pending == null) break;
        }
        sink.kick();
    }
    sink.kick();
    return sent;
}

const FakeClock = struct {
    t: u64 = 0,
    fn now(self: *FakeClock) u64 {
        self.t += 1_000_000_000;
        return self.t;
    }
    fn sleepNs(self: *FakeClock, ns: u64) void {
        self.t += ns;
    }
};

const FakeSink = struct {
    frames: std.ArrayList([54]u8) = .empty,
    kicks: usize = 0,
    allocator: std.mem.Allocator,
    fn submit(self: *FakeSink, frame: []const u8) bool {
        self.frames.append(self.allocator, frame[0..54].*) catch return false;
        return true;
    }
    fn kick(self: *FakeSink) void {
        self.kicks += 1;
    }
};

test "the TX engine drives the M2 bijection through stamp + ratelimit + submit" {
    const test_key = [16]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.8.0/30")};
    const ports = [_]u16{ 80, 443 };
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 0xDEADBEEF);
    defer eng.deinit();

    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
    });
    var tb = ratelimit.TokenBucket.init(1000, 64);
    var clock = FakeClock{};
    var sink = FakeSink{ .allocator = std.testing.allocator };
    defer sink.frames.deinit(std.testing.allocator);

    const sent = run(&eng, &tmpl, &tb, &sink, &clock, 1_000_000, std.math.maxInt(u64));
    try std.testing.expectEqual(@as(u64, 8), sent);
    try std.testing.expectEqual(@as(usize, 8), sink.frames.items.len);
    try std.testing.expect(sink.kicks >= 1);

    var seen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer seen.deinit();
    for (sink.frames.items) |*f| {
        try std.testing.expectEqual(@as(u16, 0), packet.checksum(f[14..34]));
        const ip = std.mem.readInt(u32, f[30..34], .big);
        const port = std.mem.readInt(u16, f[36..38], .big);
        try std.testing.expect(!targets.isReserved(ip));
        const key = (@as(u64, ip) << 16) | port;
        try std.testing.expect(!seen.contains(key));
        try seen.put(key, {});
    }
    try std.testing.expectEqual(@as(usize, 8), seen.count());
}

test "max_packets caps the send count below the target total" {
    const test_key = [_]u8{0} ** 16;
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.8.0/28")};
    const ports = [_]u16{ 80, 443, 22 };
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 0x1234);
    defer eng.deinit();

    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
    });
    var tb = ratelimit.TokenBucket.init(1000, 64);
    var clock = FakeClock{};
    var sink = FakeSink{ .allocator = std.testing.allocator };
    defer sink.frames.deinit(std.testing.allocator);

    const sent = run(&eng, &tmpl, &tb, &sink, &clock, 5, std.math.maxInt(u64));
    try std.testing.expectEqual(@as(u64, 5), sent);
    try std.testing.expectEqual(@as(usize, 5), sink.frames.items.len);
}

const StuckSink = struct {
    kicks: usize = 0,
    fn submit(_: *StuckSink, _: []const u8) bool {
        return false;
    }
    fn kick(self: *StuckSink) void {
        self.kicks += 1;
    }
};

test "run bails at the deadline when the sink never drains (stall watchdog)" {
    const test_key = [_]u8{0} ** 16;
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.8.0/28")};
    const ports = [_]u16{80};
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 0x1234);
    defer eng.deinit();

    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
    });
    var tb = ratelimit.TokenBucket.init(1000, 64);
    var clock = FakeClock{};
    var sink = StuckSink{};

    const sent = run(&eng, &tmpl, &tb, &sink, &clock, 1_000_000, 5_000_000_000);
    try std.testing.expectEqual(@as(u64, 0), sent);
    try std.testing.expect(sink.kicks >= 1);
}
