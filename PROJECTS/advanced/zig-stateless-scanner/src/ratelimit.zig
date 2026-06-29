// ©AngelaMos | 2026
// ratelimit.zig

const std = @import("std");

const NS_PER_SEC: u64 = 1_000_000_000;

pub const TokenBucket = struct {
    step_ns: u64,
    cap_ns: u64,
    bank_ns: u64,
    last_ns: u64,

    pub fn init(rate_pps: u64, capacity: u64) TokenBucket {
        const step = if (rate_pps == 0) NS_PER_SEC else NS_PER_SEC / rate_pps;
        const safe_step = if (step == 0) 1 else step;
        return .{
            .step_ns = safe_step,
            .cap_ns = safe_step * capacity,
            .bank_ns = 0,
            .last_ns = 0,
        };
    }

    pub fn takeBatch(self: *TokenBucket, now_ns: u64, want: u64) u64 {
        if (now_ns > self.last_ns) {
            const elapsed = now_ns - self.last_ns;
            self.bank_ns = @min(self.bank_ns +| elapsed, self.cap_ns);
        }
        self.last_ns = now_ns;
        const available = self.bank_ns / self.step_ns;
        const granted = @min(want, available);
        self.bank_ns -= granted * self.step_ns;
        return granted;
    }
};

test "bucket starts empty and grants one token per step_ns" {
    var tb = TokenBucket.init(1000, 10);
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(0, 5));
    try std.testing.expectEqual(@as(u64, 1), tb.takeBatch(1_000_000, 5));
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(1_500_000, 5));
    try std.testing.expectEqual(@as(u64, 1), tb.takeBatch(2_000_000, 5));
}

test "burst is capped at capacity" {
    var tb = TokenBucket.init(1000, 10);
    try std.testing.expectEqual(@as(u64, 10), tb.takeBatch(1_000_000_000, 1000));
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(1_000_000_000, 1000));
}

test "takeBatch grants only up to want" {
    var tb = TokenBucket.init(1_000_000, 100);
    try std.testing.expectEqual(@as(u64, 50), tb.takeBatch(100_000, 50));
    try std.testing.expectEqual(@as(u64, 50), tb.takeBatch(100_000, 50));
}

test "non-monotonic now does not over-credit" {
    var tb = TokenBucket.init(1000, 10);
    try std.testing.expectEqual(@as(u64, 1), tb.takeBatch(1_000_000, 5));
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(500_000, 5));
}

test "zero rate degrades to one-token-per-second, never divides by zero" {
    var tb = TokenBucket.init(0, 4);
    try std.testing.expectEqual(@as(u64, 1), tb.takeBatch(NS_PER_SEC, 10));
    try std.testing.expectEqual(@as(u64, 4), tb.takeBatch(NS_PER_SEC * 10, 10));
}
