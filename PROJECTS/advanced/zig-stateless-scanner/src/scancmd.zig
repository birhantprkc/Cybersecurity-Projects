// ©AngelaMos | 2026
// scancmd.zig

const std = @import("std");
const targets = @import("targets");
const template = @import("template");
const ratelimit = @import("ratelimit");
const afpacket = @import("afpacket");
const cookie = @import("cookie");
const tx = @import("tx");
const rx = @import("rx");
const dedup = @import("dedup");
const netutil = @import("netutil");
const output = @import("output");

const default_iface = "lo";
const default_rate: u64 = 10_000;
const default_src_port: u16 = 40_000;
const default_wait_ms: i32 = 2_000;
const ns_per_ms: u64 = 1_000_000;
const ns_per_sec: u64 = 1_000_000_000;
const default_ports = [_]u16{80};
const dedup_capacity: usize = 1024;
const queue_capacity: usize = 2048;
const drain_batch: usize = 256;
const drain_tick_ns: u64 = 50 * ns_per_ms;
const render_tick_interactive_ns: u64 = 125 * ns_per_ms;
const render_tick_plain_ns: u64 = 1_000 * ns_per_ms;
const rx_hard_cap_floor_ns: u64 = 60 * ns_per_sec;
const min_dashboard_cols: u16 = 64;

const need_cap_hint =
    "scan: need CAP_NET_RAW + CAP_NET_ADMIN. Grant once, then re-run (no sudo):\n" ++
    "  sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/zingela\nSkipping.\n";

const concurrency_hint =
    "scan: this system cannot launch concurrent TX/RX (needs >= 2 worker threads).\n";

const TxSink = struct {
    backend: *afpacket.Backend,
    sent: *output.Counter,

    pub fn submit(self: *TxSink, frame: []const u8) bool {
        if (self.backend.submit(frame)) {
            _ = self.sent.fetchAdd(1, .monotonic);
            return true;
        }
        return false;
    }

    pub fn kick(self: *TxSink) void {
        self.backend.kick();
    }
};

fn txWorker(
    engine: *targets.Engine,
    tmpl: *const template.SynTemplate,
    bucket: *ratelimit.TokenBucket,
    sink: *TxSink,
    max_packets: u64,
    budget_ns: u64,
    tx_done: *std.atomic.Value(bool),
) u64 {
    var clock = netutil.RealClock{};
    const deadline_ns = clock.now() +| budget_ns;
    const sent = tx.run(engine, tmpl, bucket, sink, &clock, max_packets, deadline_ns);
    tx_done.store(true, .release);
    return sent;
}

fn rxWorker(
    receiver: *rx.Receiver,
    ck: cookie.Cookie,
    dd: *dedup.Dedup,
    sink: *rx.QueueSink,
    rx_done: *std.atomic.Value(bool),
) void {
    rx.run(receiver, ck, dd, sink);
    rx_done.store(true, .release);
}

fn absorb(
    batch: []const rx.Result,
    found: *std.ArrayList(rx.Result),
    allocator: std.mem.Allocator,
    stats: *output.Stats,
    json_out: ?*std.Io.Writer,
) void {
    for (batch) |r| {
        found.append(allocator, r) catch continue;
        stats.record(r.state);
        if (json_out) |w| output.emitJson(w, r) catch {};
    }
}

fn drainQueue(
    io: std.Io,
    queue: *std.Io.Queue(rx.Result),
    buf: []rx.Result,
    found: *std.ArrayList(rx.Result),
    allocator: std.mem.Allocator,
    stats: *output.Stats,
    json_out: ?*std.Io.Writer,
) void {
    while (true) {
        const n = queue.get(io, buf, 0) catch return;
        if (n == 0) return;
        absorb(buf[0..n], found, allocator, stats, json_out);
        if (n < buf.len) return;
    }
}

fn terminalCols(fd: i32) ?u16 {
    var ws: std.posix.winsize = undefined;
    const rc = std.os.linux.ioctl(fd, std.os.linux.T.IOCGWINSZ, @intFromPtr(&ws));
    if (std.os.linux.errno(rc) != .SUCCESS) return null;
    if (ws.col == 0) return null;
    return ws.col;
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8, env: *std.process.Environ.Map) !void {
    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    const out = &ow.interface;

    var ebuf: [4096]u8 = undefined;
    var ew = std.Io.File.stderr().writer(io, &ebuf);
    const derr = &ew.interface;

    const target_text = netutil.getFlag(args, "--target") orelse {
        try derr.writeAll("scan: --target <cidr> is required (e.g. --target 10.0.0.0/24)\n");
        try derr.flush();
        return;
    };
    const ifname = netutil.getFlag(args, "--iface") orelse default_iface;
    const rate = if (netutil.getFlag(args, "--rate")) |r| try std.fmt.parseInt(u64, r, 10) else default_rate;
    const src_port = if (netutil.getFlag(args, "--src-port")) |p| try std.fmt.parseInt(u16, p, 10) else default_src_port;
    const wait_ms = if (netutil.getFlag(args, "--wait")) |w| try std.fmt.parseInt(i32, w, 10) else default_wait_ms;
    const json = netutil.hasFlag(args, "--json");

    const ports = if (netutil.getFlag(args, "--ports")) |p| try netutil.parsePorts(allocator, p) else try allocator.dupe(u16, &default_ports);
    const gw_mac = if (netutil.getFlag(args, "--gw-mac")) |m| try netutil.parseMac(m) else [_]u8{0} ** 6;
    const src_ip = if (netutil.getFlag(args, "--src-ip")) |s| try netutil.parseIpv4(s) else try netutil.resolveSrcIp(ifname);
    const src_mac = try netutil.resolveSrcMac(ifname);

    const choice = output.parseColorChoice(netutil.getFlag(args, "--color"));
    const out_level = output.envLevel(io, std.Io.File.stdout(), env, choice);
    const err_level = output.envLevel(io, std.Io.File.stderr(), env, choice);
    const stderr_tty = std.Io.File.stderr().isTty(io) catch false;
    const wide_enough = if (terminalCols(2)) |c| c >= min_dashboard_cols else true;
    const interactive = stderr_tty and wide_enough;

    var seed: u64 = undefined;
    if (netutil.getFlag(args, "--seed")) |s| {
        seed = try std.fmt.parseInt(u64, s, 10);
    } else {
        var seed_bytes: [8]u8 = undefined;
        try io.randomSecure(&seed_bytes);
        seed = std.mem.readInt(u64, &seed_bytes, .little);
    }

    const cidr = try targets.parseCidr(target_text);
    var eng = try targets.Engine.init(allocator, &.{cidr}, ports, seed);
    defer eng.deinit();
    const count = if (netutil.getFlag(args, "--count")) |c| try std.fmt.parseInt(u64, c, 10) else eng.total;
    const dash_total = @min(count, eng.total);

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
            try derr.writeAll(need_cap_hint);
            try derr.flush();
            return;
        },
        else => return err,
    };
    defer backend.close();

    var tx_done = std.atomic.Value(bool).init(false);
    var rx_done = std.atomic.Value(bool).init(false);

    const drain_window_ns: u64 = @as(u64, @intCast(@max(wait_ms, 0))) * ns_per_ms;
    const est_tx_ns: u64 = if (rate > 0) (count / rate) *| ns_per_sec else rx_hard_cap_floor_ns;
    const tx_budget_ns: u64 = (est_tx_ns *| 4) +| rx_hard_cap_floor_ns;
    const hard_cap_ns: u64 = tx_budget_ns +| drain_window_ns;

    var receiver = rx.Receiver.open(ifname, &tx_done, drain_window_ns, hard_cap_ns) catch |err| switch (err) {
        error.NeedCapNetRaw => {
            try derr.writeAll(need_cap_hint);
            try derr.flush();
            return;
        },
        else => return err,
    };
    defer receiver.close();

    var dd = try dedup.Dedup.init(allocator, dedup_capacity);
    defer dd.deinit();

    var qbuf: [queue_capacity]rx.Result = undefined;
    var queue = std.Io.Queue(rx.Result).init(&qbuf);

    var found_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer found_arena.deinit();
    const found_alloc = found_arena.allocator();
    var found: std.ArrayList(rx.Result) = .empty;

    var stats: output.Stats = .{};
    const json_out: ?*std.Io.Writer = if (json) out else null;

    try derr.print("zingela  target {s}  iface {s}  rate {d} pps  ports {d}\n", .{ target_text, ifname, rate, ports.len });
    try derr.flush();

    var clock = netutil.RealClock{};
    const t0 = clock.now();

    var tx_sink = TxSink{ .backend = &backend, .sent = &stats.sent.v };
    var rx_sink = rx.QueueSink{ .queue = &queue, .io = io };

    var tx_fut = io.concurrent(txWorker, .{ &eng, &tmpl, &bucket, &tx_sink, count, tx_budget_ns, &tx_done }) catch {
        try derr.writeAll(concurrency_hint);
        try derr.flush();
        return;
    };
    var rx_fut = io.concurrent(rxWorker, .{ &receiver, ck, &dd, &rx_sink, &rx_done }) catch {
        _ = tx_fut.await(io);
        try derr.writeAll(concurrency_hint);
        try derr.flush();
        return;
    };

    var dash = output.Dashboard.init(err_level, interactive, dash_total);
    const render_interval_ns: u64 = if (interactive) render_tick_interactive_ns else render_tick_plain_ns;
    var drain_buf: [drain_batch]rx.Result = undefined;
    var last_render: u64 = 0;

    while (!(tx_done.load(.acquire) and rx_done.load(.acquire))) {
        drainQueue(io, &queue, drain_buf[0..], &found, found_alloc, &stats, json_out);
        if (json) out.flush() catch {};
        const now = clock.now();
        if (last_render == 0 or now -| last_render >= render_interval_ns) {
            dash.render(derr, &stats, now -| t0) catch {};
            last_render = now;
        }
        clock.sleepNs(drain_tick_ns);
    }

    const sent = tx_fut.await(io);
    rx_fut.await(io);
    queue.close(io);
    drainQueue(io, &queue, drain_buf[0..], &found, found_alloc, &stats, json_out);
    if (json) out.flush() catch {};

    dash.render(derr, &stats, clock.now() -| t0) catch {};

    var open_n: u64 = 0;
    var closed_n: u64 = 0;
    var filtered_n: u64 = 0;
    for (found.items) |r| switch (r.state) {
        .open => open_n += 1,
        .closed => closed_n += 1,
        .filtered => filtered_n += 1,
    };

    if (!json) {
        if (found.items.len > 0) {
            std.mem.sort(rx.Result, found.items, {}, output.ipPortLess);
            try out.writeByte('\n');
            try output.renderTable(out, out_level, found.items);
            try out.flush();
        } else {
            try derr.writeAll("  no open, closed, or filtered responses observed\n");
        }
    }

    const elapsed_s = @as(f64, @floatFromInt(clock.now() - t0)) / @as(f64, @floatFromInt(ns_per_sec));
    try derr.writeByte('\n');
    try output.renderSummary(derr, err_level, sent, ifname, elapsed_s, open_n, closed_n, filtered_n);
    try derr.flush();
}
