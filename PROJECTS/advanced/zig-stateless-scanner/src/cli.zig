// ©AngelaMos | 2026
// cli.zig

const std = @import("std");
const build_config = @import("build_config");

const reset = "\x1b[0m";

const banner_art =
    \\  ____  _                 _
    \\ |_  /(_) _ _   __ _  ___| | __ _
    \\  / / | || ' \ / _` |/ -_) |/ _` |
    \\ /___||_||_||_|\__, |\___|_|\__,_|
    \\               |___/
;

pub fn colorEnabled(io: std.Io) bool {
    return std.Io.File.stdout().isTty(io) catch false;
}

pub fn printBanner(io: std.Io) !void {
    var buf: [512]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;
    if (colorEnabled(io)) {
        try out.print("\x1b[38;2;000;200;255m{s}{s}\n", .{ banner_art, reset });
    } else {
        try out.print("{s}\n", .{banner_art});
    }
    try out.print("  zingela {s}  stateless mass scanner (Zig 0.16)\n\n", .{build_config.version});
    try out.flush();
}

pub fn printVersion(io: std.Io) !void {
    var buf: [64]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;
    try out.print("zingela {s}\n", .{build_config.version});
    try out.flush();
}

pub fn printHelp(io: std.Io) !void {
    try printBanner(io);
    var buf: [512]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;
    try out.writeAll(
        \\usage: zingela <command> [options]
        \\
        \\commands:
        \\  smoke [ifname]   send one hand-built SYN via AF_PACKET (default ifname: lo)
        \\  tx [options]     PACKET_TX_RING SYN blast over a target range (privileged)
        \\  --version, -V    print version
        \\  --help, -h       print this help
        \\
        \\tx options:
        \\  --target <cidr>  target range, required (e.g. 10.0.0.0/24)
        \\  --ports <list>   comma-separated dst ports (default 80)
        \\  --rate <pps>     token-bucket rate, packets per second (default 10000)
        \\  --count <n>      stop after n packets (default: every target once)
        \\  --iface <name>   egress interface (default lo)
        \\  --src-ip <addr>  source IPv4 (default: resolved from --iface)
        \\  --src-port <n>   source TCP port (default 40000)
        \\  --gw-mac <mac>   gateway/dst MAC aa:bb:cc:dd:ee:ff (default 00:..:00)
        \\  --seed <n>       permutation seed (default: per-scan CSPRNG)
        \\
        \\authorized use only. responsible default rate; needs CAP_NET_RAW
        \\(grant once: sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/zingela)
        \\
    );
    try out.flush();
}

test "version string is non-empty" {
    try std.testing.expect(build_config.version.len > 0);
}
