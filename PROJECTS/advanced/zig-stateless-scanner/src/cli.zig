// ©AngelaMos | 2026
// cli.zig

const std = @import("std");
const build_config = @import("build_config");
const output = @import("output");

const banner_art =
    \\  ____  _                 _
    \\ |_  /(_) _ _   __ _  ___| | __ _
    \\  / / | || ' \ / _` |/ -_) |/ _` |
    \\ /___||_||_||_|\__, |\___|_|\__,_|
    \\               |___/
;

pub fn printBanner(io: std.Io, env: *std.process.Environ.Map) !void {
    var buf: [1024]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;
    const level = output.envLevel(io, std.Io.File.stdout(), env, .auto);
    try output.bannerWordmark(out, level, banner_art);
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

pub fn printHelp(io: std.Io, env: *std.process.Environ.Map) !void {
    try printBanner(io, env);
    var buf: [512]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;
    try out.writeAll(
        \\usage: zingela <command> [options]
        \\
        \\commands:
        \\  smoke [ifname]   send one hand-built SYN via AF_PACKET (default ifname: lo)
        \\  tx [options]     PACKET_TX_RING SYN blast over a target range (privileged)
        \\  scan [options]   SYN scan: transmit + classify replies open/closed/filtered (privileged)
        \\  --version, -V    print version
        \\  --help, -h       print this help
        \\
        \\tx / scan options:
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
        \\scan-only options:
        \\  --wait <ms>      receive drain window after transmit (default 2000)
        \\  --json           emit NDJSON results to stdout (visuals go to stderr)
        \\  --color <when>   auto | always | never (default auto)
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
