// ©AngelaMos | 2026
// build.zig

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const opts = b.addOptions();
    opts.addOption([]const u8, "version", "0.0.0-m5");

    const packet_mod = b.createModule(.{
        .root_source_file = b.path("src/packet.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cli_mod = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_mod.addOptions("build_config", opts);

    const smoke_mod = b.createModule(.{
        .root_source_file = b.path("src/smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    smoke_mod.addImport("packet", packet_mod);

    const cookie_mod = b.createModule(.{
        .root_source_file = b.path("src/cookie.zig"),
        .target = target,
        .optimize = optimize,
    });

    const numtheory_mod = b.createModule(.{
        .root_source_file = b.path("src/numtheory.zig"),
        .target = target,
        .optimize = optimize,
    });

    const targets_mod = b.createModule(.{
        .root_source_file = b.path("src/targets.zig"),
        .target = target,
        .optimize = optimize,
    });
    targets_mod.addImport("numtheory", numtheory_mod);

    const ratelimit_mod = b.createModule(.{
        .root_source_file = b.path("src/ratelimit.zig"),
        .target = target,
        .optimize = optimize,
    });

    const template_mod = b.createModule(.{
        .root_source_file = b.path("src/template.zig"),
        .target = target,
        .optimize = optimize,
    });
    template_mod.addImport("packet", packet_mod);
    template_mod.addImport("cookie", cookie_mod);

    const afpacket_mod = b.createModule(.{
        .root_source_file = b.path("src/afpacket.zig"),
        .target = target,
        .optimize = optimize,
    });
    afpacket_mod.addImport("packet", packet_mod);

    const tx_mod = b.createModule(.{
        .root_source_file = b.path("src/tx.zig"),
        .target = target,
        .optimize = optimize,
    });
    tx_mod.addImport("targets", targets_mod);
    tx_mod.addImport("template", template_mod);
    tx_mod.addImport("ratelimit", ratelimit_mod);
    tx_mod.addImport("cookie", cookie_mod);
    tx_mod.addImport("packet", packet_mod);

    const classify_mod = b.createModule(.{
        .root_source_file = b.path("src/classify.zig"),
        .target = target,
        .optimize = optimize,
    });
    classify_mod.addImport("packet", packet_mod);
    classify_mod.addImport("cookie", cookie_mod);

    const output_mod = b.createModule(.{
        .root_source_file = b.path("src/output.zig"),
        .target = target,
        .optimize = optimize,
    });
    output_mod.addImport("classify", classify_mod);
    cli_mod.addImport("output", output_mod);

    const dedup_mod = b.createModule(.{
        .root_source_file = b.path("src/dedup.zig"),
        .target = target,
        .optimize = optimize,
    });

    const rx_mod = b.createModule(.{
        .root_source_file = b.path("src/rx.zig"),
        .target = target,
        .optimize = optimize,
    });
    rx_mod.addImport("classify", classify_mod);
    rx_mod.addImport("dedup", dedup_mod);
    rx_mod.addImport("cookie", cookie_mod);

    const netutil_mod = b.createModule(.{
        .root_source_file = b.path("src/netutil.zig"),
        .target = target,
        .optimize = optimize,
    });

    const txcmd_mod = b.createModule(.{
        .root_source_file = b.path("src/txcmd.zig"),
        .target = target,
        .optimize = optimize,
    });
    txcmd_mod.addImport("targets", targets_mod);
    txcmd_mod.addImport("template", template_mod);
    txcmd_mod.addImport("ratelimit", ratelimit_mod);
    txcmd_mod.addImport("afpacket", afpacket_mod);
    txcmd_mod.addImport("cookie", cookie_mod);
    txcmd_mod.addImport("tx", tx_mod);
    txcmd_mod.addImport("netutil", netutil_mod);

    const scancmd_mod = b.createModule(.{
        .root_source_file = b.path("src/scancmd.zig"),
        .target = target,
        .optimize = optimize,
    });
    scancmd_mod.addImport("targets", targets_mod);
    scancmd_mod.addImport("template", template_mod);
    scancmd_mod.addImport("ratelimit", ratelimit_mod);
    scancmd_mod.addImport("afpacket", afpacket_mod);
    scancmd_mod.addImport("cookie", cookie_mod);
    scancmd_mod.addImport("tx", tx_mod);
    scancmd_mod.addImport("rx", rx_mod);
    scancmd_mod.addImport("dedup", dedup_mod);
    scancmd_mod.addImport("netutil", netutil_mod);
    scancmd_mod.addImport("output", output_mod);

    const exe = b.addExecutable(.{
        .name = "zingela",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
        }),
    });
    exe.root_module.addImport("cli", cli_mod);
    exe.root_module.addImport("smoke", smoke_mod);
    exe.root_module.addImport("txcmd", txcmd_mod);
    exe.root_module.addImport("scancmd", scancmd_mod);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zingela");
    run_step.dependOn(&run_cmd.step);

    const smoke_cmd = b.addSystemCommand(&.{b.getInstallPath(.bin, "zingela")});
    smoke_cmd.addArg("smoke");
    if (b.args) |args| smoke_cmd.addArgs(args);
    smoke_cmd.step.dependOn(b.getInstallStep());
    const smoke_step = b.step("smoke", "AF_PACKET ground-truth smoke on the installed binary (setcap it first)");
    smoke_step.dependOn(&smoke_cmd.step);

    const test_step = b.step("test", "Run unit tests");
    const test_mods = [_]*std.Build.Module{ packet_mod, cli_mod, smoke_mod, cookie_mod, numtheory_mod, targets_mod, ratelimit_mod, template_mod, afpacket_mod, tx_mod, txcmd_mod, classify_mod, dedup_mod, rx_mod, netutil_mod, output_mod, scancmd_mod };
    for (test_mods) |mod| {
        const t = b.addTest(.{ .root_module = mod });
        const rt = b.addRunArtifact(t);
        test_step.dependOn(&rt.step);
    }
}
