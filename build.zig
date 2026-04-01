const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xet_dep = b.dependency("xet", .{
        .target = target,
        .optimize = optimize,
    });

    const bucket_mod = b.createModule(.{
        .root_source_file = b.path("src/bucket.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xet", .module = xet_dep.module("xet") },
        },
    });

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/board.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "bucket", .module = bucket_mod },
        },
    });

    const exe = b.addExecutable(.{
        .name = "bkt",
        .root_module = root_module,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the bkt app");
    run_step.dependOn(&run_cmd.step);
}
