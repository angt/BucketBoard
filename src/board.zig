const std = @import("std");
const Io = std.Io;

const bucket = @import("bucket");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const environ_map = init.environ_map;

    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    const command: enum { get, set } = if (args.len < 2)
        .get
    else if (std.mem.eql(u8, args[1], "-"))
        .set
    else
        fatal("usage: bkt [-]\n", .{});

    const token = environ_map.get("BKT_TOKEN") orelse
        fatal("BKT_TOKEN not set", .{});

    const bucket_id = environ_map.get("BKT") orelse
        fatal("BKT not set", .{});

    var bkt = bucket.Bucket{
        .allocator = gpa,
        .io = io,
        .hf_token = token,
        .bucket_id = bucket_id,
    };
    switch (command) {
        .set => try setClipboard(&bkt),
        .get => try getClipboard(&bkt),
    }
}

fn fatal(comptime msg: []const u8, args: anytype) noreturn {
    std.debug.print(msg ++ "\n", args);
    std.process.exit(1);
}

fn setClipboard(bkt: *bucket.Bucket) !void {
    var reader = Io.File.stdin().readerStreaming(bkt.io, &.{});
    const data = try reader.interface.allocRemaining(bkt.allocator, .unlimited);
    defer bkt.allocator.free(data);

    if (data.len == 0) {
        fatal("no data on stdin", .{});
    }
    bkt.uploadData("bkt", data) catch |err| {
        fatal("upload failed: {}", .{err});
    };
}

fn getClipboard(bkt: *bucket.Bucket) !void {
    const data = bkt.download("bkt") catch |err| {
        if (err == bucket.BucketError.NotFound) {
            fatal("no data found", .{});
        }
        fatal("download failed: {}", .{err});
    };
    defer bkt.allocator.free(data);

    var buf: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(bkt.io, &buf);
    try writer.interface.writeAll(data);
    try writer.flush();
}
