const std = @import("std");
const Io = std.Io;

const xet = @import("xet");
const cas_client = xet.cas_client;
const reconstruction = xet.reconstruction;
const bucket_api = xet.bucket_api;
const upload = xet.upload;

pub fn main(init: std.process.Init) !void {
    var io = init.io;
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

    const bucket = environ_map.get("BKT") orelse
        fatal("BKT not set", .{});

    switch (command) {
        .set => try sendBucket(gpa, &io, token, bucket),
        .get => try recvBucket(gpa, &io, token, bucket),
    }
}

fn fatal(comptime msg: []const u8, args: anytype) noreturn {
    std.debug.print(msg ++ "\n", args);
    std.process.exit(1);
}

fn sendBucket(gpa: std.mem.Allocator, io: *Io, token: []const u8, bucket: []const u8) !void {
    var reader = Io.File.stdin().readerStreaming(io.*, &.{});
    const data = try reader.interface.allocRemaining(gpa, .unlimited);
    defer gpa.free(data);

    if (data.len == 0) {
        fatal("no data on stdin", .{});
    }
    try bucket_api.ensureBucket(gpa, io.*, bucket, token);

    var xet_conn = try bucket_api.getXetToken(gpa, io.*, bucket, token, "write");
    defer xet_conn.deinit();

    var cas = try cas_client.CasClient.init(gpa, io.*, xet_conn.cas_url, xet_conn.access_token);
    defer cas.deinit();

    const result = upload.uploadData(gpa, &cas, data) catch |err| {
        fatal("upload failed: {}", .{err});
    };

    bucket_api.registerFile(gpa, io.*, bucket, token, "bkt", &result.file_hash_hex) catch |err| {
        fatal("register failed: {}", .{err});
    };
}

fn recvBucket(gpa: std.mem.Allocator, io: *Io, token: []const u8, bucket: []const u8) !void {
    var metadata = bucket_api.getFileMetadata(gpa, io.*, bucket, token, "bkt") catch |err| {
        if (err == bucket_api.BucketError.NotFound) {
            fatal("no data found", .{});
        }
        fatal("metadata failed: {}", .{err});
    };
    defer metadata.deinit();

    var xet_conn = try bucket_api.getXetToken(gpa, io.*, bucket, token, "read");
    defer xet_conn.deinit();

    var cas = try cas_client.CasClient.init(gpa, io.*, xet_conn.cas_url, xet_conn.access_token);
    defer cas.deinit();

    const file_hash = try cas_client.apiHexToHash(metadata.xet_hash);
    var reconstructor = reconstruction.FileReconstructor.init(gpa, &cas);

    const data = reconstructor.reconstructFile(file_hash) catch |err| {
        fatal("download failed: {}", .{err});
    };
    defer gpa.free(data);

    var buf: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(io.*, &buf);
    try writer.interface.writeAll(data);
    try writer.flush();
}
