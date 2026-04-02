const std = @import("std");
const Io = std.Io;
const Aegis128X2 = std.crypto.aead.aegis.Aegis128X2;

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

    const secret = if (environ_map.get("BKT_SECRET")) |secret_hex|
        parseSecretKey(secret_hex)
    else
        null;

    switch (command) {
        .set => try sendBucket(gpa, &io, token, bucket, secret),
        .get => try recvBucket(gpa, &io, token, bucket, secret),
    }
}

fn fatal(comptime msg: []const u8, args: anytype) noreturn {
    std.debug.print(msg ++ "\n", args);
    std.process.exit(1);
}

fn parseSecretKey(secret_hex: []const u8) [Aegis128X2.key_length]u8 {
    if (secret_hex.len != Aegis128X2.key_length * 2) {
        fatal("BKT_SECRET must be exactly {d} hex characters", .{Aegis128X2.key_length * 2});
    }

    var key: [Aegis128X2.key_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, secret_hex) catch {
        fatal("BKT_SECRET must be valid hex", .{});
    };
    return key;
}

fn encryptData(gpa: std.mem.Allocator, io: *Io, data: []u8, key: [Aegis128X2.key_length]u8) ![]u8 {
    const plaintext_len = data.len;
    const total_len = Aegis128X2.nonce_length + plaintext_len + Aegis128X2.tag_length;
    const output = try gpa.realloc(data, total_len);

    std.mem.copyBackwards(u8, output[Aegis128X2.nonce_length .. Aegis128X2.nonce_length + plaintext_len], output[0..plaintext_len]);

    const nonce = output[0..Aegis128X2.nonce_length];
    io.random(nonce);

    const ciphertext = output[Aegis128X2.nonce_length .. Aegis128X2.nonce_length + plaintext_len];
    const tag: *[Aegis128X2.tag_length]u8 = output[Aegis128X2.nonce_length + plaintext_len ..][0..Aegis128X2.tag_length];
    Aegis128X2.encrypt(ciphertext, tag, ciphertext, "", nonce[0..nonce.len].*, key);

    return output;
}

fn decryptData(data: []u8, key: [Aegis128X2.key_length]u8) ![]u8 {
    const min_len = Aegis128X2.nonce_length + Aegis128X2.tag_length;
    if (data.len < min_len) {
        return error.InvalidCiphertext;
    }

    const nonce = data[0..Aegis128X2.nonce_length];

    const sealed = data[Aegis128X2.nonce_length..];
    const ciphertext = sealed[0 .. sealed.len - Aegis128X2.tag_length];
    const tag = sealed[sealed.len - Aegis128X2.tag_length ..][0..Aegis128X2.tag_length];

    try Aegis128X2.decrypt(ciphertext, ciphertext, tag.*, "", nonce[0..nonce.len].*, key);
    return ciphertext;
}

fn sendBucket(gpa: std.mem.Allocator, io: *Io, token: []const u8, bucket: []const u8, secret: ?[Aegis128X2.key_length]u8) !void {
    var reader = Io.File.stdin().readerStreaming(io.*, &.{});
    var data = try reader.interface.allocRemaining(gpa, .unlimited);
    defer gpa.free(data);

    if (data.len == 0) {
        fatal("no data on stdin", .{});
    }
    try bucket_api.ensureBucket(gpa, io.*, bucket, token);

    var xet_conn = try bucket_api.getXetToken(gpa, io.*, bucket, token, "write");
    defer xet_conn.deinit();

    var cas = try cas_client.CasClient.init(gpa, io.*, xet_conn.cas_url, xet_conn.access_token);
    defer cas.deinit();

    const payload = if (secret) |key| blk: {
        data = try encryptData(gpa, io, data, key);
        break :blk data;
    } else data;

    const result = upload.uploadData(gpa, &cas, payload) catch |err| {
        fatal("upload failed: {}", .{err});
    };

    bucket_api.registerFile(gpa, io.*, bucket, token, "bkt", &result.file_hash_hex) catch |err| {
        fatal("register failed: {}", .{err});
    };
}

fn recvBucket(gpa: std.mem.Allocator, io: *Io, token: []const u8, bucket: []const u8, secret: ?[Aegis128X2.key_length]u8) !void {
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

    const payload = if (secret) |key|
        decryptData(data, key) catch |err| switch (err) {
            error.AuthenticationFailed, error.InvalidCiphertext => fatal("decrypt failed", .{}),
        }
    else
        data;

    var buf: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(io.*, &buf);
    try writer.interface.writeAll(payload);
    try writer.flush();
}
