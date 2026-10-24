const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Aead = std.crypto.aead.aegis.Aegis128X2;

const xet = @import("xet");
const bucket_api = xet.bucket_api;
const cas_client = xet.cas_client;
const reconstruction = xet.reconstruction;
const upload = xet.upload;

/// Name of the file, inside the bucket, that holds the clipboard payload.
const remote_path = "bkt";

const usage_text =
    \\usage: bkt [-]
    \\
    \\Without arguments, fetch the clipboard from the bucket and write it to stdout.
    \\With "-", read stdin and store it in the bucket.
    \\
    \\Options:
    \\  -h, --help  show this help and exit
    \\
    \\Environment:
    \\  BKT_TOKEN   Hugging Face token with write access to the bucket
    \\  BKT         bucket to use, as <owner>/<name>
    \\  BKT_SECRET  optional 32 hex character key, enables end-to-end encryption
    \\
;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    const args = try init.minimal.args.toSlice(gpa);
    defer gpa.free(args);

    run(io, gpa, args, init.environ_map);
}

fn run(io: Io, gpa: Allocator, args: []const []const u8, environ_map: *const std.process.Environ.Map) void {
    const command = parseCommand(io, args);

    const token = environ_map.get("BKT_TOKEN") orelse
        fatal("BKT_TOKEN is not set", .{});
    if (token.len == 0) fatal("BKT_TOKEN is empty", .{});

    const bucket = environ_map.get("BKT") orelse
        fatal("BKT is not set", .{});
    if (std.mem.indexOfScalar(u8, bucket, '/') == null) {
        fatal("BKT must be of the form <owner>/<name>, got '{s}'", .{bucket});
    }

    var secret: ?[Aead.key_length]u8 = if (environ_map.get("BKT_SECRET")) |secret_hex|
        parseSecretKey(secret_hex) catch |err| switch (err) {
            error.InvalidSecretLength => fatal(
                "BKT_SECRET must be exactly {d} hex characters",
                .{Aead.key_length * 2},
            ),
            error.InvalidSecret => fatal("BKT_SECRET must be valid hex", .{}),
        }
    else
        null;
    defer if (secret) |*key| std.crypto.secureZero(u8, key);

    switch (command) {
        .set => sendBucket(io, gpa, token, bucket, if (secret) |*key| key else null),
        .get => recvBucket(io, gpa, token, bucket, if (secret) |*key| key else null),
    }
}

const Command = enum { get, set };

fn parseCommand(io: Io, args: []const []const u8) Command {
    if (args.len < 2) return .get;

    const arg = args[1];
    if (std.mem.eql(u8, arg, "-")) {
        if (args.len > 2) usageError(args[2]);
        return .set;
    }
    if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
        Io.File.writeStreamingAll(.stdout(), io, usage_text) catch {};
        std.process.exit(0);
    }
    usageError(arg);
}

/// Reports an argument the tool does not understand and exits with status 2.
fn usageError(arg: []const u8) noreturn {
    const kind = if (std.mem.startsWith(u8, arg, "-")) "option" else "argument";
    std.debug.print("bkt: unexpected {s} '{s}'\n\n{s}", .{ kind, arg, usage_text });
    std.process.exit(2);
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("bkt: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn parseSecretKey(secret_hex: []const u8) error{ InvalidSecretLength, InvalidSecret }![Aead.key_length]u8 {
    if (secret_hex.len != Aead.key_length * 2) return error.InvalidSecretLength;

    var key: [Aead.key_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, secret_hex) catch return error.InvalidSecret;
    return key;
}

/// Encrypts `plaintext` in place, after growing it to hold a random nonce and
/// an authentication tag.
///
/// Takes ownership of `plaintext`: on success, the returned buffer must be
/// freed instead. The on-bucket format is `nonce || ciphertext || tag`.
fn seal(gpa: Allocator, io: Io, plaintext: []u8, key: *const [Aead.key_length]u8) ![]u8 {
    const plaintext_len = plaintext.len;
    const nonce_len = Aead.nonce_length;
    const sealed = try gpa.realloc(plaintext, nonce_len + plaintext_len + Aead.tag_length);

    // Make room for the nonce at the front, then generate it.
    std.mem.copyBackwards(u8, sealed[nonce_len..][0..plaintext_len], sealed[0..plaintext_len]);
    const nonce = sealed[0..nonce_len];
    io.random(nonce);

    const ciphertext = sealed[nonce_len..][0..plaintext_len];
    const tag: *[Aead.tag_length]u8 = sealed[nonce_len + plaintext_len ..][0..Aead.tag_length];
    Aead.encrypt(ciphertext, tag, ciphertext, "", nonce.*, key.*);

    return sealed;
}

/// Decrypts `sealed` (as produced by `seal`) in place.
///
/// Returns a sub-slice of `sealed` aliasing the plaintext; the caller keeps
/// ownership of `sealed` and must free that.
fn open(sealed: []u8, key: *const [Aead.key_length]u8) error{ AuthenticationFailed, InvalidCiphertext }![]u8 {
    const nonce_len = Aead.nonce_length;
    if (sealed.len < nonce_len + Aead.tag_length) return error.InvalidCiphertext;

    const nonce: *const [nonce_len]u8 = sealed[0..nonce_len];
    const ciphertext = sealed[nonce_len..][0 .. sealed.len - nonce_len - Aead.tag_length];
    const tag: *const [Aead.tag_length]u8 = sealed[sealed.len - Aead.tag_length ..][0..Aead.tag_length];

    try Aead.decrypt(ciphertext, ciphertext, tag.*, "", nonce.*, key.*);
    return ciphertext;
}

/// Holds the CAS endpoint and its credentials for the lifetime of a transfer.
const Cas = struct {
    conn: bucket_api.XetConnectionInfo,
    client: cas_client.CasClient,

    fn init(io: Io, gpa: Allocator, bucket: []const u8, token: []const u8, mode: []const u8) !Cas {
        var conn = try bucket_api.getXetToken(gpa, io, bucket, token, mode);
        errdefer conn.deinit();

        return .{
            .client = try cas_client.CasClient.init(gpa, io, conn.cas_url, conn.access_token),
            .conn = conn,
        };
    }

    fn deinit(self: *Cas) void {
        self.client.deinit();
        self.conn.deinit();
    }
};

fn sendBucket(io: Io, gpa: Allocator, token: []const u8, bucket: []const u8, secret: ?*const [Aead.key_length]u8) void {
    var stdin_buffer: [64 * 1024]u8 = undefined;
    var reader = Io.File.stdin().readerStreaming(io, &stdin_buffer);
    var data = reader.interface.allocRemaining(gpa, .unlimited) catch |err| switch (err) {
        error.ReadFailed => fatal("cannot read stdin: {}", .{reader.err.?}),
        else => fatal("cannot read stdin: {}", .{err}),
    };
    defer gpa.free(data);

    if (data.len == 0) fatal("no data on stdin", .{});

    // `seal` takes ownership of `data` and returns the reallocated buffer.
    if (secret) |key| {
        data = seal(gpa, io, data, key) catch |err| {
            fatal("encryption failed: {}", .{err});
        };
    }

    ensureBucket(io, gpa, bucket, token);

    var cas = Cas.init(io, gpa, bucket, token, "write") catch |err| {
        reportBucketError(err);
    };
    defer cas.deinit();

    const result = upload.uploadData(gpa, &cas.client, data) catch |err| {
        fatal("upload failed: {}", .{err});
    };

    bucket_api.registerFile(gpa, io, bucket, token, remote_path, &result.file_hash_hex) catch |err| {
        reportBucketError(err);
    };
}

fn recvBucket(io: Io, gpa: Allocator, token: []const u8, bucket: []const u8, secret: ?*const [Aead.key_length]u8) void {
    var metadata = bucket_api.getFileMetadata(gpa, io, bucket, token, remote_path) catch |err| {
        if (err == bucket_api.BucketError.NotFound) fatal("no data found", .{});
        reportBucketError(err);
    };
    defer metadata.deinit();

    var cas = Cas.init(io, gpa, bucket, token, "read") catch |err| {
        reportBucketError(err);
    };
    defer cas.deinit();

    const file_hash = cas_client.apiHexToHash(metadata.xet_hash) catch |err| {
        fatal("invalid file hash from server: {}", .{err});
    };

    var reconstructor = reconstruction.FileReconstructor.init(gpa, &cas.client);
    const data = reconstructor.reconstructFile(file_hash) catch |err| {
        fatal("download failed: {}", .{err});
    };
    defer gpa.free(data);

    const payload = if (secret) |key|
        open(data, key) catch |err| switch (err) {
            error.AuthenticationFailed => fatal("decryption failed: wrong BKT_SECRET or corrupted data", .{}),
            error.InvalidCiphertext => fatal("decryption failed: payload is too short", .{}),
        }
    else
        data;

    Io.File.writeStreamingAll(.stdout(), io, payload) catch |err| switch (err) {
        // The consumer went away (e.g. `bkt | head`); run cleanup and exit OK.
        error.BrokenPipe => return,
        else => fatal("cannot write to stdout: {}", .{err}),
    };
}

fn ensureBucket(io: Io, gpa: Allocator, bucket: []const u8, token: []const u8) void {
    bucket_api.ensureBucket(gpa, io, bucket, token) catch |err| switch (err) {
        bucket_api.BucketError.Unauthorized => fatal("BKT_TOKEN is not valid", .{}),
        bucket_api.BucketError.Forbidden => fatal("BKT_TOKEN cannot access bucket '{s}'", .{bucket}),
        else => fatal("cannot access bucket '{s}': {}", .{ bucket, err }),
    };
}

fn reportBucketError(err: anyerror) noreturn {
    switch (err) {
        bucket_api.BucketError.Unauthorized => fatal("BKT_TOKEN is not valid", .{}),
        bucket_api.BucketError.Forbidden => fatal("BKT_TOKEN has no permission for this operation", .{}),
        bucket_api.BucketError.NotFound => fatal("bucket or file not found", .{}),
        else => fatal("bucket operation failed: {}", .{err}),
    }
}

test "seal and open round trip" {
    const gpa = std.testing.allocator;
    const key: [Aead.key_length]u8 = @splat(0x2a);

    const long: [1000]u8 = @splat('x');
    for ([_][]const u8{ "", "a", "hello, world", &long }) |message| {
        const plaintext = try gpa.dupe(u8, message);
        const sealed = try seal(gpa, std.testing.io, plaintext, &key);
        defer gpa.free(sealed);

        try std.testing.expectEqual(
            message.len + Aead.nonce_length + Aead.tag_length,
            sealed.len,
        );

        const opened = try open(sealed, &key);
        try std.testing.expectEqualStrings(message, opened);
    }
}

test "seal uses a fresh nonce every time" {
    const gpa = std.testing.allocator;
    const key: [Aead.key_length]u8 = @splat(0x2a);

    const first = try seal(gpa, std.testing.io, try gpa.dupe(u8, "same input"), &key);
    defer gpa.free(first);
    const second = try seal(gpa, std.testing.io, try gpa.dupe(u8, "same input"), &key);
    defer gpa.free(second);

    try std.testing.expect(!std.mem.eql(u8, first[0..Aead.nonce_length], second[0..Aead.nonce_length]));
    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "open rejects tampered ciphertext" {
    const gpa = std.testing.allocator;
    const key: [Aead.key_length]u8 = @splat(0x2a);

    const sealed = try seal(gpa, std.testing.io, try gpa.dupe(u8, "hello"), &key);
    defer gpa.free(sealed);

    sealed[Aead.nonce_length + 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, open(sealed, &key));
}

test "open rejects truncated payloads" {
    const gpa = std.testing.allocator;
    const key: [Aead.key_length]u8 = @splat(0x2a);

    const sealed = try gpa.dupe(u8, "too short");
    defer gpa.free(sealed);

    try std.testing.expectError(error.InvalidCiphertext, open(sealed, &key));
}

test "open rejects the wrong key" {
    const gpa = std.testing.allocator;
    const good: [Aead.key_length]u8 = @splat(0x2a);
    const bad: [Aead.key_length]u8 = @splat(0x2b);

    const sealed = try seal(gpa, std.testing.io, try gpa.dupe(u8, "hello"), &good);
    defer gpa.free(sealed);

    try std.testing.expectError(error.AuthenticationFailed, open(sealed, &bad));
}

test "parseSecretKey" {
    const key = try parseSecretKey("00112233445566778899aabbccddeeff");
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, &key);

    try std.testing.expectError(error.InvalidSecretLength, parseSecretKey("00"));
    try std.testing.expectError(error.InvalidSecretLength, parseSecretKey("00112233445566778899aabbccddeeff00"));
    try std.testing.expectError(error.InvalidSecret, parseSecretKey("zz112233445566778899aabbccddeeff"));
}
