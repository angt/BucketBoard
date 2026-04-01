const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const xet = @import("xet");
const chunking = xet.chunking;
const hashing = xet.hashing;
const xorb = xet.xorb;
const cas_client = xet.cas_client;
const reconstruction = xet.reconstruction;
const constants = xet.constants;
const shard = xet.shard;

pub const HF_ENDPOINT = "https://huggingface.co";

pub const XetConnectionInfo = struct {
    access_token: []const u8,
    cas_url: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *XetConnectionInfo) void {
        self.allocator.free(self.access_token);
        self.allocator.free(self.cas_url);
    }
};

pub const BucketFileMetadata = struct {
    size: u64,
    xet_hash: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *BucketFileMetadata) void {
        self.allocator.free(self.xet_hash);
    }
};

pub const BucketError = error{
    NotFound,
    Unauthorized,
    Forbidden,
    InvalidResponse,
    OutOfMemory,
    ApiError,
    EmptyData,
};

pub const Bucket = struct {
    allocator: Allocator,
    io: Io,
    hf_token: []const u8,
    bucket_id: []const u8,

    pub fn ensure(self: *Bucket) !void {
        const slash_idx = std.mem.indexOf(u8, self.bucket_id, "/") orelse
            return BucketError.InvalidResponse;

        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/api/buckets/{s}/{s}",
            .{
                HF_ENDPOINT,
                self.bucket_id[0..slash_idx],
                self.bucket_id[slash_idx + 1 ..],
            },
        );
        defer self.allocator.free(url);

        const auth_header = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{self.hf_token});
        defer self.allocator.free(auth_header);

        var http_client = std.http.Client{
            .allocator = self.allocator,
            .io = self.io,
        };
        defer http_client.deinit();

        const uri = try std.Uri.parse(url);
        var req = try http_client.request(.POST, uri, .{
            .extra_headers = &[_]std.http.Header{
                .{ .name = "Authorization", .value = auth_header },
                .{ .name = "Content-Type", .value = "application/json" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .chunked = {} };
        var req_body = try req.sendBodyUnflushed(&.{});
        try req_body.writer.writeAll("{}\n");
        try req_body.end();
        try req.connection.?.flush();

        const response = try req.receiveHead(&.{});

        if (response.head.status != .ok and
            response.head.status != .created and
            response.head.status != .conflict)
        {
            return switch (response.head.status) {
                .unauthorized => BucketError.Unauthorized,
                .forbidden => BucketError.Forbidden,
                else => BucketError.ApiError,
            };
        }
    }

    pub fn getXetToken(self: *Bucket, token_type: []const u8) !XetConnectionInfo {
        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/api/buckets/{s}/xet-{s}-token",
            .{ HF_ENDPOINT, self.bucket_id, token_type },
        );
        defer self.allocator.free(url);

        const auth_header = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{self.hf_token});
        defer self.allocator.free(auth_header);

        var http_client = std.http.Client{
            .allocator = self.allocator,
            .io = self.io,
        };
        defer http_client.deinit();

        const uri = try std.Uri.parse(url);
        var req = try http_client.request(.GET, uri, .{
            .extra_headers = &[_]std.http.Header{
                .{ .name = "Authorization", .value = auth_header },
            },
        });
        defer req.deinit();

        try req.sendBodiless();
        const response = try req.receiveHead(&.{});

        if (response.head.status != .ok) {
            return switch (response.head.status) {
                .not_found => BucketError.NotFound,
                .unauthorized => BucketError.Unauthorized,
                .forbidden => BucketError.Forbidden,
                else => BucketError.ApiError,
            };
        }

        var xet_cas_url: ?[]const u8 = null;
        var xet_access_token: ?[]const u8 = null;
        var header_iter = response.head.iterateHeaders();

        while (header_iter.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "X-Xet-Cas-Url")) {
                xet_cas_url = header.value;
            } else if (std.ascii.eqlIgnoreCase(header.name, "X-Xet-Access-Token")) {
                xet_access_token = header.value;
            }
        }
        const cas_url_value = xet_cas_url orelse
            return BucketError.InvalidResponse;

        const access_token_value = xet_access_token orelse
            return BucketError.InvalidResponse;

        return XetConnectionInfo{
            .access_token = try self.allocator.dupe(u8, access_token_value),
            .cas_url = try self.allocator.dupe(u8, cas_url_value),
            .allocator = self.allocator,
        };
    }

    pub fn getFileMetadata(self: *Bucket, remote_path: []const u8) !BucketFileMetadata {
        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/buckets/{s}/resolve/{s}",
            .{ HF_ENDPOINT, self.bucket_id, remote_path },
        );
        defer self.allocator.free(url);

        const auth_header = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{self.hf_token});
        defer self.allocator.free(auth_header);

        var http_client = std.http.Client{
            .allocator = self.allocator,
            .io = self.io,
        };
        defer http_client.deinit();

        const uri = try std.Uri.parse(url);
        var req = try http_client.request(.HEAD, uri, .{
            .extra_headers = &[_]std.http.Header{
                .{ .name = "Authorization", .value = auth_header },
            },
        });
        defer req.deinit();

        try req.sendBodiless();
        const response = try req.receiveHead(&.{});

        var xet_hash: ?[]const u8 = null;
        var content_length: ?[]const u8 = null;
        var header_iter = response.head.iterateHeaders();

        while (header_iter.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "x-xet-hash")) {
                xet_hash = header.value;
            } else if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                content_length = header.value;
            }
        }
        const xet_hash_value = xet_hash orelse
            return BucketError.NotFound;

        const size: u64 = size: {
            const cl = content_length orelse
                return BucketError.InvalidResponse;
            break :size try std.fmt.parseInt(u64, cl, 10);
        };
        return BucketFileMetadata{
            .size = size,
            .xet_hash = try self.allocator.dupe(u8, xet_hash_value),
            .allocator = self.allocator,
        };
    }

    pub fn upload(self: *Bucket, remote_path: []const u8, data: []const u8) !void {
        if (data.len == 0) return BucketError.EmptyData;

        try self.ensure();

        var xet_conn = try self.getXetToken("write");
        defer xet_conn.deinit();

        var cas = try cas_client.CasClient.init(
            self.allocator,
            self.io,
            xet_conn.cas_url,
            xet_conn.access_token,
        );
        defer cas.deinit();

        var chunks = try chunking.chunkBuffer(self.allocator, data);
        defer chunks.deinit(self.allocator);

        var xorb_builder = xorb.XorbBuilder.init(self.allocator);
        defer xorb_builder.deinit();

        var chunk_hashes: std.ArrayList(hashing.Hash) = .empty;
        defer chunk_hashes.deinit(self.allocator);

        var merkle_nodes: std.ArrayList(hashing.MerkleNode) = .empty;
        defer merkle_nodes.deinit(self.allocator);

        var chunk_sizes: std.ArrayList(u32) = .empty;
        defer chunk_sizes.deinit(self.allocator);

        for (chunks.items) |chunk_range| {
            const chunk_data = data[chunk_range.start..chunk_range.end];
            const chunk_hash = hashing.computeDataHash(chunk_data);

            try chunk_hashes.append(self.allocator, chunk_hash);

            try merkle_nodes.append(self.allocator, .{
                .hash = chunk_hash,
                .size = chunk_data.len,
            });
            try chunk_sizes.append(self.allocator, @intCast(chunk_data.len));

            _ = try xorb_builder.addChunk(chunk_data);
        }

        const xorb_data = try xorb_builder.serialize(.LZ4);
        defer self.allocator.free(xorb_data);
        const xorb_hash = try xorb_builder.computeHash();

        _ = try cas.uploadXorb(xorb_hash, xorb_data);

        const merkle_root = try hashing.buildMerkleTree(self.allocator, merkle_nodes.items);
        const file_hash = hashing.computeFileHash(merkle_root);

        const shard_data = try buildShardWithVerification(
            self.allocator,
            file_hash,
            xorb_hash,
            data.len,
            chunk_hashes.items,
            chunk_sizes.items,
            xorb_data,
        );
        defer self.allocator.free(shard_data);

        _ = try cas.uploadShard(shard_data);

        const file_hash_hex = try cas_client.hashToApiHex(file_hash, self.allocator);
        defer self.allocator.free(file_hash_hex);

        try self.registerFile(remote_path, file_hash_hex);
    }

    pub fn download(self: *Bucket, remote_path: []const u8) ![]u8 {
        var metadata = try self.getFileMetadata(remote_path);
        defer metadata.deinit();

        var xet_conn = try self.getXetToken("read");
        defer xet_conn.deinit();

        var cas = try cas_client.CasClient.init(
            self.allocator,
            self.io,
            xet_conn.cas_url,
            xet_conn.access_token,
        );
        defer cas.deinit();

        const file_hash = try cas_client.apiHexToHash(metadata.xet_hash);

        var reconstructor = reconstruction.FileReconstructor.init(self.allocator, &cas);
        return try reconstructor.reconstructFile(file_hash);
    }

    fn registerFile(self: *Bucket, remote_path: []const u8, xet_hash: []const u8) !void {
        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}/api/buckets/{s}/batch",
            .{ HF_ENDPOINT, self.bucket_id },
        );
        defer self.allocator.free(url);

        const auth_header = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{self.hf_token});
        defer self.allocator.free(auth_header);

        var http_client = std.http.Client{
            .allocator = self.allocator,
            .io = self.io,
        };
        defer http_client.deinit();

        const uri = try std.Uri.parse(url);
        var req = try http_client.request(.POST, uri, .{
            .extra_headers = &[_]std.http.Header{
                .{ .name = "Authorization", .value = auth_header },
                .{ .name = "Content-Type", .value = "application/x-ndjson" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .chunked = {} };
        var req_body = try req.sendBodyUnflushed(&.{});
        try std.json.Stringify.value(.{
            .type = "addFile",
            .path = remote_path,
            .xetHash = xet_hash,
            .mtime = 0,
        }, .{}, &req_body.writer);
        try req_body.writer.writeAll("\n");
        try req_body.end();
        try req.connection.?.flush();

        const response = try req.receiveHead(&.{});

        if (response.head.status != .ok and
            response.head.status != .created)
        {
            return switch (response.head.status) {
                .unauthorized => BucketError.Unauthorized,
                .forbidden => BucketError.Forbidden,
                else => BucketError.ApiError,
            };
        }
    }
};

fn computeHash(chunk_hashes: []const hashing.Hash) hashing.Hash {
    var result: hashing.Hash = undefined;

    var hasher = std.crypto.hash.Blake3.init(.{
        .key = constants.VerificationKey,
    });
    for (chunk_hashes) |chunk_hash| {
        hasher.update(&chunk_hash);
    }
    hasher.final(&result);
    return result;
}

fn buildShardWithVerification(
    allocator: std.mem.Allocator,
    file_hash: hashing.Hash,
    xorb_hash: hashing.Hash,
    total_size: usize,
    chunk_hashes: []const hashing.Hash,
    chunk_sizes: []const u32,
    xorb_data: []const u8,
) ![]u8 {
    const size = @sizeOf(shard.ShardHeader) +
        @sizeOf(shard.FileDataSequenceHeader) +
        @sizeOf(shard.FileDataSequenceEntry) +
        @sizeOf(shard.FileVerificationEntry) +
        constants.MdbBookendMarker.len +
        @sizeOf(shard.CASChunkSequenceHeader) +
        (chunk_hashes.len * @sizeOf(shard.CASChunkSequenceEntry)) +
        constants.MdbBookendMarker.len;

    var buffer = try std.ArrayListUnmanaged(u8).initCapacity(allocator, size);
    errdefer buffer.deinit(allocator);

    const append = struct {
        fn append(buf: *std.ArrayListUnmanaged(u8), val: anytype) void {
            buf.appendSliceAssumeCapacity(std.mem.asBytes(&val));
        }
    }.append;

    append(&buffer, shard.ShardHeader{
        .magic_tag = constants.MdbShardHeaderTag,
        .version = constants.MdbHeaderVersion,
        .footer_size = 0,
    });

    append(&buffer, shard.FileDataSequenceHeader{
        .file_hash = file_hash,
        .file_flags = 0x80000000,
        .entry_count = 1,
        .reserved = @splat(0),
    });

    append(&buffer, shard.FileDataSequenceEntry{
        .xorb_hash = xorb_hash,
        .cas_flags = 0,
        .unpacked_segment_size = @intCast(total_size),
        .chunk_index_start = 0,
        .chunk_index_end = @intCast(chunk_hashes.len),
    });

    append(&buffer, shard.FileVerificationEntry{
        .range_hash = computeHash(chunk_hashes),
        .reserved = @splat(0),
    });

    buffer.appendSliceAssumeCapacity(&constants.MdbBookendMarker);

    append(&buffer, shard.CASChunkSequenceHeader{
        .xorb_hash = xorb_hash,
        .cas_flags = 0,
        .entry_count = @intCast(chunk_hashes.len),
        .total_raw_bytes = @intCast(total_size),
        .serialized_xorb_size = @intCast(xorb_data.len),
    });

    var byte_offset: u32 = 0;
    for (chunk_hashes, chunk_sizes) |chunk_hash, chunk_size| {
        append(&buffer, shard.CASChunkSequenceEntry{
            .chunk_hash = chunk_hash,
            .byte_range_start = byte_offset,
            .unpacked_segment_size = chunk_size,
            .reserved = @splat(0),
        });

        var compressed_size: u32 = 0;
        const header_end = byte_offset + @sizeOf(xorb.ChunkHeader);

        if (header_end <= xorb_data.len) {
            const header_bytes = xorb_data[byte_offset..][0..@sizeOf(xorb.ChunkHeader)];
            const header = std.mem.bytesAsValue(xorb.ChunkHeader, header_bytes);
            compressed_size = @intCast(header.getCompressedSize());
        }
        byte_offset += 8 + compressed_size;
    }
    buffer.appendSliceAssumeCapacity(&constants.MdbBookendMarker);

    return buffer.toOwnedSlice(allocator);
}
