const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const xet = @import("xet");
const cas_client = xet.cas_client;
const reconstruction = xet.reconstruction;
const bucket_api = xet.bucket_api;
const upload = xet.upload;

pub const BucketError = bucket_api.BucketError;

pub const Bucket = struct {
    allocator: Allocator,
    io: Io,
    hf_token: []const u8,
    bucket_id: []const u8,

    pub fn uploadData(self: *Bucket, remote_path: []const u8, data: []const u8) !void {
        if (data.len == 0) return BucketError.EmptyData;

        try bucket_api.ensureBucket(self.allocator, self.io, self.bucket_id, self.hf_token);

        var xet_conn = try bucket_api.getXetToken(self.allocator, self.io, self.bucket_id, self.hf_token, "write");
        defer xet_conn.deinit();

        var cas = try cas_client.CasClient.init(
            self.allocator,
            self.io,
            xet_conn.cas_url,
            xet_conn.access_token,
        );
        defer cas.deinit();

        const result = try upload.uploadData(self.allocator, &cas, data);

        try bucket_api.registerFile(self.allocator, self.io, self.bucket_id, self.hf_token, remote_path, &result.file_hash_hex);
    }

    pub fn download(self: *Bucket, remote_path: []const u8) ![]u8 {
        var metadata = try bucket_api.getFileMetadata(self.allocator, self.io, self.bucket_id, self.hf_token, remote_path);
        defer metadata.deinit();

        var xet_conn = try bucket_api.getXetToken(self.allocator, self.io, self.bucket_id, self.hf_token, "read");
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
};
