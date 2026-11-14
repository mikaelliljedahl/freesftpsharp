using System.Net;
using System.Text;
using Amazon.S3;
using Amazon.S3.Model;
using SshServer.Filesystem.S3;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.Storage.S3;

/// <summary>
/// The S3 requests of <see cref="S3FileSystem"/> on <see cref="FakeS3Client"/>: the keys below the prefix, virtual
/// directories, the read-ahead buffer, single and multipart uploads, abort on failure, server-side copies, the options
/// of new objects and the translation of S3 errors. The contract itself is in <see cref="FakeS3ConformanceTests"/>.
/// </summary>
public sealed class S3FileSystemTests
{
    private const int KiB = 1024;
    private const FileOpenFlags WriteNew = FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate;

    private readonly FakeS3Client _s3 = new();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Small parts and buffers, so the tests are fast; the provider enforces the S3 minimum of 5 MiB.</summary>
    private S3FileSystem CreateFileSystem(int partSize = 64 * KiB, int readAhead = 256 * KiB, int concurrency = 2, long maxCopySize = S3ObjectStore.DefaultMaxCopySize,
        string? storageClass = null, string? encryption = null, string? kmsKeyId = null)
        => new(new S3ObjectStore(_s3, new S3StorageOptions
        {
            Bucket = "data-bucket-7",
            KeyPrefix = "users/alice",
            UploadPartSize = partSize,
            ReadAheadSize = readAhead,
            UploadConcurrency = concurrency,
            StorageClass = storageClass,
            ServerSideEncryption = encryption,
            KmsKeyId = kmsKeyId,
        }, maxCopySize));

    // ---- Keys and virtual directories ----

    [Fact]
    public async Task Files_and_directory_markers_are_objects_below_the_key_prefix()
    {
        var fs = CreateFileSystem();

        await fs.CreateDirectoryAsync("/dir", Ct);
        await WriteAsync(fs, "/dir/a.txt", Encoding.UTF8.GetBytes("a"));

        Assert.Equal(["users/alice/dir/", "users/alice/dir/a.txt"], _s3.Keys);
        Assert.Equal("a"u8.ToArray(), _s3.Content("users/alice/dir/a.txt"));
    }

    [Fact]
    public async Task Objects_outside_the_key_prefix_are_not_visible()
    {
        _s3.Seed("users/bob/secret.txt", "bob"u8.ToArray());
        _s3.Seed("users/alice-other.txt", "x"u8.ToArray());
        var fs = CreateFileSystem();

        Assert.Empty(await ListAsync(fs, "/"));
        Assert.Null(await fs.StatAsync("/../bob/secret.txt", true, Ct));
    }

    [Fact]
    public async Task A_directory_exists_through_its_objects_without_a_marker()
    {
        _s3.Seed("users/alice/imported/deep/a.txt", "a"u8.ToArray());
        var fs = CreateFileSystem();

        Assert.True((await fs.StatAsync("/imported", true, Ct))!.IsDirectory);
        Assert.Equal(["imported"], (await ListAsync(fs, "/")).Select(e => e.Name));
        Assert.Equal(["deep"], (await ListAsync(fs, "/imported")).Select(e => e.Name));
        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await fs.DeleteDirectoryAsync("/imported", Ct));
        Assert.Equal(FileSystemError.DirectoryNotEmpty, ex.Error);
    }

    [Fact]
    public async Task Keys_that_no_virtual_path_reaches_are_left_out_of_a_listing()
    {
        _s3.Seed("users/alice/ok.txt", "x"u8.ToArray());
        _s3.Seed("users/alice/back\\slash.txt", "x"u8.ToArray());
        _s3.Seed("users/alice//empty-segment.txt", "x"u8.ToArray());
        _s3.Seed("users/alice/../up.txt", "x"u8.ToArray());
        var fs = CreateFileSystem();

        Assert.Equal(["ok.txt"], (await ListAsync(fs, "/")).Select(e => e.Name));
    }

    [Fact]
    public async Task Listing_reads_every_page()
    {
        _s3.PageSize = 2;
        var fs = CreateFileSystem();
        await fs.CreateDirectoryAsync("/dir", Ct);
        for (var i = 0; i < 5; i++)
            await WriteAsync(fs, $"/dir/f{i}.txt", [1]);
        await fs.CreateDirectoryAsync("/dir/sub", Ct);

        var names = (await ListAsync(fs, "/dir")).Select(e => e.Name).Order(StringComparer.Ordinal);

        Assert.Equal(["f0.txt", "f1.txt", "f2.txt", "f3.txt", "f4.txt", "sub"], names);
        Assert.True(_s3.CallCount("ListObjectsV2") >= 4);
    }

    // ---- Read-ahead buffer ----

    [Fact]
    public async Task Sequential_reads_are_one_request_per_read_ahead_block()
    {
        var content = RandomBytes(1024 * KiB);
        _s3.Seed("users/alice/big.bin", content);
        var fs = CreateFileSystem(readAhead: 256 * KiB);

        var read = await ReadAllAsync(fs, "/big.bin", chunk: 32 * KiB);

        Assert.Equal(content, read);
        Assert.Equal(4, _s3.CallCount("GetObject")); // 1 MiB in 256 KiB blocks, not 32 requests of 32 KiB
    }

    [Fact]
    public async Task A_read_larger_than_the_read_ahead_size_is_one_request()
    {
        var content = RandomBytes(300 * KiB);
        _s3.Seed("users/alice/a.bin", content);
        var fs = CreateFileSystem(readAhead: 64 * KiB);
        await using var handle = await fs.OpenAsync("/a.bin", FileOpenFlags.Read, null, Ct);
        var calls = _s3.CallCount("GetObject");

        var buffer = new byte[200 * KiB];
        Assert.Equal(buffer.Length, await handle.ReadAsync(100 * KiB, buffer, Ct));

        Assert.Equal(content.AsSpan(100 * KiB, 200 * KiB).ToArray(), buffer);
        Assert.Equal(calls + 1, _s3.CallCount("GetObject"));
    }

    [Fact]
    public async Task A_read_inside_the_buffer_sends_no_request_and_a_seek_outside_it_sends_one()
    {
        var content = RandomBytes(512 * KiB);
        _s3.Seed("users/alice/a.bin", content);
        var fs = CreateFileSystem(readAhead: 128 * KiB);
        await using var handle = await fs.OpenAsync("/a.bin", FileOpenFlags.Read, null, Ct);
        Assert.Equal(1, _s3.CallCount("GetObject")); // the first block is fetched at the open
        var buffer = new byte[1000];

        await handle.ReadAsync(5000, buffer, Ct);
        await handle.ReadAsync(0, buffer, Ct);
        Assert.Equal(1, _s3.CallCount("GetObject"));

        Assert.Equal(1000, await handle.ReadAsync(400 * KiB, buffer, Ct));
        Assert.Equal(content.AsSpan(400 * KiB, 1000).ToArray(), buffer);
        Assert.Equal(2, _s3.CallCount("GetObject"));
        var range = _s3.Requests.OfType<GetObjectRequest>().Last().ByteRange;
        Assert.Equal((400L * KiB, 512L * KiB - 1), (range.Start, range.End)); // up to the end of the file
    }

    [Fact]
    public async Task A_read_after_another_writer_replaced_the_file_fails_instead_of_mixing_content()
    {
        _s3.Seed("users/alice/a.bin", RandomBytes(300 * KiB));
        var fs = CreateFileSystem(readAhead: 64 * KiB);
        await using var handle = await fs.OpenAsync("/a.bin", FileOpenFlags.Read, null, Ct);

        _s3.Seed("users/alice/a.bin", RandomBytes(300 * KiB));

        Assert.Equal(1000, await handle.ReadAsync(0, new byte[1000], Ct)); // the block of the open
        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await handle.ReadAsync(200 * KiB, new byte[1000], Ct));
        Assert.Equal(FileSystemError.Failure, ex.Error);
        Assert.IsType<AmazonS3Exception>(ex.InnerException);
    }

    // ---- Uploads ----

    [Fact]
    public async Task A_file_smaller_than_one_part_is_one_put()
    {
        var fs = CreateFileSystem(partSize: 64 * KiB);
        var content = RandomBytes(40 * KiB);

        await WriteAsync(fs, "/a.bin", content, chunk: 8 * KiB);

        Assert.Equal(content, _s3.Content("users/alice/a.bin"));
        Assert.Equal(1, _s3.CallCount("PutObject"));
        Assert.Equal(0, _s3.CallCount("InitiateMultipartUpload"));
    }

    [Fact]
    public async Task A_larger_file_is_one_multipart_upload_with_the_multipart_etag()
    {
        var fs = CreateFileSystem(partSize: 64 * KiB);
        var content = RandomBytes(200 * KiB);

        await WriteAsync(fs, "/big.bin", content, chunk: 32 * KiB);

        Assert.Equal(content, _s3.Content("users/alice/big.bin"));
        Assert.Equal(1, _s3.CallCount("InitiateMultipartUpload"));
        Assert.Equal(4, _s3.CallCount("UploadPart")); // 3 full parts of 64 KiB and the last 8 KiB
        Assert.Equal(1, _s3.CallCount("CompleteMultipartUpload"));
        Assert.Equal(0, _s3.CallCount("PutObject"));
        Assert.EndsWith("-4\"", _s3.ETagOf("users/alice/big.bin"));
        Assert.Equal(0, _s3.OpenUploads);
    }

    [Fact]
    public async Task The_object_appears_only_when_the_file_is_closed()
    {
        var fs = CreateFileSystem(partSize: 64 * KiB);
        var handle = await fs.OpenAsync("/a.bin", WriteNew, null, Ct);
        await handle.WriteAsync(0, RandomBytes(150 * KiB), Ct);
        await handle.FlushAsync(Ct);

        Assert.Null(await fs.StatAsync("/a.bin", true, Ct));
        Assert.Equal(150 * KiB, (await handle.StatAsync(Ct)).Size);

        await handle.DisposeAsync();
        Assert.Equal(150 * KiB, (await fs.StatAsync("/a.bin", true, Ct))!.Size);
    }

    [Fact]
    public async Task A_failed_part_aborts_the_multipart_upload_and_leaves_no_object()
    {
        _s3.Fail = (operation, request) => operation == "UploadPart" && ((UploadPartRequest)request).PartNumber == 2
            ? FakeS3Client.Error(HttpStatusCode.InternalServerError, "InternalError") : null;
        var fs = CreateFileSystem(partSize: 64 * KiB, concurrency: 1);
        var handle = await fs.OpenAsync("/a.bin", WriteNew, null, Ct);

        var error = await Record.ExceptionAsync(async () =>
        {
            for (var offset = 0; offset < 400 * KiB; offset += 32 * KiB)
                await handle.WriteAsync(offset, RandomBytes(32 * KiB), Ct);
        });
        var closeError = await Record.ExceptionAsync(async () => await handle.DisposeAsync());

        Assert.Equal(FileSystemError.Failure, Assert.IsType<FileSystemException>(error).Error);
        Assert.Equal(FileSystemError.Failure, Assert.IsType<FileSystemException>(closeError).Error);
        Assert.Equal(1, _s3.CallCount("AbortMultipartUpload"));
        Assert.Equal(0, _s3.CallCount("CompleteMultipartUpload"));
        Assert.Equal(0, _s3.OpenUploads);
        Assert.Empty(_s3.Keys);
    }

    [Fact]
    public async Task A_failed_complete_aborts_the_upload_and_the_close_fails()
    {
        _s3.Fail = (operation, _) => operation == "CompleteMultipartUpload" ? FakeS3Client.Error(HttpStatusCode.ServiceUnavailable, "SlowDown") : null;
        var fs = CreateFileSystem(partSize: 64 * KiB);
        var handle = await fs.OpenAsync("/a.bin", WriteNew, null, Ct);
        await handle.WriteAsync(0, RandomBytes(100 * KiB), Ct);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await handle.DisposeAsync());

        Assert.Equal(FileSystemError.Failure, ex.Error);
        Assert.Contains("SlowDown", ex.Message);
        Assert.Contains("fake-request-id", ex.Message);
        Assert.Equal(1, _s3.CallCount("AbortMultipartUpload"));
        Assert.Equal(0, _s3.OpenUploads);
        Assert.Empty(_s3.Keys);
    }

    [Fact]
    public async Task A_file_beyond_10000_parts_fails_with_quota_exceeded_and_is_aborted()
    {
        var fs = CreateFileSystem(partSize: 16, concurrency: 64);
        var handle = await fs.OpenAsync("/a.bin", WriteNew, null, Ct);
        var part = new byte[16];

        var error = await Record.ExceptionAsync(async () =>
        {
            for (var i = 0; i <= S3Upload.MaxParts; i++)
                await handle.WriteAsync(i * 16L, part, Ct);
        });
        await Record.ExceptionAsync(async () => await handle.DisposeAsync());

        Assert.Equal(FileSystemError.QuotaExceeded, Assert.IsType<FileSystemException>(error).Error);
        Assert.Equal(S3Upload.MaxParts, _s3.CallCount("UploadPart"));
        Assert.Equal(0, _s3.OpenUploads);
        Assert.Empty(_s3.Keys);
    }

    [Fact]
    public async Task A_write_at_the_end_of_a_large_existing_file_copies_it_on_the_server()
    {
        var existing = RandomBytes(150 * KiB);
        var added = RandomBytes(20 * KiB);
        _s3.Seed("users/alice/a.bin", existing);
        var fs = CreateFileSystem(partSize: 64 * KiB);

        await using (var handle = await fs.OpenAsync("/a.bin", FileOpenFlags.Write, null, Ct))
            await handle.WriteAsync(existing.Length, added, Ct); // a resumed upload ("reput")

        Assert.Equal([.. existing, .. added], _s3.Content("users/alice/a.bin"));
        Assert.Equal(1, _s3.CallCount("CopyPart"));
        Assert.Equal(0, _s3.CallCount("GetObject"));
    }

    [Fact]
    public async Task Open_for_writing_and_close_without_writes_keeps_an_existing_file()
    {
        _s3.Seed("users/alice/a.bin", "keep"u8.ToArray());
        var fs = CreateFileSystem();

        await (await fs.OpenAsync("/a.bin", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct)).DisposeAsync();

        Assert.Equal("keep"u8.ToArray(), _s3.Content("users/alice/a.bin"));
        Assert.Equal(0, _s3.CallCount("PutObject"));
    }

    [Fact]
    public async Task New_objects_get_the_storage_class_and_the_server_side_encryption()
    {
        var fs = CreateFileSystem(partSize: 64 * KiB, storageClass: "STANDARD_IA", encryption: "aws:kms", kmsKeyId: "key-1");

        await WriteAsync(fs, "/small.bin", RandomBytes(KiB));
        await WriteAsync(fs, "/big.bin", RandomBytes(100 * KiB));
        await fs.RenameAsync("/small.bin", "/moved.bin", RenameFlags.None, Ct);

        var put = _s3.Requests.OfType<PutObjectRequest>().Single();
        var initiate = _s3.Requests.OfType<InitiateMultipartUploadRequest>().Single();
        var copy = _s3.Requests.OfType<CopyObjectRequest>().Single();
        Assert.All(new[] { put.StorageClass, initiate.StorageClass, copy.StorageClass }, c => Assert.Equal(S3StorageClass.StandardInfrequentAccess, c));
        Assert.All(new[] { put.ServerSideEncryptionMethod, initiate.ServerSideEncryptionMethod, copy.ServerSideEncryptionMethod },
            m => Assert.Equal(ServerSideEncryptionMethod.AWSKMS, m));
        Assert.All(new[] { put.ServerSideEncryptionKeyManagementServiceKeyId, initiate.ServerSideEncryptionKeyManagementServiceKeyId,
            copy.ServerSideEncryptionKeyManagementServiceKeyId }, k => Assert.Equal("key-1", k));
    }

    // ---- Rename ----

    [Fact]
    public async Task Rename_of_a_file_is_a_copy_on_the_server_and_a_delete()
    {
        var content = RandomBytes(10 * KiB);
        _s3.Seed("users/alice/a.bin", content);
        var fs = CreateFileSystem();

        await fs.RenameAsync("/a.bin", "/b.bin", RenameFlags.None, Ct);

        Assert.Equal(["users/alice/b.bin"], _s3.Keys);
        Assert.Equal(content, _s3.Content("users/alice/b.bin"));
        Assert.Equal(1, _s3.CallCount("CopyObject"));
        Assert.Equal(0, _s3.CallCount("GetObject"));
    }

    [Fact]
    public async Task Rename_of_a_file_larger_than_one_copy_is_a_multipart_copy()
    {
        var content = RandomBytes(300 * KiB);
        _s3.Seed("users/alice/a.bin", content);
        var fs = CreateFileSystem(maxCopySize: 100 * KiB);

        await fs.RenameAsync("/a.bin", "/b.bin", RenameFlags.None, Ct);

        Assert.Equal(content, _s3.Content("users/alice/b.bin"));
        Assert.Equal(3, _s3.CallCount("CopyPart"));
        Assert.Equal(0, _s3.CallCount("CopyObject"));
        Assert.Equal(0, _s3.OpenUploads);
    }

    [Fact]
    public async Task Rename_of_a_directory_moves_every_object_below_it()
    {
        _s3.PageSize = 2;
        var fs = CreateFileSystem();
        await fs.CreateDirectoryAsync("/a", Ct);
        await fs.CreateDirectoryAsync("/a/sub", Ct);
        for (var i = 0; i < 3; i++)
            await WriteAsync(fs, $"/a/sub/f{i}.txt", [(byte)i]);
        _s3.Seed("users/alice/ab.txt", [9]); // same text prefix, not below the directory

        await fs.RenameAsync("/a", "/b", RenameFlags.None, Ct);

        Assert.Equal(["users/alice/ab.txt", "users/alice/b/", "users/alice/b/sub/", "users/alice/b/sub/f0.txt", "users/alice/b/sub/f1.txt", "users/alice/b/sub/f2.txt"], _s3.Keys);
        Assert.Equal([2], _s3.Content("users/alice/b/sub/f2.txt"));
    }

    [Fact]
    public async Task Rename_of_a_directory_into_itself_fails_and_changes_nothing()
    {
        var fs = CreateFileSystem();
        await fs.CreateDirectoryAsync("/a", Ct);
        await fs.CreateDirectoryAsync("/a/sub", Ct);

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await fs.RenameAsync("/a", "/a/sub/a", RenameFlags.None, Ct));

        Assert.Equal(FileSystemError.Failure, ex.Error);
        Assert.Equal(["users/alice/a/", "users/alice/a/sub/"], _s3.Keys);
    }

    // ---- Attributes and errors ----

    [Fact]
    public async Task Set_attributes_that_change_nothing_work()
    {
        _s3.Seed("users/alice/a.bin", new byte[10]);
        var fs = CreateFileSystem();

        await fs.SetAttributesAsync("/a.bin", new FileAttributesUpdate(), Ct);
        await fs.SetAttributesAsync("/a.bin", new FileAttributesUpdate { Size = 10 }, Ct);
        await using var handle = await fs.OpenAsync("/b.bin", WriteNew, null, Ct);
        await handle.SetAttributesAsync(new FileAttributesUpdate { Size = 0 }, Ct);
    }

    [Fact]
    public async Task Storage_space_is_unknown()
    {
        Assert.Null(await CreateFileSystem().GetStorageSpaceAsync("/", Ct));
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, "AccessDenied", FileSystemError.PermissionDenied)]
    [InlineData(HttpStatusCode.InternalServerError, "InternalError", FileSystemError.Failure)]
    [InlineData(HttpStatusCode.ServiceUnavailable, "SlowDown", FileSystemError.Failure)]
    [InlineData(HttpStatusCode.NotFound, "NoSuchBucket", FileSystemError.Failure)]
    public async Task S3_errors_are_translated(HttpStatusCode status, string code, FileSystemError expected)
    {
        _s3.Fail = (operation, _) => operation == "ListObjectsV2" ? FakeS3Client.Error(status, code) : null;
        var fs = CreateFileSystem();

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await ListAsync(fs, "/"));

        Assert.Equal(expected, ex.Error);
        Assert.IsType<AmazonS3Exception>(ex.InnerException);
        Assert.DoesNotContain("data-bucket-7", ex.Message);
        Assert.DoesNotContain("users/alice", ex.Message);
    }

    [Fact]
    public async Task A_network_failure_is_a_failure()
    {
        _s3.Fail = (_, _) => new HttpRequestException("connection refused");
        var fs = CreateFileSystem();

        var ex = await Assert.ThrowsAsync<FileSystemException>(async () => await fs.StatAsync("/a.txt", true, Ct));

        Assert.Equal(FileSystemError.Failure, ex.Error);
    }

    // ---- Helpers ----

    private static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        Random.Shared.NextBytes(bytes);
        return bytes;
    }

    private static async Task WriteAsync(IFileSystem fs, string path, byte[] content, int chunk = 32 * KiB)
    {
        await using var handle = await fs.OpenAsync(path, WriteNew, null, Ct);
        for (var offset = 0; offset < content.Length; offset += chunk)
            await handle.WriteAsync(offset, content.AsMemory(offset, Math.Min(chunk, content.Length - offset)), Ct);
    }

    private static async Task<byte[]> ReadAllAsync(IFileSystem fs, string path, int chunk)
    {
        await using var handle = await fs.OpenAsync(path, FileOpenFlags.Read, null, Ct);
        using var result = new MemoryStream();
        var buffer = new byte[chunk];
        int read;
        while ((read = await handle.ReadAsync(result.Length, buffer, Ct)) > 0)
            result.Write(buffer, 0, read);
        return result.ToArray();
    }

    private static async Task<List<FileSystemEntry>> ListAsync(IFileSystem fs, string path)
    {
        var entries = new List<FileSystemEntry>();
        await foreach (var entry in fs.ListAsync(path, Ct))
            entries.Add(entry);
        return entries;
    }
}
