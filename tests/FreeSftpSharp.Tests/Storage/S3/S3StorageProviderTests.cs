using Microsoft.Extensions.DependencyInjection;
using SshServer.Filesystem.LocalDisk;
using SshServer.Filesystem.S3;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage.S3;

/// <summary><c>AddS3Storage</c>, the typed options of <see cref="S3StorageProvider"/> and their validation, and the client cache.</summary>
public sealed class S3StorageProviderTests
{
    private static readonly S3StorageOptions Valid = new() { Bucket = "my-bucket" };

    private static readonly ClientContext Client = new("sftp", "127.0.0.1");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void Registration_adds_the_s3_provider_next_to_the_local_disk_once()
    {
        using var services = new ServiceCollection().AddSshServerStorage().AddLocalDiskStorage().AddS3Storage().AddS3Storage().BuildServiceProvider();

        var registry = services.GetRequiredService<IStorageProviderRegistry>();

        Assert.Equal(["local", "s3"], registry.Providers.Select(p => p.Name).Order(StringComparer.Ordinal));
        Assert.IsType<S3StorageProvider>(registry.Get("S3"));
        Assert.Equal(typeof(S3StorageOptions), registry.Get("s3").OptionsType);
    }

    [Fact]
    public void Only_the_bucket_is_required_and_the_defaults_are_valid()
    {
        var provider = new S3StorageProvider(new S3ClientCache());

        Assert.Empty(provider.Validate(Valid));
        Assert.Equal(5 * 1024 * 1024, Valid.UploadPartSize);
        Assert.Equal(2, Valid.UploadConcurrency);
        Assert.Equal(4 * 1024 * 1024, Valid.ReadAheadSize);
        Assert.Empty(provider.Validate(Valid with
        {
            KeyPrefix = "users/alice",
            Endpoint = "http://localhost:9000",
            Region = "eu-north-1",
            ForcePathStyle = true,
            AccessKey = "id",
            SecretKey = "secret",
            StorageClass = "STANDARD_IA",
            ServerSideEncryption = "aws:kms",
            KmsKeyId = "key",
            UploadPartSize = 16 * 1024 * 1024,
            UploadConcurrency = 8,
            ReadAheadSize = 64 * 1024,
        }));
    }

    public static TheoryData<S3StorageOptions, string> InvalidOptions => new()
    {
        { Valid with { Bucket = "" }, "bucket" },
        { Valid with { Bucket = "a/b" }, "bucket" },
        { Valid with { KeyPrefix = "users/../admin" }, "key prefix" },
        { Valid with { KeyPrefix = "users\\alice" }, "key prefix" },
        { Valid with { Endpoint = "localhost:9000" }, "endpoint" },
        { Valid with { Endpoint = "ftp://localhost" }, "endpoint" },
        { Valid with { AccessKey = "id" }, "secret key" },
        { Valid with { SecretKey = "secret" }, "secret key" },
        { Valid with { ServerSideEncryption = "aes256" }, "encryption" },
        { Valid with { KmsKeyId = "key" }, "KMS" },
        { Valid with { UploadPartSize = 5 * 1024 * 1024 - 1 }, "part size" },
        { Valid with { UploadConcurrency = 0 }, "concurrency" },
        { Valid with { ReadAheadSize = 1024 }, "read-ahead" },
    };

    [Theory]
    [MemberData(nameof(InvalidOptions))]
    public async Task Invalid_options_are_refused_with_the_reason(S3StorageOptions options, string reason)
    {
        var provider = new S3StorageProvider(new S3ClientCache());

        Assert.Contains(provider.Validate(options), problem => problem.Contains(reason, StringComparison.OrdinalIgnoreCase));
        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.CreateAsync(options, Ct));
    }

    [Fact]
    public void The_secret_key_is_not_in_the_text_of_the_options()
    {
        var text = (Valid with { AccessKey = "AKIDEXAMPLE", SecretKey = "wJalrXUtnFEMI-very-secret" }).ToString();

        Assert.Contains("AKIDEXAMPLE", text);
        Assert.DoesNotContain("very-secret", text);
    }

    [Fact]
    public async Task Create_gives_an_s3_file_system_without_a_request()
    {
        var provider = new S3StorageProvider(new S3ClientCache());

        var fileSystem = await provider.CreateAsync(Valid with { Endpoint = "http://127.0.0.1:9", AccessKey = "id", SecretKey = "secret" }, Ct);

        Assert.IsType<S3FileSystem>(fileSystem);
        Assert.Equal(StorageCapabilities.Append | StorageCapabilities.Rename | StorageCapabilities.ServerSideCopy, fileSystem.Capabilities);
    }

    [Fact]
    public void Options_with_the_same_endpoint_and_credentials_share_one_client()
    {
        var created = 0;
        using var cache = new S3ClientCache(_ => { created++; return new FakeS3Client(); });
        var alice = Valid with { Endpoint = "http://minio:9000", AccessKey = "id", SecretKey = "secret", KeyPrefix = "alice" };

        var first = cache.Get(alice);
        var second = cache.Get(alice with { KeyPrefix = "bob", Bucket = "other", UploadConcurrency = 4 });
        var third = cache.Get(alice with { SecretKey = "other" });

        Assert.Same(first, second);
        Assert.NotSame(first, third);
        Assert.Equal(2, created);
    }

    [Fact]
    public async Task The_factory_wraps_an_s3_user_in_the_permission_decorator()
    {
        var s3 = new FakeS3Client();
        s3.Seed("users/r/a.txt", "a"u8.ToArray());
        var factory = new StorageFileSystemFactory(
            new StorageProviderRegistry([new S3StorageProvider(new S3ClientCache(_ => s3))]),
            new FixedResolver(new StorageSelection(S3StorageProvider.ProviderName, Valid with { KeyPrefix = "users/r" })),
            new EffectivePermissionsService());

        var unrestricted = await factory.CreateAsync(new User { Username = "u" }, Client, Ct);
        var readOnly = await factory.CreateAsync(new User
        {
            Username = "r",
            Permissions = new() { ["/"] = FilePermissions.List | FilePermissions.Download },
        }, Client, Ct);

        Assert.IsType<S3FileSystem>(unrestricted);
        Assert.IsType<PermissionFileSystem>(readOnly);
        Assert.Equal(1, (await readOnly.StatAsync("/a.txt", true, Ct))!.Size);
        var ex = await Assert.ThrowsAsync<FileSystemException>(() =>
            readOnly.OpenAsync("/new.txt", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct).AsTask());
        Assert.Equal(FileSystemError.PermissionDenied, ex.Error);
        Assert.Equal(["users/r/a.txt"], s3.Keys);
        Assert.Equal(0, s3.CallCount("PutObject"));
    }

    private sealed class FixedResolver(StorageSelection selection) : IUserStorageResolver
    {
        public StorageSelection Resolve(User user) => selection;
    }
}
