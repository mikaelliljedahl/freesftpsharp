using System.Net;
using Google;
using Google.Cloud.Storage.V1;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Filesystem.Gcs;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage.Gcs;

/// <summary><c>AddGcsStorage</c>, the typed options of <see cref="GcsStorageProvider"/> and their validation, the client cache and the error translation.</summary>
public sealed class GcsStorageProviderTests
{
    private static readonly GcsStorageOptions Valid = new() { Bucket = "my-bucket" };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void Registration_adds_the_gcs_provider_next_to_the_local_disk_once()
    {
        using var services = new ServiceCollection().AddSshServerStorage().AddLocalDiskStorage().AddGcsStorage().AddGcsStorage().BuildServiceProvider();

        var registry = services.GetRequiredService<IStorageProviderRegistry>();

        Assert.Equal(["gcs", "local"], registry.Providers.Select(p => p.Name).Order(StringComparer.Ordinal));
        Assert.IsType<GcsStorageProvider>(registry.Get("GCS"));
        Assert.Equal(typeof(GcsStorageOptions), registry.Get("gcs").OptionsType);
    }

    [Fact]
    public void Only_the_bucket_is_required_and_the_defaults_are_valid()
    {
        var provider = new GcsStorageProvider(new GcsClientCache());

        Assert.Empty(provider.Validate(Valid));
        Assert.Equal(8 * 1024 * 1024, Valid.UploadChunkSize);
        Assert.Equal(4 * 1024 * 1024, Valid.ReadAheadSize);
        Assert.Empty(provider.Validate(Valid with
        {
            KeyPrefix = "users/alice",
            Endpoint = "http://localhost:4443",
            CredentialsJson = "{\"type\":\"service_account\"}",
            StorageClass = "NEARLINE",
            UploadChunkSize = 256 * 1024,
            ReadAheadSize = 64 * 1024,
        }));
        Assert.Empty(provider.Validate(Valid with { CredentialsFile = "/etc/key.json" }));
    }

    public static TheoryData<GcsStorageOptions, string> InvalidOptions => new()
    {
        { Valid with { Bucket = "" }, "bucket" },
        { Valid with { Bucket = "a/b" }, "bucket" },
        { Valid with { KeyPrefix = "users/../admin" }, "key prefix" },
        { Valid with { KeyPrefix = "users\\alice" }, "key prefix" },
        { Valid with { Endpoint = "localhost:4443" }, "endpoint" },
        { Valid with { Endpoint = "ftp://localhost" }, "endpoint" },
        { Valid with { CredentialsJson = "{}", CredentialsFile = "/etc/key.json" }, "not both" },
        { Valid with { CredentialsJson = "not json" }, "JSON object" },
        { Valid with { CredentialsJson = "[1]" }, "JSON object" },
        { Valid with { StorageClass = "standard" }, "storage class" },
        { Valid with { UploadChunkSize = 256 * 1024 + 1 }, "chunk size" },
        { Valid with { UploadChunkSize = 128 * 1024 }, "chunk size" },
        { Valid with { ReadAheadSize = 1024 }, "read-ahead" },
    };

    [Theory]
    [MemberData(nameof(InvalidOptions))]
    public async Task Invalid_options_are_refused_with_the_reason(GcsStorageOptions options, string reason)
    {
        var provider = new GcsStorageProvider(new GcsClientCache());

        Assert.Contains(provider.Validate(options), problem => problem.Contains(reason, StringComparison.OrdinalIgnoreCase));
        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.CreateAsync(options, Ct));
    }

    [Fact]
    public void The_credentials_are_not_in_the_text_of_the_options()
    {
        var text = (Valid with { CredentialsJson = "{\"private_key\":\"very-secret\"}", CredentialsFile = "/etc/key.json" }).ToString();

        Assert.Contains("/etc/key.json", text);
        Assert.DoesNotContain("very-secret", text);
    }

    [Fact]
    public async Task Create_gives_a_gcs_file_system_without_a_request()
    {
        using var clients = new GcsClientCache();
        var provider = new GcsStorageProvider(clients);

        var fileSystem = await provider.CreateAsync(Valid with { Endpoint = "http://127.0.0.1:9" }, Ct);

        Assert.IsType<GcsFileSystem>(fileSystem);
        Assert.Equal(StorageCapabilities.Append | StorageCapabilities.Rename | StorageCapabilities.ServerSideCopy, fileSystem.Capabilities);
    }

    [Fact]
    public async Task A_credentials_file_that_does_not_exist_is_an_invalid_argument_not_a_crash()
    {
        var provider = new GcsStorageProvider(new GcsClientCache());

        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.CreateAsync(Valid with { CredentialsFile = "/does/not/exist.json" }, Ct));
    }

    [Fact]
    public void Options_with_the_same_endpoint_and_credentials_share_one_client()
    {
        var created = 0;
        using var cache = new GcsClientCache(_ => { created++; return StorageClient.CreateUnauthenticated(); });
        var alice = Valid with { Endpoint = "http://emulator:4443", KeyPrefix = "alice" };

        var first = cache.Get(alice);
        var second = cache.Get(alice with { KeyPrefix = "bob", Bucket = "other", UploadChunkSize = 512 * 1024 });
        var third = cache.Get(alice with { CredentialsFile = "/etc/key.json" });

        Assert.Same(first, second);
        Assert.NotSame(first, third);
        Assert.Equal(2, created);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, FileSystemError.NoSuchFile)]
    [InlineData(HttpStatusCode.Forbidden, FileSystemError.PermissionDenied)]
    [InlineData(HttpStatusCode.Unauthorized, FileSystemError.PermissionDenied)]
    [InlineData(HttpStatusCode.PreconditionFailed, FileSystemError.AlreadyExists)]
    [InlineData(HttpStatusCode.InternalServerError, FileSystemError.Failure)]
    public void Google_errors_are_translated_by_status(HttpStatusCode status, FileSystemError expected)
    {
        var translated = GcsErrors.Translate(new GoogleApiException("Storage", "boom") { HttpStatusCode = status }, "/a.txt", CancellationToken.None);
        var raw = GcsErrors.Translate(new HttpRequestException("boom", null, status), "/a.txt", CancellationToken.None);

        Assert.Equal(expected, translated!.Error);
        Assert.Equal(expected, raw!.Error);
        Assert.DoesNotContain("my-bucket", translated.Message);
    }

    [Fact]
    public void A_cancel_by_the_caller_and_unknown_exceptions_are_not_translated()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Null(GcsErrors.Translate(new OperationCanceledException(cts.Token), "/a", cts.Token));
        Assert.Null(GcsErrors.Translate(new InvalidOperationException(), "/a", CancellationToken.None));
        Assert.Equal(FileSystemError.Failure, GcsErrors.Translate(new IOException(), "/a", CancellationToken.None)!.Error);
    }
}
