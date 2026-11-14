using Microsoft.Extensions.DependencyInjection;
using SshServer.Filesystem.AzureBlob;
using SshServer.Filesystem.LocalDisk;
using SshServer.Filesystem.S3;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage.AzureBlob;

/// <summary><c>AddAzureBlobStorage</c>, the typed options of <see cref="AzureBlobStorageProvider"/> and their validation, and the client cache.</summary>
public sealed class AzureBlobStorageProviderTests
{
    private const string Connection = "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=c2VjcmV0;EndpointSuffix=core.windows.net";

    private static readonly AzureBlobStorageOptions Valid = new() { Container = "data", ConnectionString = Connection };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void Registration_adds_the_azure_blob_provider_next_to_the_others_once()
    {
        using var services = new ServiceCollection().AddSshServerStorage().AddLocalDiskStorage().AddS3Storage()
            .AddAzureBlobStorage().AddAzureBlobStorage().BuildServiceProvider();

        var registry = services.GetRequiredService<IStorageProviderRegistry>();

        Assert.Equal(["azure-blob", "local", "s3"], registry.Providers.Select(p => p.Name).Order(StringComparer.Ordinal));
        Assert.IsType<AzureBlobStorageProvider>(registry.Get("Azure-Blob"));
        Assert.Equal(typeof(AzureBlobStorageOptions), registry.Get("azure-blob").OptionsType);
    }

    [Fact]
    public void The_container_and_one_way_to_sign_in_are_required_and_the_defaults_are_valid()
    {
        var provider = new AzureBlobStorageProvider(new AzureBlobClientCache());

        Assert.Empty(provider.Validate(Valid));
        Assert.Equal(4 * 1024 * 1024, Valid.UploadBlockSize);
        Assert.Equal(2, Valid.UploadConcurrency);
        Assert.Equal(4 * 1024 * 1024, Valid.ReadAheadSize);
        Assert.Empty(provider.Validate(new AzureBlobStorageOptions { Container = "data", AccountName = "acct" }));
        Assert.Empty(provider.Validate(new AzureBlobStorageOptions { Container = "data", SasUrl = "https://acct.blob.core.windows.net/?sv=1&sig=x" }));
        Assert.Empty(provider.Validate(new AzureBlobStorageOptions { SasUrl = "https://acct.blob.core.windows.net/data?sv=1&sig=x" })); // a container SAS
        Assert.Empty(provider.Validate(new AzureBlobStorageOptions { Container = "data", AccountName = "acct", Endpoint = "https://acct.blob.core.chinacloudapi.cn" }));
        Assert.Empty(provider.Validate(Valid with
        {
            KeyPrefix = "users/alice",
            AccessTier = "Cool",
            UploadBlockSize = 16 * 1024 * 1024,
            UploadConcurrency = 8,
            ReadAheadSize = 64 * 1024,
        }));
    }

    public static TheoryData<AzureBlobStorageOptions, string> InvalidOptions => new()
    {
        { Valid with { Container = "" }, "container" },
        { Valid with { Container = "a/b" }, "container" },
        { Valid with { KeyPrefix = "users/../admin" }, "key prefix" },
        { Valid with { KeyPrefix = "users\\alice" }, "key prefix" },
        { new AzureBlobStorageOptions { Container = "data" }, "exactly one" },
        { Valid with { AccountName = "acct" }, "exactly one" },
        { Valid with { SasUrl = "https://acct.blob.core.windows.net/?sig=x" }, "exactly one" },
        { new AzureBlobStorageOptions { Container = "data", SasUrl = "acct.blob/?sig=x" }, "SAS URL" },
        { Valid with { Endpoint = "http://127.0.0.1:10000/acct" }, "endpoint" },
        { new AzureBlobStorageOptions { Container = "data", AccountName = "acct", Endpoint = "ftp://host" }, "endpoint" },
        { new AzureBlobStorageOptions { Container = "data", AccountName = "a b" }, "account name" },
        { Valid with { AccessTier = "Archive" }, "access tier" },
        { Valid with { UploadBlockSize = 1024 }, "block size" },
        { Valid with { UploadBlockSize = 257 * 1024 * 1024 }, "block size" },
        { Valid with { UploadConcurrency = 0 }, "concurrency" },
        { Valid with { ReadAheadSize = 1024 }, "read-ahead" },
    };

    [Theory]
    [MemberData(nameof(InvalidOptions))]
    public async Task Invalid_options_are_refused_with_the_reason(AzureBlobStorageOptions options, string reason)
    {
        var provider = new AzureBlobStorageProvider(new AzureBlobClientCache());

        Assert.Contains(provider.Validate(options), problem => problem.Contains(reason, StringComparison.OrdinalIgnoreCase));
        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.CreateAsync(options, Ct));
    }

    [Fact]
    public void The_connection_string_and_the_sas_url_are_not_in_the_text_of_the_options()
    {
        var text = (Valid with { KeyPrefix = "alice" }).ToString();
        var sas = new AzureBlobStorageOptions { SasUrl = "https://acct.blob.core.windows.net/data?sig=very-secret-signature" }.ToString();

        Assert.Contains("alice", text);
        Assert.DoesNotContain("c2VjcmV0", text);
        Assert.DoesNotContain("AccountKey", text);
        Assert.DoesNotContain("very-secret", sas);
    }

    [Fact]
    public async Task Create_gives_an_azure_blob_file_system_without_a_request()
    {
        var provider = new AzureBlobStorageProvider(new AzureBlobClientCache());

        foreach (var options in new[]
                 {
                     Valid,
                     new AzureBlobStorageOptions { Container = "data", AccountName = "acct" }, // DefaultAzureCredential, no sign-in yet
                     new AzureBlobStorageOptions { SasUrl = "https://acct.blob.core.windows.net/data?sv=1&sig=x" },
                     new AzureBlobStorageOptions { Container = "data", SasUrl = "https://acct.blob.core.windows.net/?sv=1&sig=x" },
                 })
        {
            var fileSystem = await provider.CreateAsync(options, Ct);

            Assert.IsType<AzureBlobFileSystem>(fileSystem);
            Assert.Equal(StorageCapabilities.Append | StorageCapabilities.Rename | StorageCapabilities.ServerSideCopy, fileSystem.Capabilities);
        }
    }

    [Fact]
    public async Task A_connection_string_that_the_sdk_cannot_read_is_an_invalid_argument_that_does_not_repeat_it()
    {
        var provider = new AzureBlobStorageProvider(new AzureBlobClientCache());

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () => await provider.CreateAsync(Valid with { ConnectionString = "not-a-connection-string-SECRETVALUE" }, Ct));

        Assert.DoesNotContain("SECRETVALUE", ex.Message);
    }

    [Fact]
    public void Options_with_the_same_account_container_and_credentials_share_one_client()
    {
        var cache = new AzureBlobClientCache();
        var alice = Valid with { KeyPrefix = "alice" };

        var first = cache.Get(alice);
        var second = cache.Get(alice with { KeyPrefix = "bob", UploadConcurrency = 4 });
        var otherContainer = cache.Get(alice with { Container = "other" });

        Assert.Same(first, second);
        Assert.NotSame(first, otherContainer);
    }
}
