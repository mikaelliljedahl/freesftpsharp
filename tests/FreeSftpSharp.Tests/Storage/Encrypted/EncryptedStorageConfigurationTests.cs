using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using SshServer.Filesystem.Encrypted;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage.Encrypted;

/// <summary>
/// <c>AddEncryptedLocalStorage</c> and the configuration section <c>Storage:Encryption</c>: nothing changes while it is
/// off, the start fails with a clear message when it is on and the keys are wrong, and no message has a key.
/// </summary>
public sealed class EncryptedStorageConfigurationTests : IDisposable
{
    private static readonly string KeyA = Convert.ToBase64String(TestKeys.KeyA);
    private static readonly string KeyB = Convert.ToBase64String(TestKeys.KeyB);

    private readonly string _tempDirectory = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public EncryptedStorageConfigurationTests() => Directory.CreateDirectory(_tempDirectory);

    public void Dispose()
    {
        try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
    }

    [Fact]
    public async Task Without_configuration_the_start_succeeds_and_every_user_has_the_plain_local_disk()
    {
        using var host = await StartHostAsync([]);
        var services = host.Services;

        var fileSystem = await CreateUserFileSystemAsync(services);

        Assert.IsType<LocalFileSystem>(fileSystem);
        Assert.Equal(["local", "local-encrypted"], services.GetRequiredService<IStorageProviderRegistry>().Providers.Select(p => p.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Keys_without_enabled_change_nothing()
    {
        using var host = await StartHostAsync(new() { ["Storage:Encryption:ActiveKeyId"] = "missing" });

        Assert.IsType<LocalFileSystem>(await CreateUserFileSystemAsync(host.Services));
    }

    [Fact]
    public async Task Enabled_with_a_valid_key_gives_every_user_the_encrypted_local_disk()
    {
        using var host = await StartHostAsync(new()
        {
            ["Storage:Encryption:Enabled"] = "true",
            ["Storage:Encryption:ActiveKeyId"] = "b",
            ["Storage:Encryption:Keys:0:Id"] = "a",
            ["Storage:Encryption:Keys:0:Key"] = KeyA,
            ["Storage:Encryption:Keys:1:Id"] = "b",
            ["Storage:Encryption:Keys:1:Key"] = KeyB,
        });

        var fileSystem = await CreateUserFileSystemAsync(host.Services);
        await using (var handle = await fileSystem.OpenAsync("/a.txt", FileOpenFlags.Write | FileOpenFlags.Create | FileOpenFlags.Truncate, null, Ct))
            await handle.WriteAsync(0, "secret"u8.ToArray(), Ct);

        Assert.IsType<EncryptedFileSystem>(fileSystem);
        var onDisk = File.ReadAllBytes(Path.Combine(_tempDirectory, "a.txt"));
        Assert.Equal("FSS1"u8.ToArray(), onDisk[..4]);
        Assert.Equal(new MasterKey("b", TestKeys.KeyB).KeyId.ToArray(), onDisk[5..21]);
    }

    public static TheoryData<string, Dictionary<string, string?>> InvalidConfigurations => new()
    {
        { "ActiveKeyId is not set", new() { ["Keys:0:Id"] = "a", ["Keys:0:Key"] = KeyA } },
        { "The active key 'b' is not in", new() { ["ActiveKeyId"] = "b", ["Keys:0:Id"] = "a", ["Keys:0:Key"] = KeyA } },
        { "The active key 'a' is not in", new() { ["ActiveKeyId"] = "a" } },
        { "must be 32 bytes", new() { ["ActiveKeyId"] = "a", ["Keys:0:Id"] = "a", ["Keys:0:Key"] = Convert.ToBase64String(new byte[16]) } },
        { "not valid base64", new() { ["ActiveKeyId"] = "a", ["Keys:0:Id"] = "a", ["Keys:0:Key"] = "not base64!" } },
        { "used twice", new() { ["ActiveKeyId"] = "a", ["Keys:0:Id"] = "a", ["Keys:0:Key"] = KeyA, ["Keys:1:Id"] = "a", ["Keys:1:Key"] = KeyB } },
        { "has no Id", new() { ["ActiveKeyId"] = "a", ["Keys:0:Key"] = KeyA } },
        { "exactly one of Key or KeyFile", new() { ["ActiveKeyId"] = "a", ["Keys:0:Id"] = "a" } },
        { "key file of the key 'a' does not exist", new() { ["ActiveKeyId"] = "a", ["Keys:0:Id"] = "a", ["Keys:0:KeyFile"] = "/no/such/key/file" } },
    };

    [Theory]
    [MemberData(nameof(InvalidConfigurations))]
    public async Task Enabled_with_invalid_keys_fails_the_start_with_a_clear_message_without_the_key(string expected, Dictionary<string, string?> section)
    {
        var values = section.ToDictionary(kv => "Storage:Encryption:" + kv.Key, kv => kv.Value);
        values["Storage:Encryption:Enabled"] = "true";

        var ex = await Assert.ThrowsAsync<OptionsValidationException>(() => StartHostAsync(values));

        Assert.Contains(expected, ex.Message);
        Assert.Contains("Storage:Encryption", ex.Message);
        Assert.DoesNotContain(KeyA, ex.Message);
        Assert.DoesNotContain(KeyB, ex.Message);
    }

    [Fact]
    public async Task A_key_file_that_only_the_owner_can_read_is_used()
    {
        var keyFile = WriteKeyFile(KeyA + "\n", UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var provider = new ConfigurationMasterKeyProvider(Options.Create(new EncryptedStorageOptions
        {
            Enabled = true,
            ActiveKeyId = "a",
            Keys = [new EncryptionKeyOptions { Id = "a", KeyFile = keyFile }],
        }));

        var key = await provider.GetActiveKeyAsync(Ct);

        Assert.Equal("a", key.Id);
        Assert.True(key.Key.SequenceEqual(TestKeys.KeyA));
    }

    [Fact]
    public void A_key_file_that_other_users_can_read_is_refused()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "POSIX file modes");
        var keyFile = WriteKeyFile(KeyA, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);

        var result = new EncryptedStorageOptionsValidator().Validate(null, new EncryptedStorageOptions
        {
            Enabled = true,
            ActiveKeyId = "a",
            Keys = [new EncryptionKeyOptions { Id = "a", KeyFile = keyFile }],
        });

        Assert.True(result.Failed);
        Assert.Contains("chmod 600", result.FailureMessage);
    }

    [Fact]
    public void Options_and_keys_never_show_the_key_as_text()
    {
        var options = TestKeys.Options("a", ("a", TestKeys.KeyA));

        Assert.DoesNotContain(KeyA, options.ToString());
        Assert.DoesNotContain(KeyA, options.Keys[0].ToString());
        Assert.Equal("MasterKey a", new MasterKey("a", TestKeys.KeyA).ToString());
    }

    [Fact]
    public async Task The_provider_refuses_to_create_a_storage_without_a_valid_active_key()
    {
        var provider = new EncryptedLocalStorageProvider(TestKeys.Provider("missing", ("a", TestKeys.KeyA)));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(async () => await provider.CreateAsync(new EncryptedLocalStorageOptions(_tempDirectory), Ct));

        Assert.Contains("'missing'", ex.Message);
    }

    [Fact]
    public void The_provider_has_typed_options()
    {
        var provider = new EncryptedLocalStorageProvider(TestKeys.Provider("a", ("a", TestKeys.KeyA)));

        Assert.Equal("local-encrypted", provider.Name);
        Assert.Equal(typeof(EncryptedLocalStorageOptions), provider.OptionsType);
        Assert.Empty(provider.Validate(new EncryptedLocalStorageOptions(_tempDirectory)));
        Assert.NotEmpty(provider.Validate(new EncryptedLocalStorageOptions(" ")));
        Assert.NotEmpty(provider.Validate(new LocalDiskStorageOptions(_tempDirectory)));
    }

    /// <summary>Starts a generic host with the storage registration of the hosts and this configuration.</summary>
    private static async Task<IHost> StartHostAsync(Dictionary<string, string?> values)
    {
        var host = new HostBuilder()
            .ConfigureAppConfiguration(config => config.AddInMemoryCollection(values))
            .ConfigureServices(services => services.AddSshServerStorage().AddLocalDiskStorage().AddEncryptedLocalStorage())
            .Build();
        try
        {
            await host.StartAsync(Ct);
        }
        catch
        {
            host.Dispose();
            throw;
        }
        return host;
    }

    private ValueTask<IFileSystem> CreateUserFileSystemAsync(IServiceProvider services)
        => services.GetRequiredService<IFileSystemFactory>().CreateAsync(new User { Username = "u", UserRootDirectory = _tempDirectory }, new ClientContext("SFTP", "127.0.0.1"), Ct);

    private string WriteKeyFile(string content, UnixFileMode mode)
    {
        var path = Path.Combine(_tempDirectory, "master.key");
        File.WriteAllText(path, content);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, mode);
        return path;
    }
}
