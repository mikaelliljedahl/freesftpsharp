using Microsoft.Extensions.DependencyInjection;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// <see cref="IStorageProvider"/>, <see cref="StorageProviderRegistry"/> and the registration of the hosts:
/// <c>AddSshServerStorage</c> + <c>AddLocalDiskStorage</c> give every user the local disk at the user root.
/// </summary>
public sealed class StorageProviderTests : IDisposable
{
    private readonly string _tempDirectory = Path.Combine(Path.GetTempPath(), "freesftpsharp-tests", Guid.NewGuid().ToString("N"));

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        try { Directory.Delete(_tempDirectory, recursive: true); } catch { }
    }

    [Fact]
    public async Task Host_registration_gives_a_user_the_local_disk_at_the_user_root()
    {
        Directory.CreateDirectory(_tempDirectory);
        File.WriteAllText(Path.Combine(_tempDirectory, "a.txt"), "a");
        using var services = new ServiceCollection().AddSshServerStorage().AddLocalDiskStorage().BuildServiceProvider();

        var fileSystem = await services.GetRequiredService<IFileSystemFactory>()
            .CreateAsync(new User { Username = "u", UserRootDirectory = _tempDirectory }, Ct);

        Assert.IsType<LocalFileSystem>(fileSystem);
        Assert.Equal(1, (await fileSystem.StatAsync("/a.txt", true, Ct))!.Size);
        Assert.Equal(["local"], services.GetRequiredService<IStorageProviderRegistry>().Providers.Select(p => p.Name));
    }

    [Fact]
    public void Registration_twice_registers_the_provider_once()
    {
        using var services = new ServiceCollection().AddSshServerStorage().AddLocalDiskStorage().AddLocalDiskStorage().BuildServiceProvider();

        Assert.Single(services.GetRequiredService<IStorageProviderRegistry>().Providers);
    }

    [Theory]
    [InlineData("local")]
    [InlineData("LOCAL")]
    public void Registry_finds_a_provider_by_name_without_case(string name)
    {
        var registry = new StorageProviderRegistry([new LocalDiskStorageProvider()]);

        Assert.IsType<LocalDiskStorageProvider>(registry.Get(name));
    }

    [Fact]
    public void Registry_of_an_unknown_name_tells_the_registered_names()
    {
        var registry = new StorageProviderRegistry([new LocalDiskStorageProvider()]);

        var ex = Assert.Throws<KeyNotFoundException>(() => registry.Get("s3"));

        Assert.Contains("'s3'", ex.Message);
        Assert.Contains("local", ex.Message);
    }

    [Fact]
    public void Registry_refuses_two_providers_with_the_same_name()
    {
        Assert.Throws<InvalidOperationException>(() => new StorageProviderRegistry([new LocalDiskStorageProvider(), new LocalDiskStorageProvider()]));
    }

    [Fact]
    public void Local_provider_has_typed_options()
    {
        var provider = new LocalDiskStorageProvider();

        Assert.Equal("local", provider.Name);
        Assert.Equal(typeof(LocalDiskStorageOptions), provider.OptionsType);
        Assert.Empty(provider.Validate(new LocalDiskStorageOptions(_tempDirectory)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public async Task Local_provider_refuses_options_without_a_root_directory(string root)
    {
        var provider = new LocalDiskStorageProvider();

        Assert.NotEmpty(provider.Validate(new LocalDiskStorageOptions(root)));
        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.CreateAsync(new LocalDiskStorageOptions(root), Ct));
    }

    [Fact]
    public async Task Provider_refuses_options_of_another_type()
    {
        var provider = new LocalDiskStorageProvider();

        Assert.NotEmpty(provider.Validate("not the options"));
        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.CreateAsync("not the options", Ct));
    }

    [Fact]
    public async Task Factory_with_an_unknown_provider_throws()
    {
        var factory = new StorageFileSystemFactory(new StorageProviderRegistry([]), new FixedResolver(new StorageSelection("s3", new object())));

        await Assert.ThrowsAsync<KeyNotFoundException>(async () => await factory.CreateAsync(new User(), Ct));
    }

    private sealed class FixedResolver(StorageSelection selection) : IUserStorageResolver
    {
        public StorageSelection Resolve(User user) => selection;
    }
}
