using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FreeSftpSharp.Tests.Storage.Encrypted;
using FreeSftpSharp.Tests.Storage.S3;
using SshServer.Filesystem.Encrypted;
using SshServer.Filesystem.LocalDisk;
using SshServer.Filesystem.S3;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Storage;

/// <summary>
/// The per-user storage configuration (issue #56): the option fields read from the options records, the form of a
/// stored configuration (never with a secret), validation by the provider, the connection test, the codec and the
/// factory with virtual folders.
/// </summary>
public sealed class StorageConfigServiceTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly TempDirectory _temp = new();
    private readonly FakeS3Client _s3 = new();
    private readonly StorageProviderRegistry _registry;
    private readonly StorageOptionsCodec _codec;
    private readonly StorageConfigService _service;

    public StorageConfigServiceTests()
    {
        _registry = new StorageProviderRegistry([
            new LocalDiskStorageProvider(),
            new S3StorageProvider(new S3ClientCache(_ => _s3)),
            new EncryptedLocalStorageProvider(TestKeys.Provider("a", ("a", TestKeys.KeyA))),
        ]);
        _codec = new StorageOptionsCodec(_registry, new TestSecretProtector());
        _service = new StorageConfigService(_registry, _codec);
    }

    public void Dispose() => _temp.Dispose();

    private StorageSettings S3Form(string bucket = "bucket", string? accessKey = "AKIA1", string? secretKey = "secret-1")
    {
        var settings = _service.Edit(null);
        _service.SelectProvider(settings, "s3");
        settings.Values["Bucket"] = bucket;
        settings.Values["Region"] = "eu-north-1";
        settings.Values["AccessKey"] = accessKey ?? "";
        settings.Values["SecretKey"] = secretKey ?? "";
        return settings;
    }

    [Fact]
    public void Every_registered_provider_is_offered_with_the_fields_of_its_options_record()
    {
        var providers = _service.Providers;

        Assert.Equal(["Local disk", "Local disk (encrypted)", "S3 (AWS or S3-compatible)"], providers.Select(p => p.DisplayName));
        var s3 = _service.Find("S3")!;
        Assert.Equal("s3", s3.Name);
        Assert.Equal(["Bucket", "KeyPrefix", "Region", "Endpoint", "ForcePathStyle", "AccessKey", "SecretKey"], s3.Fields.Take(7).Select(f => f.Name));
        Assert.Equal([nameof(S3StorageOptions.SecretKey)], s3.Fields.Where(f => f.IsSecret).Select(f => f.Name));
        Assert.Equal(StorageOptionKind.Boolean, s3.Fields.Single(f => f.Name == "ForcePathStyle").Kind);
        Assert.Equal(StorageOptionKind.Number, s3.Fields.Single(f => f.Name == "UploadPartSize").Kind);
        Assert.Equal(["", "AES256", "aws:kms"], s3.Fields.Single(f => f.Name == "ServerSideEncryption").Choices);
        Assert.Equal("Directory", _service.Find("local")!.Fields.Single().Label);
    }

    [Fact]
    public void A_new_form_has_the_defaults_of_the_options_record()
    {
        var settings = _service.Edit(null);
        _service.SelectProvider(settings, "s3");

        Assert.Equal("s3", settings.Provider);
        Assert.Equal("5242880", settings.Value("UploadPartSize"));
        Assert.Equal("false", settings.Value("ForcePathStyle"));
        Assert.Equal("", settings.Value("Bucket"));
    }

    [Fact]
    public void A_saved_configuration_has_the_secret_encrypted_and_the_form_never_shows_it()
    {
        var result = _service.Build(S3Form());

        Assert.True(result.IsValid, string.Join(" ", result.Problems));
        Assert.Equal("s3", result.Config!.Provider);
        Assert.DoesNotContain("secret-1", result.Config.Options);
        Assert.Contains(TestSecretProtector.Prefix, result.Config.Options);
        Assert.Equal("secret-1", ((S3StorageOptions)_codec.Decode(result.Config)).SecretKey);

        var form = _service.Edit(result.Config);
        Assert.Equal("", form.Value("SecretKey"));
        Assert.Contains("SecretKey", form.StoredSecrets);
        Assert.Equal("AKIA1", form.Value("AccessKey"));
        Assert.DoesNotContain(form.Values.Values, v => v.Contains("secret-1") || v.Contains(TestSecretProtector.Prefix));
    }

    [Fact]
    public void An_empty_secret_keeps_the_stored_one_a_new_one_replaces_it_and_clear_removes_it()
    {
        var stored = _service.Build(S3Form()).Config!;

        var keep = _service.Edit(stored);
        keep.Values["Bucket"] = "other";
        var kept = (S3StorageOptions)_codec.Decode(_service.Build(keep).Config!);
        Assert.Equal(("other", "secret-1"), (kept.Bucket, kept.SecretKey));

        var replace = _service.Edit(stored);
        replace.Values["SecretKey"] = "secret-2";
        Assert.Equal("secret-2", ((S3StorageOptions)_codec.Decode(_service.Build(replace).Config!)).SecretKey);

        var clear = _service.Edit(stored);
        clear.Values["AccessKey"] = "";
        clear.ClearSecrets.Add("SecretKey");
        var cleared = (S3StorageOptions)_codec.Decode(_service.Build(clear).Config!);
        Assert.Null(cleared.AccessKey);
        Assert.Null(cleared.SecretKey);
    }

    [Fact]
    public void Switching_to_another_provider_drops_the_stored_secret()
    {
        var stored = _service.Build(S3Form()).Config!;
        var form = _service.Edit(stored);

        _service.SelectProvider(form, "local");
        form.Values["RootDirectory"] = _temp.Path;
        var result = _service.Build(form);

        Assert.Equal("local", result.Config!.Provider);
        Assert.DoesNotContain("SecretKey", result.Config.Options);
        Assert.Empty(form.StoredSecrets);
    }

    [Fact]
    public void The_provider_validates_the_options()
    {
        var noBucket = _service.Build(S3Form(bucket: ""));
        var onlyAccessKey = _service.Build(S3Form(secretKey: null));
        var badNumber = S3Form();
        badNumber.Values["UploadPartSize"] = "five";
        var tooSmall = S3Form();
        tooSmall.Values["UploadPartSize"] = "1024";
        var noProvider = _service.Build(_service.Edit(null));

        Assert.Contains("The bucket is not set.", noBucket.Problems);
        Assert.Contains(onlyAccessKey.Problems, p => p.Contains("access key"));
        Assert.Contains("Upload part size (bytes) must be a whole number.", _service.Build(badNumber).Problems);
        Assert.Contains(_service.Build(tooSmall).Problems, p => p.Contains("upload part size"));
        Assert.Equal(["Select a storage provider."], noProvider.Problems);
        Assert.False(noBucket.IsValid);
    }

    [Fact]
    public void A_configuration_of_a_provider_that_is_not_registered_tells_why()
    {
        var form = _service.Edit(new StorageConfig { Provider = "azure", Options = "{}" });

        Assert.Contains("'azure'", form.LoadProblem);
        Assert.Contains(_service.Build(form).Problems, p => p.Contains("'azure'"));
    }

    [Fact]
    public async Task The_connection_test_lists_the_root_of_the_unsaved_settings()
    {
        File.WriteAllText(Path.Combine(_temp.Path, "a.txt"), "a");
        var form = _service.Edit(null);
        _service.SelectProvider(form, "local");
        form.Values["RootDirectory"] = _temp.Path;

        var ok = await _service.TestAsync(form, Ct);
        form.Values["RootDirectory"] = Path.Combine(_temp.Path, "missing");
        var missing = await _service.TestAsync(form, Ct);
        form.Values["RootDirectory"] = "";
        var invalid = await _service.TestAsync(form, Ct);

        Assert.True(ok.Success, ok.Message);
        Assert.Contains("1 entry", ok.Message);
        Assert.False(missing.Success);
        Assert.False(invalid.Success);
        Assert.Contains("root directory is not set", invalid.Message);
    }

    [Fact]
    public async Task The_connection_test_of_s3_uses_the_stored_secret_and_reports_errors_without_it()
    {
        _s3.Seed("a.txt", "a"u8.ToArray());
        var stored = _service.Build(S3Form()).Config!;

        var ok = await _service.TestAsync(_service.Edit(stored), Ct);
        _s3.Fail = (operation, _) => operation == "ListObjectsV2" ? FakeS3Client.Error(System.Net.HttpStatusCode.Forbidden, "AccessDenied") : null;
        var denied = await _service.TestAsync(_service.Edit(stored), Ct);

        Assert.True(ok.Success, ok.Message);
        Assert.False(denied.Success);
        Assert.DoesNotContain("secret-1", denied.Message);
    }

    [Fact]
    public async Task The_factory_gives_a_user_the_configured_storage_and_mounts_the_virtual_folders()
    {
        var repository = new InMemorySettingsRepository(new ServerSettings());
        var shared = Path.Combine(_temp.Path, "shared");
        Directory.CreateDirectory(shared);
        File.WriteAllText(Path.Combine(shared, "in-shared.txt"), "s");
        _s3.Seed("users/alice/in-s3.txt", "x"u8.ToArray());
        var s3Form = S3Form();
        s3Form.Values["KeyPrefix"] = "users/alice";
        var folder = new VirtualFolder { Name = "shared", Storage = _codec.Encode("local", new LocalDiskStorageOptions(shared)) };
        repository.AddVirtualFolder(folder);
        var user = new User
        {
            Username = "alice",
            Storage = _service.Build(s3Form).Config,
            VirtualFolders = [new() { VirtualFolderId = folder.Id, MountPath = "/shared" }],
            Permissions = new() { ["/"] = FilePermissions.All, ["/shared"] = FilePermissions.List | FilePermissions.Download },
        };
        var factory = new StorageFileSystemFactory(_registry, new UserStorageResolver(new UserRootDefaultStorage(), repository), _codec,
            new EffectivePermissionsService());

        var fileSystem = await factory.CreateAsync(user, new ClientContext("SFTP", "127.0.0.1"), Ct);

        Assert.IsType<PermissionFileSystem>(fileSystem);
        var names = new List<string>();
        await foreach (var entry in fileSystem.ListAsync("/", Ct))
            names.Add(entry.Name);
        Assert.Equal(["in-s3.txt", "shared"], names.Order());
        Assert.Equal(1, (await fileSystem.StatAsync("/shared/in-shared.txt", true, Ct))!.Size);
        // The permission rules see the virtual path: /shared is read-only.
        var denied = await Assert.ThrowsAsync<FileSystemException>(() =>
            fileSystem.OpenAsync("/shared/new.txt", FileOpenFlags.Write | FileOpenFlags.Create, null, Ct).AsTask());
        Assert.Equal(FileSystemError.PermissionDenied, denied.Error);
        await fileSystem.RenameAsync("/in-s3.txt", "/renamed.txt", RenameFlags.None, Ct); // inside the S3 root
        Assert.Equal(["users/alice/renamed.txt"], _s3.Keys);
    }

    [Fact]
    public async Task A_virtual_folder_that_cannot_be_created_names_the_folder()
    {
        var repository = new InMemorySettingsRepository(new ServerSettings());
        var folder = new VirtualFolder { Name = "broken", Storage = new StorageConfig { Provider = "local", Options = "{\"RootDirectory\":\"\"}" } };
        repository.AddVirtualFolder(folder);
        var factory = new StorageFileSystemFactory(_registry, new UserStorageResolver(new UserRootDefaultStorage(), repository), _codec,
            new EffectivePermissionsService());
        var user = new User { Username = "u", UserRootDirectory = _temp.Path, VirtualFolders = [new() { VirtualFolderId = folder.Id, MountPath = "/b" }] };

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () => await factory.CreateAsync(user, new ClientContext("SFTP", "127.0.0.1"), Ct));

        Assert.Contains("'broken'", ex.Message);
        Assert.Contains("/b", ex.Message);
    }

    [Fact]
    public void A_mount_of_a_removed_folder_is_an_error_of_the_resolver()
    {
        var resolver = new UserStorageResolver(new UserRootDefaultStorage(), new InMemorySettingsRepository(new ServerSettings()));

        Assert.Throws<ArgumentException>(() => resolver.Resolve(new User { VirtualFolders = [new() { VirtualFolderId = 7, MountPath = "/x" }] }));
    }

    [Fact]
    public void A_stored_secret_that_is_not_protected_is_refused()
    {
        var plain = new StorageConfig { Provider = "s3", Options = "{\"bucket\":\"b\",\"accessKey\":\"a\",\"secretKey\":\"plain\"}" };

        var ex = Assert.Throws<ArgumentException>(() => _codec.Decode(plain));

        Assert.Contains("Secret access key", ex.Message);
    }

    [Fact]
    public void Mount_paths_are_validated()
    {
        var repository = new InMemorySettingsRepository(new ServerSettings());
        var folder = new VirtualFolder { Name = "f", Storage = new StorageConfig { Provider = "local" } };
        repository.AddVirtualFolder(folder);
        var service = new VirtualFolderService(repository);

        var problems = service.ValidateMounts([
            new() { VirtualFolderId = folder.Id, MountPath = "relative" },
            new() { VirtualFolderId = folder.Id, MountPath = "/" },
            new() { VirtualFolderId = folder.Id, MountPath = "/a" },
            new() { VirtualFolderId = folder.Id, MountPath = "/A/" },
            new() { VirtualFolderId = 99, MountPath = "/b" },
        ]);

        Assert.Equal(4, problems.Count);
        Assert.Contains(problems, p => p.Contains("must start with /"));
        Assert.Contains(problems, p => p.Contains("cannot be mounted at /"));
        Assert.Contains(problems, p => p.Contains("Two virtual folders are mounted at /A"));
        Assert.Contains(problems, p => p.Contains("Select a virtual folder for /b"));
        Assert.Empty(service.ValidateMounts([new() { VirtualFolderId = folder.Id, MountPath = "/in/shared" }]));
    }
}
