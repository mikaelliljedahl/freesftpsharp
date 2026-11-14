using Microsoft.Extensions.DependencyInjection;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SshServer.Filesystem.LocalDisk;
using SshServer.Filesystem.S3;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;
using SshServer.Settings.Sql;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Settings;

/// <summary>
/// The storage of a user and the virtual folders (issue #56) in the settings stores: the migration of an existing
/// database, CRUD, the mounts, and the secrets at rest.
/// </summary>
public sealed class StorageSettingsRepositoryTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly SqlSettingsRepository _repository;

    public StorageSettingsRepositoryTests()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        _repository = new SqlSettingsRepository(Options(_connection), createHostKey: () => TestCredentials.HostKey);
    }

    public void Dispose()
    {
        _repository.Dispose();
        _connection.Dispose();
    }

    private static DbContextOptions<SettingsDbContext> Options(SqliteConnection connection)
        => new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(connection).Options;

    private static StorageConfig Local(string root) => new UserRootDefaultStorage().For(new User { UserRootDirectory = root });

    private static User NewUser(string name) => new() { Username = name, UserRootDirectory = "/srv/" + name, WhitelistedIps = [] };

    private VirtualFolder AddFolder(string name, string root = "/srv/shared")
    {
        var folder = new VirtualFolder { Name = name, Description = "d-" + name, Storage = Local(root) };
        Assert.True(_repository.AddVirtualFolder(folder));
        return folder;
    }

    [Fact]
    public void An_existing_database_upgrades_and_every_user_keeps_the_same_local_directory()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var options = Options(connection);
        using (var db = new SettingsDbContext(options))
        {
            // The schema before issue #56, with a user row as the previous version wrote it.
            db.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>().Migrate("20261114082326_AddAuditLog");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO ServerSettings (ServerRsaKey, ServerBanner, ListenToPort, BindToAddress, BlacklistedIps, MaxLoginAttemptsBeforeBan, " +
                "IdleTimeout, EnableCommand, EnableDirectTcpIp, OnlyWhitelistedIps, LoginFailureWindowSeconds, BanDurationSeconds, ExemptLoopbackFromBan) " +
                "VALUES ('old-key', NULL, 22, NULL, NULL, 0, 600, 0, 0, 0, 600, 1800, 1)");
            db.Database.ExecuteSqlRaw(
                "INSERT INTO Users (Username, UserRootDirectory, HashedPassword, RsaPublicKey, OnlyWhitelistedIps, WhitelistedIps, LastSuccessfulLogin, Permissions) " +
                "VALUES ('old', '/srv/old', 'hash', NULL, 0, '[]', '2026-01-02 03:04:05', '{{\"/\":\"All\"}}')");
        }

        using var repository = new SqlSettingsRepository(options, createHostKey: () => throw new InvalidOperationException("must not be called"));

        var user = repository.GetUser("old");
        Assert.Null(user.Storage);
        Assert.Empty(user.VirtualFolders);
        Assert.Empty(repository.GetVirtualFolders());
        var storage = new UserStorageResolver(new UserRootDefaultStorage(), repository).Resolve(user);
        Assert.Empty(storage.Mounts);
        Assert.Equal("local", storage.Root.Provider);
        var codec = TestStorage.Codec(new LocalDiskStorageProvider());
        Assert.Equal(new LocalDiskStorageOptions("/srv/old"), codec.Decode(storage.Root));
        using (var db = new SettingsDbContext(options))
            Assert.Contains(db.Database.GetAppliedMigrations(), m => m.EndsWith("_AddUserStorageAndVirtualFolders", StringComparison.Ordinal));
    }

    [Fact]
    public void The_storage_and_the_mounts_of_a_user_are_saved_and_read()
    {
        var shared = AddFolder("shared");
        var archive = AddFolder("archive", "/srv/archive");
        var user = NewUser("alice");
        user.Storage = new StorageConfig { Provider = "s3", Options = "{\"Bucket\":\"b\"}" };
        user.VirtualFolders = [new() { VirtualFolderId = shared.Id, MountPath = "/shared" }];
        Assert.True(_repository.AddUser(user));

        var stored = _repository.GetUser("alice");
        Assert.Equal(user.Storage, stored.Storage);
        Assert.Equal([("/shared", shared.Id)], stored.VirtualFolders.Select(m => (m.MountPath, m.VirtualFolderId)));

        // Swap and add mounts: an unchanged mount keeps its row, a moved one is a new row.
        stored.Storage = null;
        stored.VirtualFolders =
        [
            new() { VirtualFolderId = archive.Id, MountPath = "/shared" },
            new() { VirtualFolderId = shared.Id, MountPath = "/in/shared" },
        ];
        Assert.True(_repository.UpdateUser(stored));

        var updated = _repository.GetUser("alice");
        Assert.Null(updated.Storage);
        Assert.Equal([("/in/shared", shared.Id), ("/shared", archive.Id)],
            updated.VirtualFolders.Select(m => (m.MountPath, m.VirtualFolderId)).OrderBy(m => m.MountPath));

        updated.VirtualFolders = [];
        Assert.True(_repository.UpdateUser(updated));
        Assert.Empty(_repository.GetUser("alice").VirtualFolders);
    }

    [Fact]
    public void Virtual_folders_have_unique_names_without_case_and_can_be_changed()
    {
        var folder = AddFolder("Shared");

        Assert.False(_repository.AddVirtualFolder(new VirtualFolder { Name = "shared", Storage = Local("/x") }));
        Assert.False(_repository.AddVirtualFolder(new VirtualFolder { Name = " ", Storage = Local("/x") }));
        var other = AddFolder("other");
        Assert.False(_repository.UpdateVirtualFolder(new VirtualFolder { Id = other.Id, Name = "SHARED", Storage = Local("/x") }));
        Assert.False(_repository.UpdateVirtualFolder(new VirtualFolder { Id = 999, Name = "x", Storage = Local("/x") }));

        folder.Name = "renamed";
        folder.Description = null;
        folder.Storage = Local("/srv/new");
        Assert.True(_repository.UpdateVirtualFolder(folder));

        var stored = _repository.GetVirtualFolder(folder.Id)!;
        Assert.Equal("renamed", stored.Name);
        Assert.Null(stored.Description);
        Assert.Equal(Local("/srv/new"), stored.Storage);
        Assert.Equal(["other", "renamed"], _repository.GetVirtualFolders().Select(f => f.Name));
        Assert.Null(_repository.GetVirtualFolder(999));
    }

    [Fact]
    public void Removing_a_folder_unmounts_it_and_removing_a_user_removes_its_mounts()
    {
        var shared = AddFolder("shared");
        var keep = AddFolder("keep");
        var alice = NewUser("alice");
        alice.VirtualFolders = [new() { VirtualFolderId = shared.Id, MountPath = "/s" }, new() { VirtualFolderId = keep.Id, MountPath = "/k" }];
        var bob = NewUser("bob");
        bob.VirtualFolders = [new() { VirtualFolderId = shared.Id, MountPath = "/s" }];
        _repository.AddUser(alice);
        _repository.AddUser(bob);

        Assert.True(_repository.RemoveVirtualFolder(shared.Id));
        Assert.False(_repository.RemoveVirtualFolder(shared.Id));

        Assert.Equal(["/k"], _repository.GetUser("alice").VirtualFolders.Select(m => m.MountPath));
        Assert.Empty(_repository.GetUser("bob").VirtualFolders);

        Assert.True(_repository.RemoveUser("alice"));
        Assert.True(_repository.RemoveVirtualFolder(keep.Id));
        using var db = new SettingsDbContext(Options(_connection));
        Assert.Equal(0, db.Database.SqlQueryRaw<int>("SELECT COUNT(*) AS Value FROM UserVirtualFolders").Single());
    }

    [Fact]
    public void A_secret_is_not_in_clear_text_in_the_database_and_reads_back_with_the_same_keys()
    {
        var keys = new EphemeralDataProtectionProvider();
        var codec = new StorageOptionsCodec(new StorageProviderRegistry([new S3StorageProvider(new S3ClientCache())]), new DataProtectionSecretProtector(keys));
        var options = new S3StorageOptions { Bucket = "b", AccessKey = "AKIAEXAMPLE", SecretKey = "very-secret-key-123" };
        var folder = new VirtualFolder { Name = "s3", Storage = codec.Encode("s3", options) };
        Assert.True(_repository.AddVirtualFolder(folder));
        var user = NewUser("alice");
        user.Storage = codec.Encode("s3", options);
        _repository.AddUser(user);

        using (var db = new SettingsDbContext(Options(_connection)))
        {
            var dump = string.Join("\n", db.Database.SqlQueryRaw<string>("SELECT Storage AS Value FROM VirtualFolders UNION ALL SELECT Storage AS Value FROM Users").ToList());
            Assert.DoesNotContain("very-secret-key-123", dump);
            Assert.Contains("AKIAEXAMPLE", dump); // the access key id is not a secret
        }

        Assert.Equal(options, codec.Decode(_repository.GetVirtualFolder(folder.Id)!.Storage));
        Assert.Equal(options, codec.Decode(_repository.GetUser("alice").Storage!));

        var otherKeys = new StorageOptionsCodec(new StorageProviderRegistry([new S3StorageProvider(new S3ClientCache())]),
            new DataProtectionSecretProtector(new EphemeralDataProtectionProvider()));
        var ex = Assert.Throws<ArgumentException>(() => otherKeys.Decode(user.Storage!));
        Assert.Contains("cannot be decrypted", ex.Message);
        Assert.DoesNotContain("very-secret-key-123", ex.ToString());
    }

    [Fact]
    public void The_secret_protection_uses_the_data_protection_of_the_host()
    {
        using var temp = new TempDirectory();
        var services = new ServiceCollection();
        services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(temp.Path, "keys")));
        using var withKeys = services.AddSshServerSecretProtection().BuildServiceProvider();
        using var without = new ServiceCollection().AddSshServerSecretProtection().BuildServiceProvider();

        var protector = withKeys.GetRequiredService<SshServer.Interfaces.Security.ISecretProtector>();
        var protectedValue = protector.Protect("s3-secret");

        Assert.IsType<DataProtectionSecretProtector>(protector);
        Assert.NotEqual("s3-secret", protectedValue);
        Assert.Equal("s3-secret", protector.Unprotect(protectedValue));
        Assert.Throws<InvalidOperationException>(() => without.GetRequiredService<SshServer.Interfaces.Security.ISecretProtector>().Protect("x"));
    }

    [Fact]
    public void The_LiteDB_store_keeps_the_storage_and_the_virtual_folders_too()
    {
        using var temp = new TempDirectory();
        using var repository = new SettingsRepository(Path.Combine(temp.Path, "config.db"));
        var folder = new VirtualFolder { Name = "shared", Storage = Local("/srv/shared") };
        Assert.True(repository.AddVirtualFolder(folder));
        Assert.False(repository.AddVirtualFolder(new VirtualFolder { Name = "SHARED", Storage = Local("/x") }));
        var user = NewUser("alice");
        user.Storage = Local("/srv/elsewhere");
        user.VirtualFolders = [new() { VirtualFolderId = folder.Id, MountPath = "/shared" }];
        repository.AddUser(user);

        var stored = repository.GetUser("alice");
        Assert.Equal(Local("/srv/elsewhere"), stored.Storage);
        Assert.Equal([("/shared", folder.Id)], stored.VirtualFolders.Select(m => (m.MountPath, m.VirtualFolderId)));
        Assert.Equal("shared", repository.GetVirtualFolder(folder.Id)!.Name);

        folder.Name = "renamed";
        Assert.True(repository.UpdateVirtualFolder(folder));
        Assert.Equal(["renamed"], repository.GetVirtualFolders().Select(f => f.Name));

        Assert.True(repository.RemoveVirtualFolder(folder.Id));
        Assert.Empty(repository.GetUser("alice").VirtualFolders);
        Assert.Empty(repository.GetVirtualFolders());
    }
}
