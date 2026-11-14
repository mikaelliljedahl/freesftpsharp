using System.Text;
using System.Text.Json;
using FreeSftpSharp.Tests.Infrastructure;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.EndToEnd;

/// <summary>
/// The server with two virtual folders (issue #56) mounted into the root of the test user: "/shared" (another local
/// directory, full access) and "/readonly" (list and download only, by the user's permission rules on the virtual path).
/// </summary>
public sealed class VirtualFolderSftpServerFixture : SftpServerFixture
{
    public string SharedRoot => Path.Combine(TempDirectory, "shared");
    public string ReadOnlyRoot => Path.Combine(TempDirectory, "readonly");

    protected override void ConfigureUser(User user)
    {
        user.Permissions = new()
        {
            ["/"] = FilePermissions.All,
            ["/readonly"] = FilePermissions.List | FilePermissions.Download,
        };
    }

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        Directory.CreateDirectory(SharedRoot);
        Directory.CreateDirectory(ReadOnlyRoot);
        File.WriteAllText(Path.Combine(ReadOnlyRoot, "report.txt"), "read me");

        var shared = Folder("shared", SharedRoot);
        var readOnly = Folder("readonly", ReadOnlyRoot);
        var user = Repository.GetUser(Username);
        user.VirtualFolders =
        [
            new() { VirtualFolderId = shared.Id, MountPath = "/shared" },
            new() { VirtualFolderId = readOnly.Id, MountPath = "/readonly" },
        ];
        Repository.UpdateUser(user);
    }

    private VirtualFolder Folder(string name, string root)
    {
        var folder = new VirtualFolder
        {
            Name = name,
            Storage = new StorageConfig { Provider = LocalDiskStorageProvider.ProviderName, Options = JsonSerializer.Serialize(new LocalDiskStorageOptions(root)) },
        };
        Assert.True(Repository.AddVirtualFolder(folder));
        return folder;
    }
}

/// <summary>SSH.NET against a user root with virtual folders: listing, transfers in both storages, rename and permission rules.</summary>
public sealed class SshNetVirtualFolderTests : IClassFixture<VirtualFolderSftpServerFixture>
{
    private readonly VirtualFolderSftpServerFixture _server;

    public SshNetVirtualFolderTests(VirtualFolderSftpServerFixture server)
    {
        _server = server;
    }

    private static void Upload(SftpClient client, string path, string content)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(content));
        client.UploadFile(stream, path);
    }

    private static string Download(SftpClient client, string path)
    {
        using var stream = new MemoryStream();
        client.DownloadFile(path, stream);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    [Fact]
    public void The_virtual_folders_are_directories_in_the_root_listing()
    {
        using var client = _server.Connect();

        var root = client.ListDirectory("/").Where(f => f.Name is not ("." or "..")).ToList();

        Assert.True(root.Single(f => f.Name == "shared").IsDirectory);
        Assert.True(root.Single(f => f.Name == "readonly").IsDirectory);
        Assert.True(client.GetAttributes("/shared").IsDirectory);
        Assert.False(Directory.Exists(_server.PhysicalPath("/shared")), "The mount point is not a directory in the user root.");
    }

    [Fact]
    public void Files_transfer_in_the_root_and_in_a_virtual_folder_and_land_in_their_own_storage()
    {
        using var client = _server.Connect();
        var name = $"f-{Guid.NewGuid():N}.txt";

        Upload(client, "/" + name, "in the root");
        Upload(client, "/shared/" + name, "in the folder");
        client.CreateDirectory("/shared/sub-" + name);

        Assert.Equal("in the root", File.ReadAllText(_server.PhysicalPath("/" + name)));
        Assert.Equal("in the folder", File.ReadAllText(Path.Combine(_server.SharedRoot, name)));
        Assert.True(Directory.Exists(Path.Combine(_server.SharedRoot, "sub-" + name)));
        Assert.Equal("in the root", Download(client, "/" + name));
        Assert.Equal("in the folder", Download(client, "/shared/" + name));
        Assert.Contains(client.ListDirectory("/shared"), f => f.Name == name);
    }

    [Fact]
    public void A_rename_into_a_virtual_folder_is_not_supported_and_a_rename_inside_it_works()
    {
        using var client = _server.Connect();
        var name = $"r-{Guid.NewGuid():N}.txt";
        Upload(client, "/" + name, "a");
        Upload(client, "/shared/" + name, "b");

        var ex = Assert.ThrowsAny<SshException>(() => client.RenameFile("/" + name, "/shared/moved-" + name));
        client.RenameFile("/shared/" + name, "/shared/renamed-" + name);

        Assert.Contains("not supported", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(_server.PhysicalPath("/" + name)));
        Assert.False(File.Exists(Path.Combine(_server.SharedRoot, "moved-" + name)));
        Assert.True(File.Exists(Path.Combine(_server.SharedRoot, "renamed-" + name)));
    }

    [Fact]
    public void The_permission_rules_apply_to_the_virtual_path_of_a_folder()
    {
        using var client = _server.Connect();

        Assert.Equal("read me", Download(client, "/readonly/report.txt"));
        Assert.Throws<SftpPermissionDeniedException>(() => Upload(client, "/readonly/new.txt", "x"));
        Assert.Throws<SftpPermissionDeniedException>(() => client.DeleteFile("/readonly/report.txt"));

        Assert.False(File.Exists(Path.Combine(_server.ReadOnlyRoot, "new.txt")));
        Assert.True(File.Exists(Path.Combine(_server.ReadOnlyRoot, "report.txt")));
    }

    [Fact]
    public void A_virtual_folder_cannot_be_removed_or_moved()
    {
        using var client = _server.Connect();

        Assert.Throws<SftpPermissionDeniedException>(() => client.DeleteDirectory("/shared"));
        Assert.Throws<SftpPermissionDeniedException>(() => client.RenameFile("/shared", "/elsewhere"));

        Assert.True(Directory.Exists(_server.SharedRoot));
        Assert.True(client.GetAttributes("/shared").IsDirectory);
    }
}
