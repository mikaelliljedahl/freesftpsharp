using Bunit;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FxSshSftpServer.Components.Pages;
using SshServer.Filesystem.LocalDisk;
using SshServer.Filesystem.S3;
using SshServer.Interfaces;
using SshServer.Interfaces.Storage;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// The storage of a user and the virtual folders in the admin UI (issue #56): provider selection with the fields of
/// the provider, secrets that are never shown again, validation by the provider, the connection test, the mounts and
/// the virtual folders page (bUnit).
/// </summary>
public sealed class StoragePagesTests : AdminUiComponentContext
{
    private static readonly TimeSpan SaveTimeout = TimeSpan.FromSeconds(15);

    private readonly TempDirectory _root = new();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _root.Dispose();
        base.Dispose(disposing);
    }

    private void AddUser(string name, StorageConfig? storage = null, List<VirtualFolderMount>? mounts = null) =>
        Repository.AddUser(new User
        {
            Username = name,
            UserRootDirectory = _root.Path,
            HashedPassword = TestCredentials.HashPassword("secret-password"),
            WhitelistedIps = [],
            Storage = storage,
            VirtualFolders = mounts ?? [],
        });

    private VirtualFolder AddFolder(string name, string? root = null)
    {
        var folder = new VirtualFolder { Name = name, Storage = Codec.Encode("local", new LocalDiskStorageOptions(root ?? _root.Path)) };
        Repository.AddVirtualFolder(folder);
        return folder;
    }

    [Fact]
    public void A_user_gets_s3_storage_and_the_secret_is_stored_protected_and_never_shown()
    {
        AddUser("alice");
        var page = Render<Users>();
        page.Find(".edit-user").Click();

        page.Find("#user-storage-provider").Change("s3");
        Assert.Empty(page.FindAll("#root-directory"));
        page.Find("#user-storage-Bucket").Change("files");
        page.Find("#user-storage-Region").Change("eu-north-1");
        page.Find("#user-storage-AccessKey").Change("AKIAUI");
        page.Find("#user-storage-SecretKey").Change("ui-secret-value");
        page.Find("#user-form").Submit();

        page.WaitForAssertion(() => Assert.Equal("s3", Repository.GetUser("alice").Storage?.Provider), SaveTimeout);
        var stored = Repository.GetUser("alice").Storage!;
        Assert.DoesNotContain("ui-secret-value", stored.Options);
        var options = (S3StorageOptions)Codec.Decode(stored);
        Assert.Equal(("files", "AKIAUI", "ui-secret-value"), (options.Bucket, options.AccessKey, options.SecretKey));

        page.WaitForAssertion(() => Assert.Equal("", page.Find("#user-storage-SecretKey").GetAttribute("value") ?? ""), SaveTimeout);
        Assert.DoesNotContain("ui-secret-value", page.Markup);
        Assert.Contains("A value is stored", page.Find("#user-storage-SecretKey").GetAttribute("placeholder"));
        page.Find(".card-header .btn-close").Click(); // the list shows the storage column only without the form
        Assert.Contains("S3 (AWS or S3-compatible)", page.Find("#user-table").TextContent);
    }

    [Fact]
    public void Saving_again_with_an_empty_secret_keeps_the_stored_secret()
    {
        AddUser("bob", Codec.Encode("s3", new S3StorageOptions { Bucket = "b", AccessKey = "AK", SecretKey = "keep-me" }));
        var page = Render<Users>();
        page.Find(".edit-user").Click();

        page.Find("#user-storage-Bucket").Change("b2");
        page.Find("#user-form").Submit();

        page.WaitForAssertion(() => Assert.Equal("b2", ((S3StorageOptions)Codec.Decode(Repository.GetUser("bob").Storage!)).Bucket), SaveTimeout);
        Assert.Equal("keep-me", ((S3StorageOptions)Codec.Decode(Repository.GetUser("bob").Storage!)).SecretKey);
    }

    [Fact]
    public void The_provider_validates_the_storage_and_nothing_is_saved()
    {
        AddUser("carol");
        var page = Render<Users>();
        page.Find(".edit-user").Click();

        page.Find("#user-storage-provider").Change("s3");
        page.Find("#user-storage-AccessKey").Change("only-the-access-key");
        page.Find("#user-form").Submit();

        Assert.Contains("The bucket is not set.", page.Find("#user-storage-problems").TextContent);
        Assert.Contains("access key", page.Find("#user-storage-problems").TextContent);
        Assert.Null(Repository.GetUser("carol").Storage);
    }

    [Fact]
    public void Selecting_the_default_storage_again_removes_the_configuration()
    {
        AddUser("dave", Codec.Encode("local", new LocalDiskStorageOptions(_root.Path)));
        var page = Render<Users>();
        page.Find(".edit-user").Click();

        page.Find("#user-storage-provider").Change("");
        page.Find("#root-directory").Change(_root.Path);
        page.Find("#user-form").Submit();

        page.WaitForAssertion(() => Assert.Null(Repository.GetUser("dave").Storage), SaveTimeout);
    }

    [Fact]
    public void The_connection_test_reports_the_result()
    {
        File.WriteAllText(Path.Combine(_root.Path, "x.txt"), "x");
        AddUser("erin");
        var page = Render<Users>();
        page.Find(".edit-user").Click();
        page.Find("#user-storage-provider").Change("local");
        page.Find("#user-storage-RootDirectory").Change(_root.Path);

        page.Find("#user-storage-test").Click();

        page.WaitForAssertion(() => Assert.Contains("The storage works", page.Find("#user-storage-test-result").TextContent), SaveTimeout);

        page.Find("#user-storage-RootDirectory").Change(Path.Combine(_root.Path, "missing"));
        page.Find("#user-storage-test").Click();
        page.WaitForAssertion(() => Assert.Contains("does not work", page.Find("#user-storage-test-result").TextContent), SaveTimeout);
    }

    [Fact]
    public void A_virtual_folder_is_mounted_for_a_user_and_a_bad_mount_path_is_refused()
    {
        var folder = AddFolder("shared");
        AddUser("frank");
        var page = Render<Users>();
        page.Find(".edit-user").Click();

        page.Find("#add-mount").Click();
        Assert.Equal("/shared", page.Find("#mount-path-0").GetAttribute("value"));
        page.Find("#mount-path-0").Change("/");
        page.Find("#user-form").Submit();
        Assert.Contains("cannot be mounted at /", page.Find("#mount-problems").TextContent);
        Assert.Empty(Repository.GetUser("frank").VirtualFolders);

        page.Find("#mount-path-0").Change("/in/shared/");
        page.Find("#user-form").Submit();

        page.WaitForAssertion(() => Assert.Single(Repository.GetUser("frank").VirtualFolders), SaveTimeout);
        var mount = Repository.GetUser("frank").VirtualFolders.Single();
        Assert.Equal((folder.Id, "/in/shared"), (mount.VirtualFolderId, mount.MountPath));
    }

    [Fact]
    public void Without_virtual_folders_the_user_page_says_so()
    {
        AddUser("gina");
        var page = Render<Users>();
        page.Find(".edit-user").Click();

        Assert.NotNull(page.Find("#no-folders"));
        Assert.Empty(page.FindAll("#add-mount"));
    }

    [Fact]
    public void A_virtual_folder_is_created_and_edited_on_its_page()
    {
        var page = Render<VirtualFolders>();
        Assert.NotNull(page.Find("#no-folders"));

        page.Find("#add-folder").Click();
        page.Find("#folder-name").Change("incoming");
        page.Find("#folder-description").Change("Uploads of the partners");
        page.Find("#folder-storage-provider").Change("s3");
        page.Find("#folder-storage-Bucket").Change("partners");
        page.Find("#folder-storage-KeyPrefix").Change("incoming");
        page.Find("#folder-storage-Region").Change("eu-north-1");
        page.Find("#folder-form").Submit();

        var folder = Assert.Single(Repository.GetVirtualFolders());
        Assert.Equal(("incoming", "Uploads of the partners", "s3"), (folder.Name, folder.Description, folder.Storage.Provider));
        Assert.Equal("incoming", ((S3StorageOptions)Codec.Decode(folder.Storage)).KeyPrefix);
        Assert.Contains("incoming", page.Find("#folder-table").TextContent);

        page.Find("#folder-name").Change("incoming-2");
        page.Find("#folder-form").Submit();
        Assert.Equal("incoming-2", Repository.GetVirtualFolder(folder.Id)!.Name);
    }

    [Fact]
    public void A_folder_name_and_its_storage_are_validated()
    {
        AddFolder("taken");
        var page = Render<VirtualFolders>();

        page.Find("#add-folder").Click();
        page.Find("#folder-storage-provider").Change("local");
        page.Find("#folder-form").Submit();
        Assert.Contains("Enter a name.", page.Find("#folder-name-problem").TextContent);
        Assert.Contains("root directory is not set", page.Find("#folder-storage-problems").TextContent);

        page.Find("#folder-name").Change("TAKEN");
        page.Find("#folder-storage-RootDirectory").Change(_root.Path);
        page.Find("#folder-form").Submit();
        Assert.Contains("already used", page.Find("#folder-name-problem").TextContent);
        Assert.Single(Repository.GetVirtualFolders());
    }

    [Fact]
    public void Deleting_a_folder_tells_its_users_and_unmounts_it()
    {
        var folder = AddFolder("shared");
        AddUser("henry", mounts: [new() { VirtualFolderId = folder.Id, MountPath = "/shared" }]);
        var page = Render<VirtualFolders>();
        Assert.Contains("henry", page.Find("#folder-table").TextContent);

        page.Find(".delete-folder").Click();
        Assert.Contains("henry", page.Find(".modal").TextContent);
        page.Find(".confirm-button").Click();

        Assert.Empty(Repository.GetVirtualFolders());
        Assert.Empty(Repository.GetUser("henry").VirtualFolders);
        Assert.NotNull(page.Find("#no-folders"));
    }
}
