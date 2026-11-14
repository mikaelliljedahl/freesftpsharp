using Bunit;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FxSshSftpServer.Components.Pages;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>The users page: list, search, create, edit, delete with confirmation, key and whitelist (bUnit).</summary>
public sealed class UsersPageTests : AdminUiComponentContext
{
    // Saving a user hashes the password with PBKDF2 (600k iterations); a busy CI runner needs more than 1 s.
    private static readonly TimeSpan SaveTimeout = TimeSpan.FromSeconds(15);

    private readonly TempDirectory _root = new();

    private void AddUser(string name, string? password = "secret-password", params PublicKeyEntry[] keys) =>
        Repository.AddUser(new User
        {
            Username = name,
            UserRootDirectory = _root.Path,
            HashedPassword = password is null ? null : TestCredentials.HashPassword(password),
            PublicKeys = keys.Length == 0 ? null : keys.ToList(),
            WhitelistedIps = new List<string>(),
        });

    [Fact]
    public void Users_are_listed_and_the_search_filters_them()
    {
        AddUser("alice");
        AddUser("bob");
        var page = Render<Users>();

        Assert.Contains("alice", page.Find("#user-table").TextContent);
        Assert.Contains("bob", page.Find("#user-table").TextContent);

        page.Input("#user-search", "ali");

        Assert.Contains("alice", page.Find("#user-table").TextContent);
        Assert.DoesNotContain("bob", page.Find("#user-table").TextContent);
    }

    [Fact]
    public void A_new_user_is_created_with_a_hashed_password_and_a_whitelist()
    {
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#username", "carol");
        page.Change("#root-directory", _root.Path);
        page.Change("#new-password", "long-enough-1");
        page.Change("#confirm-password", "long-enough-1");
        page.Change("#user-whitelist-mode", true);
        page.Change("#user-whitelist", "10.0.0.0/8\n::1");
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.NotNull(Repository.GetUser("carol")), SaveTimeout);
        var user = Repository.GetUser("carol");
        Assert.Equal(_root.Path, user.UserRootDirectory);
        Assert.True(PasswordHasher.Verify("long-enough-1", user.HashedPassword));
        Assert.True(user.OnlyWhitelistedIps);
        Assert.Equal(new[] { "10.0.0.0/8", "::1" }, user.WhitelistedIps);
        page.WaitForAssertion(() => Assert.Contains("carol", page.Find("#user-table").TextContent), SaveTimeout);
    }

    [Fact]
    public void A_bad_cidr_in_the_user_whitelist_is_rejected()
    {
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#username", "dave");
        page.Change("#root-directory", _root.Path);
        page.Change("#user-whitelist", "10.0.0.0/40");
        page.Submit("#user-form");

        Assert.Contains("Not a valid network: 10.0.0.0/40", page.Markup);
        Assert.Null(Repository.GetUser("dave"));
    }

    [Theory]
    [InlineData("", "Enter a user name.")]
    [InlineData("with space", "The user name cannot have spaces")]
    public void An_invalid_user_name_is_rejected(string username, string message)
    {
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#username", username);
        page.Change("#root-directory", _root.Path);
        page.Submit("#user-form");

        Assert.Contains(message, page.Markup);
        Assert.Empty(Repository.GetAllUsers());
    }

    [Theory]
    [InlineData("short", "short", "at least 8 characters")]
    [InlineData("long-enough-1", "long-enough-2", "The passwords are not the same.")]
    public void A_bad_password_is_rejected(string password, string confirm, string message)
    {
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#username", "erin");
        page.Change("#root-directory", _root.Path);
        page.Change("#new-password", password);
        page.Change("#confirm-password", confirm);
        page.Submit("#user-form");

        Assert.Contains(message, page.Markup);
        Assert.Null(Repository.GetUser("erin"));
    }

    [Fact]
    public void A_missing_root_directory_gives_a_warning()
    {
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#root-directory", Path.Combine(_root.Path, "does-not-exist"));

        Assert.NotNull(page.Find("#root-missing"));

        page.Change("#root-directory", _root.Path);
        Assert.Empty(page.FindAll("#root-missing"));
    }

    [Fact]
    public void Editing_a_user_keeps_the_password_when_none_is_entered()
    {
        AddUser("frank", password: "old-password");
        var oldHash = Repository.GetUser("frank").HashedPassword;
        var page = Render<Users>();

        page.Click(".edit-user");
        Assert.True(page.Find("#username").HasAttribute("readonly"));
        var newRoot = Path.Combine(_root.Path, "sub");
        Directory.CreateDirectory(newRoot);
        page.Change("#root-directory", newRoot);
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.Equal(newRoot, Repository.GetUser("frank").UserRootDirectory), SaveTimeout);
        Assert.Equal(oldHash, Repository.GetUser("frank").HashedPassword);
        Assert.Equal("never", page.Find("#last-login").TextContent);
    }

    [Fact]
    public void Editing_shows_the_last_login_and_the_fingerprints_of_the_keys()
    {
        var ed25519 = TestUserKeys.Ed25519("gina@laptop");
        var rsa = TestUserKeys.Rsa("gina@desktop");
        AddUser("gina", "secret-password", ed25519.Entry, rsa.Entry);
        Repository.GetUser("gina").LastLoginAt = new DateTime(2026, 10, 30, 8, 15, 0, DateTimeKind.Utc);
        var page = Render<Users>();

        Assert.Contains("2 keys", page.Find("#user-table").TextContent);
        page.Click(".edit-user");

        Assert.Equal("2026-10-30 08:15", page.Find("#last-login").TextContent);
        Assert.Equal(new[] { ed25519.Entry.Fingerprint, rsa.Entry.Fingerprint }, page.FindAll(".key-fingerprint").Select(e => e.TextContent));
        Assert.StartsWith("SHA256:", ed25519.Entry.Fingerprint);
        Assert.Contains("gina@laptop", page.Find("#key-table").TextContent);
    }

    [Fact]
    public void The_protocols_of_a_user_are_saved()
    {
        AddUser("paula");
        var page = Render<Users>();

        page.Click(".edit-user");
        Assert.True(page.Find("#allow-sftp").HasAttribute("checked"));
        Assert.True(page.Find("#allow-ftp").HasAttribute("checked"));
        page.Change("#allow-webdav", false);
        page.Change("#allow-web", false);
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.Equal(UserProtocols.Sftp | UserProtocols.Ftp, Repository.GetUser("paula").AllowedProtocols), SaveTimeout);
        page.Click(".edit-user");
        page.Change("#allow-ftp", false);
        page.Submit("#user-form");
        page.WaitForAssertion(() => Assert.Equal(UserProtocols.Sftp, Repository.GetUser("paula").AllowedProtocols), SaveTimeout);
        page.WaitForAssertion(() => Assert.Contains("SFTP", page.Find("#user-table").TextContent), SaveTimeout);

        page.Change("#allow-sftp", false);
        page.Submit("#user-form");
        Assert.Contains("Allow at least one protocol.", page.Markup);
        Assert.Equal(UserProtocols.Sftp, Repository.GetUser("paula").AllowedProtocols);
    }

    [Fact]
    public void An_app_password_is_shown_once_stored_as_a_hash_and_can_be_removed()
    {
        AddUser("quinn");
        var page = Render<Users>();
        page.Click(".edit-user");
        Assert.NotNull(page.Find("#no-app-passwords"));

        page.Change("#app-password-name", "Finder");
        page.Click("#create-app-password");

        var secret = page.Find("#new-app-password").TextContent;
        var stored = Assert.Single(Repository.GetUser("quinn").AppPasswords!);
        Assert.Equal("Finder", stored.Name);
        Assert.Equal(UserProtocols.WebDav, stored.Protocols);
        Assert.True(stored.Matches(secret));
        Assert.Contains("Finder", page.Find("#app-password-table").TextContent);

        page.Click("#create-app-password");
        Assert.Contains("Enter a name", page.Find("#app-password-error").TextContent);
        Assert.Empty(page.FindAll("#new-app-password"));

        page.Click(".remove-app-password");
        Assert.Null(Repository.GetUser("quinn").AppPasswords);
        Assert.NotNull(page.Find("#no-app-passwords"));
    }

    [Fact]
    public void Keys_pasted_as_text_are_added_with_the_expiry()
    {
        AddUser("lisa");
        var first = TestUserKeys.Ed25519();
        var second = TestUserKeys.EcdsaNistP256();
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Change("#new-keys", first.AuthorizedKeysLine + "\n" + second.AuthorizedKeysLine);
        page.Change("#new-keys-expiry", "2027-03-01");
        page.Click("#add-keys");

        var keys = Repository.GetUser("lisa").PublicKeys!;
        Assert.Equal(new[] { first.Entry.KeyBase64, second.Entry.KeyBase64 }, keys.Select(k => k.KeyBase64));
        Assert.All(keys, k => Assert.Equal(new DateTime(2027, 3, 1, 0, 0, 0, DateTimeKind.Utc), k.ExpiresAt));
        Assert.Equal(2, page.FindAll(".key-row").Count);
    }

    [Fact]
    public void A_pasted_line_with_options_shows_the_error_and_adds_nothing()
    {
        AddUser("mona");
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Change("#new-keys", "from=\"10.0.0.0/8\" " + TestUserKeys.Ed25519().AuthorizedKeysLine);
        page.Click("#add-keys");

        Assert.Contains("options", page.Find("#key-error").TextContent);
        Assert.Null(Repository.GetUser("mona").PublicKeys);
    }

    [Fact]
    public void The_login_methods_and_the_multi_step_login_are_saved()
    {
        AddUser("nina");
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Change("#multi-step", FxSshSftpServer.Models.UserForm.KeyThenPassword);
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.Equal([AuthMethods.PublicKey, AuthMethods.Password], Repository.GetUser("nina").RequireAllOf), SaveTimeout);
        Assert.Equal(AuthMethods.All, Repository.GetUser("nina").AllowedAuthMethods);

        page.Change("#multi-step", "");
        page.Change("#allow-password", false);
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.Null(Repository.GetUser("nina").RequireAllOf), SaveTimeout);
        Assert.Equal(AuthMethods.PublicKey | AuthMethods.KeyboardInteractive, Repository.GetUser("nina").AllowedAuthMethods);
    }

    [Fact]
    public void A_multi_step_login_with_a_method_that_is_not_allowed_is_not_saved()
    {
        AddUser("olga");
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Change("#allow-password", false);
        page.Change("#multi-step", FxSshSftpServer.Models.UserForm.KeyThenPassword);
        page.Submit("#user-form");

        Assert.Contains("not an allowed method", page.Find("#user-form").TextContent);
        Assert.Null(Repository.GetUser("olga").RequireAllOf);
        Assert.Equal(AuthMethods.All, Repository.GetUser("olga").AllowedAuthMethods);
    }

    [Fact]
    public void No_login_method_at_all_is_not_saved()
    {
        AddUser("petra");
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Change("#allow-password", false);
        page.Change("#allow-public-key", false);
        page.Submit("#user-form");

        Assert.Contains("Allow the password, the public key or both.", page.Find("#user-form").TextContent);
        Assert.Equal(AuthMethods.All, Repository.GetUser("petra").AllowedAuthMethods);
    }

    [Fact]
    public void Delete_asks_for_confirmation_and_cancel_keeps_the_user()
    {
        AddUser("henry");
        var page = Render<Users>();

        page.Click(".delete-user");
        Assert.Contains("Delete the user", page.Find(".modal").TextContent);

        page.Click(".modal .btn-secondary");

        Assert.Empty(page.FindAll(".modal"));
        Assert.NotNull(Repository.GetUser("henry"));
    }

    [Fact]
    public void Delete_removes_the_user_after_confirmation()
    {
        AddUser("ivan");
        var page = Render<Users>();

        page.Click(".delete-user");
        page.Click(".confirm-button");

        Assert.Null(Repository.GetUser("ivan"));
        Assert.NotNull(page.Find("#no-users"));
    }

    [Fact]
    public void Generating_a_key_stores_the_public_key_and_downloads_the_private_key()
    {
        AddUser("judy");
        var download = JSInterop.SetupVoid("BlazorDownloadFile", _ => true);
        download.SetVoidResult();
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Click("#generate-key");

        page.WaitForAssertion(() => Assert.NotNull(Repository.GetUser("judy").PublicKeys), TimeSpan.FromSeconds(30));
        var invocation = Assert.Single(download.Invocations);
        Assert.Equal("judy.pem", invocation.Arguments[0]);
        Assert.Equal("ssh-rsa", Assert.Single(Repository.GetUser("judy").PublicKeys!).KeyType);
        page.WaitForAssertion(() => Assert.StartsWith("SHA256:", page.Find(".key-fingerprint").TextContent), SaveTimeout);
    }

    [Fact]
    public void Generating_an_ed25519_key_adds_it_and_downloads_an_openssh_private_key()
    {
        AddUser("jane");
        var download = JSInterop.SetupVoid("BlazorDownloadFile", _ => true);
        download.SetVoidResult();
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Click("#generate-ed25519-key");

        page.WaitForAssertion(() => Assert.NotNull(Repository.GetUser("jane").PublicKeys), SaveTimeout);
        var entry = Assert.Single(Repository.GetUser("jane").PublicKeys!);
        Assert.Equal("ssh-ed25519", entry.KeyType);
        var invocation = Assert.Single(download.Invocations);
        Assert.Equal("jane_ed25519", invocation.Arguments[0]);
        // The private key works: SSH.NET reads it and it has the stored public key.
        var bytes = (byte[])invocation.Arguments[2]!;
        Assert.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----", System.Text.Encoding.UTF8.GetString(bytes));
        using var keyFile = new Renci.SshNet.PrivateKeyFile(new MemoryStream(bytes));
        var key = Assert.IsType<Renci.SshNet.Security.ED25519Key>(keyFile.Key);
        Assert.Equal(Convert.FromBase64String(entry.KeyBase64)[^32..], key.PublicKey);
    }

    [Fact]
    public void Removing_a_key_asks_for_confirmation_and_keeps_the_other_keys()
    {
        var remove = TestUserKeys.Ed25519();
        var keep = TestUserKeys.Rsa();
        AddUser("kim", "secret-password", remove.Entry, keep.Entry);
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Click(".remove-key", 0);
        page.Click(".confirm-button");

        Assert.Equal(keep.Entry.KeyBase64, Assert.Single(Repository.GetUser("kim").PublicKeys!).KeyBase64);
        Assert.Single(page.FindAll(".key-row"));
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _root.Dispose();
        base.Dispose(disposing);
    }

    [Fact]
    public void A_new_user_has_all_permissions_at_the_root_and_no_filters()
    {
        var page = Render<Users>();

        page.Click("#add-user");

        Assert.Single(page.FindAll(".permission-row"));
        Assert.Equal("/", page.Find("#permission-path-0").GetAttribute("value"));
        Assert.True(page.Find("#permission-path-0").HasAttribute("readonly"));
        Assert.All(PermissionRowColumns(), flag => Assert.True(page.Find($"#permission-0-{flag}").HasAttribute("checked")));
        Assert.Empty(page.FindAll(".remove-permission"));
        Assert.Empty(page.FindAll(".filter-row"));
    }

    [Fact]
    public void Permissions_and_path_filters_are_edited_in_the_tables_and_saved()
    {
        AddUser("grace");
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Change("#permission-0-Delete", false);
        page.Click("#add-permission");
        page.Change("#permission-path-1", "/incoming/");
        foreach (var flag in PermissionRowColumns().Where(f => f != FilePermissions.Upload))
            page.Change($"#permission-1-{flag}", false);
        page.Click("#add-filter");
        Assert.Equal("/", page.Find("#filter-path-0").GetAttribute("value"));
        page.Change("#filter-denied-0", "*.exe, *.bat");
        page.Change("#filter-hidden-0", ".git");
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.Equal(2, Repository.GetUser("grace").Permissions!.Count), SaveTimeout);
        var user = Repository.GetUser("grace");
        Assert.Equal(FilePermissions.All & ~FilePermissions.Delete, user.Permissions!["/"]);
        Assert.Equal(FilePermissions.Upload, user.Permissions["/incoming"]);
        Assert.Equal(["*.exe", "*.bat"], user.PathFilters!["/"].DeniedPatterns);
        Assert.Equal([".git"], user.PathFilters["/"].HiddenPatterns);
        Assert.Empty(user.PathFilters["/"].AllowedPatterns);
    }

    [Fact]
    public void Stored_permissions_are_shown_with_the_root_first_and_rows_can_be_removed()
    {
        AddUser("heidi");
        var stored = Repository.GetUser("heidi");
        stored.Permissions = new() { ["/b"] = FilePermissions.List, ["/"] = FilePermissions.Download, ["/a"] = FilePermissions.Upload };
        stored.PathFilters = new() { ["/a"] = new PathFilter { AllowedPatterns = ["*.csv"] } };
        var page = Render<Users>();

        page.Click(".edit-user");

        Assert.Equal(["/", "/a", "/b"], page.FindAll(".permission-row input[type=text]").Select(i => i.GetAttribute("value")));
        Assert.True(page.Find("#permission-0-Download").HasAttribute("checked"));
        Assert.False(page.Find("#permission-0-List").HasAttribute("checked"));
        Assert.Equal("*.csv", page.Find("#filter-allowed-0").GetAttribute("value"));

        page.Click(".remove-permission", 1); // "/b"
        page.Click(".remove-filter");
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.Equal(2, Repository.GetUser("heidi").Permissions!.Count), SaveTimeout);
        Assert.False(Repository.GetUser("heidi").Permissions!.ContainsKey("/b"));
        Assert.Null(Repository.GetUser("heidi").PathFilters);
    }

    [Theory]
    [InlineData("incoming", "must start with")]
    [InlineData("", "Enter a path")]
    [InlineData("/", "twice")]
    public void A_bad_permission_path_is_rejected(string path, string message)
    {
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#username", "ivan");
        page.Change("#root-directory", _root.Path);
        page.Click("#add-permission");
        page.Change("#permission-path-1", path);
        page.Submit("#user-form");

        Assert.Contains(message, page.Markup);
        Assert.Null(Repository.GetUser("ivan"));
    }

    [Fact]
    public void A_pattern_with_a_slash_is_rejected()
    {
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#username", "judy");
        page.Change("#root-directory", _root.Path);
        page.Click("#add-filter");
        page.Change("#filter-denied-0", "bin/*.exe");
        page.Submit("#user-form");

        Assert.Contains("a pattern matches a name, not a path", page.Markup);
        Assert.Null(Repository.GetUser("judy"));
    }

    [Fact]
    public void The_quotas_and_the_bandwidth_of_a_new_user_are_saved()
    {
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#username", "quota-user");
        page.Change("#root-directory", _root.Path);
        page.Change("#quota-size", "1.5");
        page.Change("#quota-files", "100");
        page.Change("#quota-download", "10");
        page.Change("#bandwidth-download", "256");
        page.Click("#add-bandwidth-override");
        page.Change("#override-sources-0", "10.0.0.0/8, 192.168.0.0/16");
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.NotNull(Repository.GetUser("quota-user")), SaveTimeout);
        var user = Repository.GetUser("quota-user");
        Assert.Equal((1_572_864L, 100L), (user.DiskQuota!.MaxSizeBytes, user.DiskQuota.MaxFiles));
        Assert.Equal((0L, 10_485_760L, 0L), (user.TransferQuota!.MaxUploadBytes, user.TransferQuota.MaxDownloadBytes, user.TransferQuota.MaxTotalBytes));
        Assert.Equal((0, 256), (user.Bandwidth!.UploadKiBPerSecond, user.Bandwidth.DownloadKiBPerSecond));
        var lan = Assert.Single(user.Bandwidth.Overrides!);
        Assert.Equal(["10.0.0.0/8", "192.168.0.0/16"], lan.Sources);
        Assert.Equal((0, 0), (lan.UploadKiBPerSecond, lan.DownloadKiBPerSecond));
    }

    [Fact]
    public void A_user_without_limits_stores_no_quota_and_a_bad_override_network_is_rejected()
    {
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#username", "no-limits");
        page.Change("#root-directory", _root.Path);
        page.Click("#add-bandwidth-override");
        page.Change("#override-sources-0", "10.0.0.0/40");
        page.Submit("#user-form");

        Assert.Contains("Not a valid network: 10.0.0.0/40", page.Markup);
        Assert.Null(Repository.GetUser("no-limits"));

        page.Click(".remove-override");
        page.Submit("#user-form");
        page.WaitForAssertion(() => Assert.NotNull(Repository.GetUser("no-limits")), SaveTimeout);
        var user = Repository.GetUser("no-limits");
        Assert.Null(user.DiskQuota);
        Assert.Null(user.TransferQuota);
        Assert.Null(user.Bandwidth);
    }

    [Fact]
    public async Task The_usage_of_a_user_with_a_quota_is_shown_and_can_be_rescanned_and_reset()
    {
        Repository.AddUser(new User
        {
            Username = "counted",
            UserRootDirectory = _root.Path,
            DiskQuota = new SshServer.Interfaces.Quotas.DiskQuota { MaxSizeBytes = 2 * 1024 * 1024, MaxFiles = 10 },
            TransferQuota = new SshServer.Interfaces.Quotas.TransferQuota { MaxUploadBytes = 1024 },
            WhitelistedIps = new List<string>(),
        });
        var scope = SshServer.Interfaces.Quotas.QuotaScope.ForUser("counted");
        await Quotas.LoadAsync(scope, Xunit.TestContext.Current.CancellationToken);
        Quotas.AddDisk(scope, 1024 * 1024, 3);
        Quotas.AddTransfer(scope, 512, 0);
        var page = Render<Users>();

        page.Click(".edit-user");

        var usage = page.Find("#quota-usage").TextContent;
        Assert.Contains("1 MiB of 2 MiB", usage);
        Assert.Contains("3 of 10 files", usage);
        Assert.Contains("never scanned", usage);
        Assert.Contains("uploaded 512 bytes of 1 KiB", page.Find("#transfer-usage").TextContent);

        page.Click("#rescan-quota");
        Assert.True(QuotaScans.IsUserPending("counted"));
        Assert.Contains("scan queued", page.Find("#quota-usage").TextContent);

        page.Click("#reset-transfer");
        page.WaitForAssertion(() => Assert.Equal(0, Quotas.Current(scope).UploadedBytes));
        page.WaitForAssertion(() => Assert.Contains("uploaded 0 bytes", page.Find("#transfer-usage").TextContent));
    }

    [Fact]
    public void A_user_without_a_quota_shows_no_usage()
    {
        AddUser("plain");
        var page = Render<Users>();

        page.Click(".edit-user");

        Assert.Empty(page.FindAll("#quota-usage"));
        Assert.NotEmpty(page.FindAll("#quota-fieldset"));
    }

    private static IEnumerable<FilePermissions> PermissionRowColumns() =>
        FxSshSftpServer.Models.PermissionRow.Columns.Select(c => c.Flag);
}
