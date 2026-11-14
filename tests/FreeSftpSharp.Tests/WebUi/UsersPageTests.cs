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

        page.Find("#user-search").Input("ali");

        Assert.Contains("alice", page.Find("#user-table").TextContent);
        Assert.DoesNotContain("bob", page.Find("#user-table").TextContent);
    }

    [Fact]
    public void A_new_user_is_created_with_a_hashed_password_and_a_whitelist()
    {
        var page = Render<Users>();

        page.Find("#add-user").Click();
        page.Find("#username").Change("carol");
        page.Find("#root-directory").Change(_root.Path);
        page.Find("#new-password").Change("long-enough-1");
        page.Find("#confirm-password").Change("long-enough-1");
        page.Find("#user-whitelist-mode").Change(true);
        page.Find("#user-whitelist").Change("10.0.0.0/8\n::1");
        page.Find("#user-form").Submit();

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

        page.Find("#add-user").Click();
        page.Find("#username").Change("dave");
        page.Find("#root-directory").Change(_root.Path);
        page.Find("#user-whitelist").Change("10.0.0.0/40");
        page.Find("#user-form").Submit();

        Assert.Contains("Not a valid network: 10.0.0.0/40", page.Markup);
        Assert.Null(Repository.GetUser("dave"));
    }

    [Theory]
    [InlineData("", "Enter a user name.")]
    [InlineData("with space", "The user name cannot have spaces")]
    public void An_invalid_user_name_is_rejected(string username, string message)
    {
        var page = Render<Users>();

        page.Find("#add-user").Click();
        page.Find("#username").Change(username);
        page.Find("#root-directory").Change(_root.Path);
        page.Find("#user-form").Submit();

        Assert.Contains(message, page.Markup);
        Assert.Empty(Repository.GetAllUsers());
    }

    [Theory]
    [InlineData("short", "short", "at least 8 characters")]
    [InlineData("long-enough-1", "long-enough-2", "The passwords are not the same.")]
    public void A_bad_password_is_rejected(string password, string confirm, string message)
    {
        var page = Render<Users>();

        page.Find("#add-user").Click();
        page.Find("#username").Change("erin");
        page.Find("#root-directory").Change(_root.Path);
        page.Find("#new-password").Change(password);
        page.Find("#confirm-password").Change(confirm);
        page.Find("#user-form").Submit();

        Assert.Contains(message, page.Markup);
        Assert.Null(Repository.GetUser("erin"));
    }

    [Fact]
    public void A_missing_root_directory_gives_a_warning()
    {
        var page = Render<Users>();

        page.Find("#add-user").Click();
        page.Find("#root-directory").Change(Path.Combine(_root.Path, "does-not-exist"));

        Assert.NotNull(page.Find("#root-missing"));

        page.Find("#root-directory").Change(_root.Path);
        Assert.Empty(page.FindAll("#root-missing"));
    }

    [Fact]
    public void Editing_a_user_keeps_the_password_when_none_is_entered()
    {
        AddUser("frank", password: "old-password");
        var oldHash = Repository.GetUser("frank").HashedPassword;
        var page = Render<Users>();

        page.Find(".edit-user").Click();
        Assert.True(page.Find("#username").HasAttribute("readonly"));
        var newRoot = Path.Combine(_root.Path, "sub");
        Directory.CreateDirectory(newRoot);
        page.Find("#root-directory").Change(newRoot);
        page.Find("#user-form").Submit();

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
        page.Find(".edit-user").Click();

        Assert.Equal("2026-10-30 08:15", page.Find("#last-login").TextContent);
        Assert.Equal(new[] { ed25519.Entry.Fingerprint, rsa.Entry.Fingerprint }, page.FindAll(".key-fingerprint").Select(e => e.TextContent));
        Assert.StartsWith("SHA256:", ed25519.Entry.Fingerprint);
        Assert.Contains("gina@laptop", page.Find("#key-table").TextContent);
    }

    [Fact]
    public void Keys_pasted_as_text_are_added_with_the_expiry()
    {
        AddUser("lisa");
        var first = TestUserKeys.Ed25519();
        var second = TestUserKeys.EcdsaNistP256();
        var page = Render<Users>();

        page.Find(".edit-user").Click();
        page.Find("#new-keys").Change(first.AuthorizedKeysLine + "\n" + second.AuthorizedKeysLine);
        page.Find("#new-keys-expiry").Change("2027-03-01");
        page.Find("#add-keys").Click();

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

        page.Find(".edit-user").Click();
        page.Find("#new-keys").Change("from=\"10.0.0.0/8\" " + TestUserKeys.Ed25519().AuthorizedKeysLine);
        page.Find("#add-keys").Click();

        Assert.Contains("options", page.Find("#key-error").TextContent);
        Assert.Null(Repository.GetUser("mona").PublicKeys);
    }

    [Fact]
    public void The_login_methods_and_the_multi_step_login_are_saved()
    {
        AddUser("nina");
        var page = Render<Users>();

        page.Find(".edit-user").Click();
        page.Find("#multi-step").Change(FxSshSftpServer.Models.UserForm.KeyThenPassword);
        page.Find("#user-form").Submit();

        page.WaitForAssertion(() => Assert.Equal([AuthMethods.PublicKey, AuthMethods.Password], Repository.GetUser("nina").RequireAllOf), SaveTimeout);
        Assert.Equal(AuthMethods.All, Repository.GetUser("nina").AllowedAuthMethods);

        page.Find("#multi-step").Change("");
        page.Find("#allow-password").Change(false);
        page.Find("#user-form").Submit();

        page.WaitForAssertion(() => Assert.Null(Repository.GetUser("nina").RequireAllOf), SaveTimeout);
        Assert.Equal(AuthMethods.PublicKey | AuthMethods.KeyboardInteractive, Repository.GetUser("nina").AllowedAuthMethods);
    }

    [Fact]
    public void A_multi_step_login_with_a_method_that_is_not_allowed_is_not_saved()
    {
        AddUser("olga");
        var page = Render<Users>();

        page.Find(".edit-user").Click();
        page.Find("#allow-password").Change(false);
        page.Find("#multi-step").Change(FxSshSftpServer.Models.UserForm.KeyThenPassword);
        page.Find("#user-form").Submit();

        Assert.Contains("not an allowed method", page.Find("#user-form").TextContent);
        Assert.Null(Repository.GetUser("olga").RequireAllOf);
        Assert.Equal(AuthMethods.All, Repository.GetUser("olga").AllowedAuthMethods);
    }

    [Fact]
    public void No_login_method_at_all_is_not_saved()
    {
        AddUser("petra");
        var page = Render<Users>();

        page.Find(".edit-user").Click();
        page.Find("#allow-password").Change(false);
        page.Find("#allow-public-key").Change(false);
        page.Find("#user-form").Submit();

        Assert.Contains("Allow the password, the public key or both.", page.Find("#user-form").TextContent);
        Assert.Equal(AuthMethods.All, Repository.GetUser("petra").AllowedAuthMethods);
    }

    [Fact]
    public void Delete_asks_for_confirmation_and_cancel_keeps_the_user()
    {
        AddUser("henry");
        var page = Render<Users>();

        page.Find(".delete-user").Click();
        Assert.Contains("Delete the user", page.Find(".modal").TextContent);

        page.Find(".modal .btn-secondary").Click();

        Assert.Empty(page.FindAll(".modal"));
        Assert.NotNull(Repository.GetUser("henry"));
    }

    [Fact]
    public void Delete_removes_the_user_after_confirmation()
    {
        AddUser("ivan");
        var page = Render<Users>();

        page.Find(".delete-user").Click();
        page.Find(".confirm-button").Click();

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

        page.Find(".edit-user").Click();
        page.Find("#generate-key").Click();

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

        page.Find(".edit-user").Click();
        page.Find("#generate-ed25519-key").Click();

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

        page.Find(".edit-user").Click();
        page.FindAll(".remove-key")[0].Click();
        page.Find(".confirm-button").Click();

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

        page.Find("#add-user").Click();

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

        page.Find(".edit-user").Click();
        page.Find("#permission-0-Delete").Change(false);
        page.Find("#add-permission").Click();
        page.Find("#permission-path-1").Change("/incoming/");
        foreach (var flag in PermissionRowColumns().Where(f => f != FilePermissions.Upload))
            page.Find($"#permission-1-{flag}").Change(false);
        page.Find("#add-filter").Click();
        Assert.Equal("/", page.Find("#filter-path-0").GetAttribute("value"));
        page.Find("#filter-denied-0").Change("*.exe, *.bat");
        page.Find("#filter-hidden-0").Change(".git");
        page.Find("#user-form").Submit();

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

        page.Find(".edit-user").Click();

        Assert.Equal(["/", "/a", "/b"], page.FindAll(".permission-row input[type=text]").Select(i => i.GetAttribute("value")));
        Assert.True(page.Find("#permission-0-Download").HasAttribute("checked"));
        Assert.False(page.Find("#permission-0-List").HasAttribute("checked"));
        Assert.Equal("*.csv", page.Find("#filter-allowed-0").GetAttribute("value"));

        page.FindAll(".remove-permission")[1].Click(); // "/b"
        page.Find(".remove-filter").Click();
        page.Find("#user-form").Submit();

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

        page.Find("#add-user").Click();
        page.Find("#username").Change("ivan");
        page.Find("#root-directory").Change(_root.Path);
        page.Find("#add-permission").Click();
        page.Find("#permission-path-1").Change(path);
        page.Find("#user-form").Submit();

        Assert.Contains(message, page.Markup);
        Assert.Null(Repository.GetUser("ivan"));
    }

    [Fact]
    public void A_pattern_with_a_slash_is_rejected()
    {
        var page = Render<Users>();

        page.Find("#add-user").Click();
        page.Find("#username").Change("judy");
        page.Find("#root-directory").Change(_root.Path);
        page.Find("#add-filter").Click();
        page.Find("#filter-denied-0").Change("bin/*.exe");
        page.Find("#user-form").Submit();

        Assert.Contains("a pattern matches a name, not a path", page.Markup);
        Assert.Null(Repository.GetUser("judy"));
    }

    private static IEnumerable<FilePermissions> PermissionRowColumns() =>
        FxSshSftpServer.Models.PermissionRow.Columns.Select(c => c.Flag);
}
