using Bunit;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FxSshSftpServer.Components.Pages;
using SshServer.Interfaces;
using SshServer.Interfaces.Security;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>The users page: list, search, create, edit, delete with confirmation, key and whitelist (bUnit).</summary>
public sealed class UsersPageTests : AdminUiComponentContext
{
    private readonly TempDirectory _root = new();

    private void AddUser(string name, string? password = "secret-password", string? key = null) =>
        Repository.AddUser(new User
        {
            Username = name,
            UserRootDirectory = _root.Path,
            HashedPassword = password is null ? null : TestCredentials.HashPassword(password),
            RsaPublicKey = key,
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

        page.WaitForAssertion(() => Assert.NotNull(Repository.GetUser("carol")));
        var user = Repository.GetUser("carol");
        Assert.Equal(_root.Path, user.UserRootDirectory);
        Assert.True(PasswordHasher.Verify("long-enough-1", user.HashedPassword));
        Assert.True(user.OnlyWhitelistedIps);
        Assert.Equal(new[] { "10.0.0.0/8", "::1" }, user.WhitelistedIps);
        page.WaitForAssertion(() => Assert.Contains("carol", page.Find("#user-table").TextContent));
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

        page.WaitForAssertion(() => Assert.Equal(newRoot, Repository.GetUser("frank").UserRootDirectory));
        Assert.Equal(oldHash, Repository.GetUser("frank").HashedPassword);
        Assert.Equal("never", page.Find("#last-login").TextContent);
    }

    [Fact]
    public void Editing_shows_the_last_login_and_the_key_fingerprint()
    {
        using var rsa = new System.Security.Cryptography.RSACryptoServiceProvider(2048);
        var key = Convert.ToBase64String(rsa.ExportCspBlob(false));
        AddUser("gina", key: key);
        Repository.GetUser("gina").LastSuccessfulLogin = new DateTime(2026, 10, 30, 8, 15, 0, DateTimeKind.Utc);
        var page = Render<Users>();

        page.Find(".edit-user").Click();

        Assert.Equal("2026-10-30 08:15", page.Find("#last-login").TextContent);
        Assert.Equal(FxSsh.SshServerModule.ServerInfo.GetUserKeyFingerprint(key), page.Find("#user-key-fingerprint").TextContent);
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

        page.WaitForAssertion(() => Assert.NotNull(Repository.GetUser("judy").RsaPublicKey), TimeSpan.FromSeconds(30));
        var invocation = Assert.Single(download.Invocations);
        Assert.Equal("judy.pem", invocation.Arguments[0]);
        page.WaitForAssertion(() => Assert.StartsWith("SHA256:", page.Find("#user-key-fingerprint").TextContent));
    }

    [Fact]
    public void Removing_the_key_asks_for_confirmation()
    {
        using var rsa = new System.Security.Cryptography.RSACryptoServiceProvider(2048);
        AddUser("kim", key: Convert.ToBase64String(rsa.ExportCspBlob(false)));
        var page = Render<Users>();

        page.Find(".edit-user").Click();
        page.Find("#remove-key").Click();
        page.Find(".confirm-button").Click();

        Assert.Null(Repository.GetUser("kim").RsaPublicKey);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _root.Dispose();
        base.Dispose(disposing);
    }
}
